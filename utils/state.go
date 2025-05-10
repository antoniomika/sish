package utils

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/antoniomika/syncmap"
	"github.com/jpillora/ipfilter"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/roundrobin"
)

// ListenerType represents any listener sish supports.
type ListenerType int

const (
	// AliasListener represents a tcp alias.
	AliasListener ListenerType = iota

	// HTTPListener represents a HTTP proxy.
	HTTPListener

	// TCPListener represents a generic tcp listener.
	TCPListener

	// ProcessListener represents a process specific listener.
	ProcessListener
)

// LogWriter represents a writer that is used for writing logs in multiple locations.
type LogWriter struct {
	TimeFmt     string
	MultiWriter io.Writer
}

// Write implements the write function for the LogWriter. It will add a time in a
// specific format to logs.
func (w LogWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprintf(w.MultiWriter, "%v | %s", time.Now().Format(w.TimeFmt), string(bytes))
}

// ListenerHolder represents a generic listener.
type ListenerHolder struct {
	net.Listener
	ListenAddr   string
	Type         ListenerType
	SSHConn      *SSHConnection
	OriginalAddr string
	OriginalPort uint32
}

// HTTPHolder holds proxy and connection info.
type HTTPHolder struct {
	HTTPUrl        *url.URL
	History        *ConnectionHistory
	SSHConnections *syncmap.Map[string, *SSHConnection]
	Forward        *forward.Forwarder
	Balancer       *roundrobin.RoundRobin
}

// AliasHolder holds alias and connection info.
type AliasHolder struct {
	AliasHost      string
	SSHConnections *syncmap.Map[string, *SSHConnection]
	Balancer       *roundrobin.RoundRobin
}

type HistoryHolder struct {
	TotalConnects         int
	Duration              int64
	Requests              int64
	RequestContentLength  int64
	ResponseContentLength int64
	TotalContentLength    int64
	Connects              []*ConnectionHistory // last 100 connections
}

// TCPHolder holds proxy and connection info.
type TCPHolder struct {
	TCPHost        string
	Listener       net.Listener
	SSHConnections *syncmap.Map[string, *SSHConnection]
	SNIProxy       bool
	Balancers      *syncmap.Map[string, *roundrobin.RoundRobin]
	NoHandle       bool
}

// Handle will copy connections from one handler to a roundrobin server.
func (tH *TCPHolder) Handle(state *State) {
	for {
		cl, err := tH.Listener.Accept()
		if err != nil {
			break
		}

		go func() {
			clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

			if err != nil || state.IPFilter.Blocked(clientRemote) {
				cl.Close()
				return
			}

			var bufBytes []byte

			balancerName := ""
			if tH.SNIProxy {
				tlsHello, teeConn, err := PeekTLSHello(cl)
				if tlsHello == nil {
					log.Printf("Unable to read TLS hello: %s", err)
					cl.Close()
					return
				}

				bufBytes = make([]byte, teeConn.Buffer.Buffered())

				_, err = io.ReadFull(teeConn, bufBytes)
				if err != nil {
					log.Printf("Unable to read buffered data: %s", err)
					cl.Close()
					return
				}

				balancerName = tlsHello.ServerName
			}

			pB, ok := tH.Balancers.Load(balancerName)
			if !ok {
				tH.Balancers.Range(func(n string, b *roundrobin.RoundRobin) bool {
					if MatchesWildcardHost(balancerName, n) {
						pB = b
						return false
					}
					return true
				})

				if pB == nil {
					log.Printf("Unable to load connection location: %s not found on TCP listener %s", balancerName, tH.TCPHost)
					cl.Close()
					return
				}
			}

			balancer := pB

			connectionLocation, err := balancer.NextServer()
			if err != nil {
				log.Println("Unable to load connection location:", err)
				cl.Close()
				return
			}

			host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
			if err != nil {
				log.Println("Unable to decode connection location:", err)
				cl.Close()
				return
			}

			hostAddr := string(host)

			logLine := fmt.Sprintf("Accepted connection from %s -> %s", cl.RemoteAddr().String(), cl.LocalAddr().String())
			log.Println(logLine)

			if viper.GetBool("log-to-client") {
				tH.SSHConnections.Range(func(key string, sshConn *SSHConnection) bool {
					sshConn.Listeners.Range(func(listenerAddr string, val net.Listener) bool {
						if listenerAddr == hostAddr {
							sshConn.SendMessage(logLine, true)

							return false
						}

						return true
					})

					return true
				})
			}

			conn, err := net.Dial("unix", hostAddr)
			if err != nil {
				log.Println("Error connecting to tcp balancer:", err)
				cl.Close()
				return
			}

			if bufBytes != nil {
				_, err := conn.Write(bufBytes)
				if err != nil {
					log.Println("Unable to write to conn:", err)
					cl.Close()
					return
				}
			}

			CopyBoth(conn, cl)
		}()
	}
}

type Ports struct {
	// HTTPPort is used as a string override for the used HTTP port.
	HTTPPort int

	// HTTPSPort is used as a string override for the used HTTPS port.
	HTTPSPort int

	// SSHPort is used as a string override for the used SSH port.
	SSHPort int
}

// State handles overall state. It retains mutexed maps for various
// datastructures and shared objects.
type State struct {
	Console        *WebConsole
	SSHConnections *syncmap.Map[string, *SSHConnection]
	Listeners      *syncmap.Map[string, net.Listener]
	HTTPListeners  *syncmap.Map[string, *HTTPHolder]
	AliasListeners *syncmap.Map[string, *AliasHolder]
	TCPListeners   *syncmap.Map[string, *TCPHolder]
	UserFilter     map[string]int
	IPFilter       *ipfilter.IPFilter
	LogWriter      io.Writer
	Ports          *Ports
	RetryTimer     RetryTimer
	History        *syncmap.Map[string, *HistoryHolder]
}

// NewState returns a new State struct.
func NewState() *State {
	return &State{
		SSHConnections: syncmap.New[string, *SSHConnection](),
		Listeners:      syncmap.New[string, net.Listener](),
		HTTPListeners:  syncmap.New[string, *HTTPHolder](),
		AliasListeners: syncmap.New[string, *AliasHolder](),
		TCPListeners:   syncmap.New[string, *TCPHolder](),
		IPFilter:       Filter,
		UserFilter:     UserFilter,
		Console:        NewWebConsole(),
		LogWriter:      multiWriter,
		Ports:          &Ports{},
		RetryTimer:     Retry,
		History:        syncmap.New[string, *HistoryHolder](),
	}
}
