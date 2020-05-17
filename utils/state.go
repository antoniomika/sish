package utils

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/antoniomika/oxy/forward"
	"github.com/antoniomika/oxy/roundrobin"
	"github.com/jpillora/ipfilter"
	"github.com/spf13/viper"
)

// ListenerType represents any listener sish supports
type ListenerType int

const (
	// AliasListener represents a tcp alias
	AliasListener ListenerType = iota

	// HTTPListener represents a HTTP proxy
	HTTPListener

	// TCPListener represents a generic tcp listener
	TCPListener

	// ProcessListener represents a process specific listener
	ProcessListener
)

// ListenerHolder represents a generic listener
type ListenerHolder struct {
	net.Listener
	ListenAddr string
	Type       ListenerType
	SSHConn    *SSHConnection
}

// HTTPHolder holds proxy and connection info
type HTTPHolder struct {
	HTTPHost string
	Scheme   string
	SSHConns *sync.Map
	Forward  *forward.Forwarder
	Balancer *roundrobin.RoundRobin
}

// AliasHolder holds alias and connection info
type AliasHolder struct {
	AliasHost string
	SSHConns  *sync.Map
	Balancer  *roundrobin.RoundRobin
}

// TCPHolder holds proxy and connection info
type TCPHolder struct {
	TCPHost  string
	Listener net.Listener
	SSHConns *sync.Map
	Balancer *roundrobin.RoundRobin
}

// Handle will copy connections from one handler to a roundrobin server
func (tH *TCPHolder) Handle(state *State) {
	for {
		cl, err := tH.Listener.Accept()
		if err != nil {
			break
		}

		clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

		if err != nil || state.IPFilter.Blocked(clientRemote) {
			cl.Close()
			continue
		}

		connectionLocation, err := tH.Balancer.NextServer()
		if err != nil {
			log.Println("Unable to load connection location:", err)
			cl.Close()
			continue
		}

		host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
		if err != nil {
			log.Println("Unable to decode connection location:", err)
			cl.Close()
			continue
		}

		hostAddr := string(host)

		logLine := fmt.Sprintf("Accepted connection from %s -> %s", cl.RemoteAddr().String(), cl.LocalAddr().String())
		log.Println(logLine)

		if viper.GetBool("log-to-client") {
			tH.SSHConns.Range(func(key, val interface{}) bool {
				sshConn := val.(*SSHConnection)

				sshConn.Listeners.Range(func(key, val interface{}) bool {
					listenerAddr := key.(string)

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
			continue
		}

		go CopyBoth(conn, cl)
	}
}

// State handles overall state
type State struct {
	Console        *WebConsole
	SSHConnections *sync.Map
	Listeners      *sync.Map
	HTTPListeners  *sync.Map
	AliasListeners *sync.Map
	TCPListeners   *sync.Map
	IPFilter       *ipfilter.IPFilter
	LogWriter      io.Writer
}

// NewState returns a new state struct
func NewState() *State {
	return &State{
		SSHConnections: &sync.Map{},
		Listeners:      &sync.Map{},
		HTTPListeners:  &sync.Map{},
		AliasListeners: &sync.Map{},
		TCPListeners:   &sync.Map{},
		IPFilter:       Filter,
		Console:        NewWebConsole(),
		LogWriter:      multiWriter,
	}
}
