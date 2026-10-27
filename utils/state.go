package utils

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httputil"
	"net/url"

	"github.com/antoniomika/syncmap"
	"github.com/jpillora/ipfilter"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
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
	SSHConnections *syncmap.Map[string, *SSHConnection]
	Forward        *httputil.ReverseProxy
	Balancer       *roundrobin.RoundRobin
}

// TunnelId identifies the tunnel in logs. It keeps the basic auth username
// from the URL and leaves out the password.
func (h *HTTPHolder) TunnelId() string {
	var user string
	if name := h.HTTPUrl.User.Username(); name != "" {
		user = name + "@"
	}

	return fmt.Sprintf("%s%s%s", user, h.HTTPUrl.Hostname(), h.HTTPUrl.Path)
}

// AliasHolder holds alias and connection info.
type AliasHolder struct {
	AliasHost      string
	SSHConnections *syncmap.Map[string, *SSHConnection]
	Balancer       *roundrobin.RoundRobin
}

// TunnelId identifies the tunnel in logs.
func (h *AliasHolder) TunnelId() string {
	return h.AliasHost
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

// TunnelId identifies the tunnel in logs.
func (h *TCPHolder) TunnelId() string {
	return h.TCPHost
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
				err := cl.Close()
				if err != nil {
					slog.Error(
						"unable to close connection",
						"error", err,
					)
				}

				if viper.GetBool("debug") {
					slog.Debug(
						"blocked connection",
						"remoteAddr", cl.RemoteAddr().String(),
						"localAddr", cl.LocalAddr().String(),
					)
				}

				return
			}

			var bufBytes []byte

			balancerName := ""
			if tH.SNIProxy {
				tlsHello, teeConn, err := PeekTLSHello(cl)
				if tlsHello == nil {
					slog.Error(
						"unable to read tls hello",
						"error", err,
					)

					err := cl.Close()
					if err != nil {
						slog.Error(
							"unable to close connection",
							"error", err,
						)
					}

					return
				}

				bufBytes = make([]byte, teeConn.Buffer.Buffered())

				_, err = io.ReadFull(teeConn, bufBytes)
				if err != nil {
					slog.Error(
						"unable to read buffered data",
						"error", err,
					)

					err := cl.Close()
					if err != nil {
						slog.Error(
							"unable to close connection",
							"error", err,
						)
					}

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
					slog.Info(
						"unable to load connection location",
						"balancer", balancerName,
						"tcpHost", tH.TCPHost,
					)

					err := cl.Close()
					if err != nil {
						slog.Error(
							"unable to close connection",
							"error", err,
						)
					}

					return
				}
			}

			balancer := pB

			connectionLocation, err := balancer.NextServer()
			if err != nil {
				slog.Error(
					"unable to load connection location",
					"error", err,
				)

				err := cl.Close()
				if err != nil {
					slog.Error(
						"unable to close connection",
						"error", err,
					)
				}

				return
			}

			host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
			if err != nil {
				slog.Error(
					"unable to decode connection location",
					"error", err,
				)

				err := cl.Close()
				if err != nil {
					slog.Error(
						"unable to close connection",
						"error", err,
					)
				}

				return
			}

			hostAddr := string(host)

			logLine := fmt.Sprintf("Accepted TCP connection from %s -> %s", cl.RemoteAddr().String(), cl.LocalAddr().String())

			sshConn := ListenerOwner(tH.SSHConnections, hostAddr)

			ev := ConnectionEvent{
				SSHConn:        sshConn,
				TunnelType:     "tcp",
				TunnelId:       tH.TunnelId(),
				ConnectionType: "tcp",
				RemoteAddr:     cl.RemoteAddr().String(),
				LocalAddr:      cl.LocalAddr().String(),
			}

			state.LogConnection(ev)

			if viper.GetBool("log-to-client") && sshConn != nil {
				sshConn.SendConnection(logLine, ev)
			}

			conn, err := net.Dial("unix", hostAddr)
			if err != nil {
				slog.Error(
					"unable to connect to tcp balancer",
					"error", err,
				)

				err := cl.Close()
				if err != nil {
					slog.Error(
						"unable to close connection",
						"error", err,
					)
				}

				return
			}

			var proxyProtoHeader *proxyproto.Header

			tH.SSHConnections.Range(func(_ string, sshConn *SSHConnection) bool {
				if sshConn.ProxyProto != 0 {
					var sourceInfo *net.TCPAddr
					var destInfo *net.TCPAddr
					if _, ok := cl.RemoteAddr().(*net.TCPAddr); !ok {
						sourceInfo = sshConn.SSHConn.RemoteAddr().(*net.TCPAddr)
						destInfo = sshConn.SSHConn.LocalAddr().(*net.TCPAddr)
					} else {
						sourceInfo = cl.RemoteAddr().(*net.TCPAddr)
						destInfo = cl.LocalAddr().(*net.TCPAddr)
					}

					addressFamily := proxyproto.TCPv4
					if sourceInfo.IP.To4() == nil {
						addressFamily = proxyproto.TCPv6
					}

					proxyProtoHeader = &proxyproto.Header{
						Version:           sshConn.ProxyProto,
						Command:           proxyproto.PROXY,
						TransportProtocol: addressFamily,
						SourceAddr:        sourceInfo,
						DestinationAddr:   destInfo,
					}
				}

				return false
			})

			if proxyProtoHeader != nil {
				_, err := proxyProtoHeader.WriteTo(conn)
				if err != nil && viper.GetBool("debug") {
					slog.Error(
						"error writing to conn",
						"error", err,
					)
				}
			}

			if bufBytes != nil {
				_, err := conn.Write(bufBytes)
				if err != nil {
					slog.Error(
						"unable to write to conn",
						"error", err,
					)

					err := cl.Close()
					if err != nil {
						slog.Error(
							"unable to close connection",
							"error", err,
						)
					}

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
	IPFilter       *ipfilter.IPFilter
	Ports          *Ports
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
		Console:        NewWebConsole(),
		Ports:          &Ports{},
	}
}

// ConnectionEvent describes a visitor connection that a tunnel accepted.
type ConnectionEvent struct {
	// SSHConn is the client whose user is logged, or nil if there is none.
	SSHConn        *SSHConnection
	TunnelType     string
	TunnelId       string
	ConnectionType string
	RemoteAddr     string
	LocalAddr      string
}

// LogConnection logs a visitor connection that a tunnel accepted.
func (s *State) LogConnection(ev ConnectionEvent) {
	slog.Info("accepted connection", ev.attrs()...)
}

func (ev ConnectionEvent) attrs() []any {
	return []any{
		"remoteAddr", ev.RemoteAddr,
		"localAddr", ev.LocalAddr,
		"tunnelType", ev.TunnelType,
		"tunnelId", ev.TunnelId,
		"connectionType", ev.ConnectionType,
		"user", ev.SSHConn.User(),
	}
}

// ListenerOwner returns the client in conns that has a listener on addr, or nil.
func ListenerOwner(conns *syncmap.Map[string, *SSHConnection], addr string) *SSHConnection {
	var owner *SSHConnection

	conns.Range(func(_ string, conn *SSHConnection) bool {
		if _, ok := conn.Listeners.Load(addr); ok {
			owner = conn
		}

		return owner == nil
	})

	return owner
}
