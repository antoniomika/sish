package httpmuxer

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

type proxyListener struct {
	Listener net.Listener
	Holder   *utils.TCPHolder
	State    *utils.State

	// HelloTimeout bounds how long a client has to send its TLS hello. 0 waits forever.
	HelloTimeout time.Duration

	setup sync.Once
	start sync.Once
	stop  sync.Once
	conns chan net.Conn
	done  chan struct{}
}

func (pL *proxyListener) init() {
	pL.setup.Do(func() {
		pL.conns = make(chan net.Conn)
		pL.done = make(chan struct{})
	})
}

// Accept returns the next connection for sish's own HTTPS server. Connections
// whose SNI matches a tunnel are passed to it and never returned.
func (pL *proxyListener) Accept() (net.Conn, error) {
	pL.init()
	pL.start.Do(func() { go pL.acceptLoop() })

	select {
	case conn := <-pL.conns:
		return conn, nil
	case <-pL.done:
		return nil, net.ErrClosed
	}
}

func (pL *proxyListener) acceptLoop() {
	backoff := time.Duration(0)

	for {
		cl, err := pL.Listener.Accept()
		if err != nil {
			select {
			case <-pL.done:
				return
			default:
			}

			// Errors such as running out of file descriptors pass, so keep accepting.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)

			slog.Error(
				"error accepting https connection",
				"err", err,
				"retryIn", backoff,
			)

			select {
			case <-time.After(backoff):
			case <-pL.done:
				return
			}

			continue
		}

		backoff = 0

		// Reading the hello can take as long as the client wants, so it can't hold up the accept loop.
		go pL.route(cl)
	}
}

// route sends a connection to the tunnel its SNI names, or to sish's HTTPS server.
func (pL *proxyListener) route(cl net.Conn) {
	closeConn := func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			slog.Error(
				"error closing connection",
				"err", err,
			)
		}
	}

	clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

	if err != nil || pL.State.IPFilter.Blocked(clientRemote) {
		closeConn(cl)

		if viper.GetBool("debug") {
			slog.Debug(
				"blocked connection",
				"remoteAddr", cl.RemoteAddr().String(),
				"localAddr", cl.LocalAddr().String(),
			)
		}

		return
	}

	tlsHello, teeConn, _ := utils.PeekTLSHello(cl, pL.HelloTimeout)

	serve := func() {
		select {
		case pL.conns <- teeConn:
		case <-pL.done:
			closeConn(teeConn)
		}
	}

	if tlsHello == nil || tlsHello.ServerName == "" {
		serve()
		return
	}

	balancerName := tlsHello.ServerName

	balancer, ok := pL.Holder.Balancers.Load(balancerName)
	if !ok {
		pL.Holder.Balancers.Range(func(n string, b *roundrobin.RoundRobin) bool {
			if utils.MatchesWildcardHost(balancerName, n) {
				balancer = b
				return false
			}
			return true
		})

		if balancer == nil {
			serve()
			return
		}
	}

	connectionLocation, err := balancer.NextServer()
	if err != nil {
		slog.Error(
			"unable to load connection location",
			"err", err,
		)

		closeConn(teeConn)
		return
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		slog.Error(
			"unable to decode connection location",
			"err", err,
		)

		closeConn(teeConn)
		return
	}

	hostAddr := string(host)

	logLine := fmt.Sprintf("Accepted HTTP connection from %s -> %s", teeConn.RemoteAddr().String(), teeConn.LocalAddr().String())

	sshConn := utils.ListenerOwner(pL.Holder.SSHConnections, hostAddr)

	ev := utils.ConnectionEvent{
		SSHConn:        sshConn,
		TunnelType:     "sni",
		TunnelId:       fmt.Sprintf("%s-%s", pL.Holder.TunnelId(), balancerName),
		ConnectionType: "tls",
		RemoteAddr:     teeConn.RemoteAddr().String(),
		LocalAddr:      teeConn.LocalAddr().String(),
	}

	pL.State.LogConnection(ev)

	if viper.GetBool("log-to-client") && sshConn != nil {
		sshConn.SendConnection(logLine, ev)
	}

	conn, err := net.Dial("unix", hostAddr)
	if err != nil {
		slog.Error(
			"error connecting to tcp balancer",
			"err", err,
		)

		closeConn(teeConn)
		return
	}

	utils.CopyBoth(conn, teeConn)
}

func (pL *proxyListener) Close() error {
	pL.init()
	pL.stop.Do(func() { close(pL.done) })

	return pL.Listener.Close()
}

// Addr returns the listener's network address.
func (pL *proxyListener) Addr() net.Addr {
	return pL.Listener.Addr()
}
