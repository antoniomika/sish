package httpmuxer

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

type proxyListener struct {
	Listener net.Listener
	Holder   *utils.TCPHolder
	State    *utils.State
}

func (pL *proxyListener) Accept() (net.Conn, error) {
	cl, err := pL.Listener.Accept()
	if err != nil {
		return nil, err
	}

	clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

	if err != nil || pL.State.IPFilter.Blocked(clientRemote) {
		err := cl.Close()
		if err != nil {
			slog.Error(
				"error closing connection",
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

		return pL.Accept()
	}

	tlsHello, teeConn, _ := utils.PeekTLSHello(cl)
	if tlsHello == nil {
		return teeConn, nil
	}

	balancerName := tlsHello.ServerName
	if balancerName == "" {
		return teeConn, nil
	}

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
			return teeConn, nil
		}
	}

	connectionLocation, err := balancer.NextServer()
	if err != nil {
		slog.Error(
			"unable to load connection location",
			"error", err,
		)

		err := teeConn.Close()
		if err != nil {
			slog.Error(
				"error closing teeConn",
				"error", err,
			)
		}

		return pL.Accept()
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		slog.Error(
			"unable to decode connection location",
			"error", err,
		)

		err := teeConn.Close()
		if err != nil {
			slog.Error(
				"error closing teeConn",
				"error", err,
			)
		}

		return pL.Accept()
	}

	hostAddr := string(host)

	logLine := fmt.Sprintf("Accepted HTTP connection from %s -> %s", teeConn.RemoteAddr().String(), teeConn.LocalAddr().String())

	sshConn := utils.ListenerOwner(pL.Holder.SSHConnections, hostAddr)

	pL.State.LogConnection(utils.ConnectionEvent{
		SSHConn:        sshConn,
		TunnelType:     "sni",
		TunnelId:       fmt.Sprintf("%s-%s", pL.Holder.TunnelId(), balancerName),
		ConnectionType: "tls",
		RemoteAddr:     teeConn.RemoteAddr().String(),
		LocalAddr:      teeConn.LocalAddr().String(),
	})

	if viper.GetBool("log-to-client") && sshConn != nil {
		sshConn.SendMessage(logLine, true)
	}

	conn, err := net.Dial("unix", hostAddr)
	if err != nil {
		slog.Error(
			"error connecting to tcp balancer",
			"error", err,
		)

		err := teeConn.Close()
		if err != nil {
			slog.Error(
				"error closing teeConn",
				"error", err,
			)
		}

		return pL.Accept()
	}

	go utils.CopyBoth(conn, teeConn)

	return pL.Accept()
}

func (pL *proxyListener) Close() error {
	return pL.Listener.Close()
}

// Addr returns the listener's network address.
func (pL *proxyListener) Addr() net.Addr {
	return pL.Listener.Addr()
}
