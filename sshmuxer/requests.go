package sshmuxer

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniomika/multilistener"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
	"golang.org/x/crypto/ssh"
)

// channelForwardMsg is the message sent by SSH
// to init a forwarded connection.
type channelForwardMsg struct {
	Addr  string
	Rport uint32
}

// channelForwardReply defines the reply to inform the client what port was
// actually assigned https://tools.ietf.org/html/rfc4254#section-7.1
type channelForwardReply struct {
	Rport uint32
}

// forwardedTCPPayload is the payload sent by SSH
// to init a forwarded connection.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// handleCancelRemoteForward will handle a remote forward cancellation
// request and remove the relevant listeners.
func handleCancelRemoteForward(newRequest *ssh.Request, sshConn *utils.SSHConnection, _ *utils.State) {
	check := &channelForwardMsg{}

	err := ssh.Unmarshal(newRequest.Payload, check)
	if err != nil {
		slog.Error(
			"error unmarshaling remote forward payload",
			"err", err,
		)
		err = newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to request",
				"err", err,
			)
		}
		return
	}

	closed := false

	sshConn.Listeners.Range(func(remoteAddr string, listener net.Listener) bool {
		holder, ok := listener.(*utils.ListenerHolder)
		if !ok {
			return false
		}

		if holder.OriginalAddr == check.Addr && (holder.OriginalPort == check.Rport || holder.BoundPort == check.Rport) {
			closed = true

			err := holder.Close()
			if err != nil {
				slog.Error(
					"error closing listener",
					"err", err,
				)
			}

			return false
		}

		return true
	})

	if !closed {
		sshConn.Logger().Warn(
			"no forward to cancel",
			"addr", check.Addr,
			"port", check.Rport,
		)

		err = newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to request",
				"err", err,
			)
		}

		return
	}

	err = newRequest.Reply(true, nil)
	if err != nil {
		slog.Error(
			"error replying to request",
			"err", err,
		)
	}
}

// handleRemoteForward will handle a remote forward request
// and stand up the relevant listeners.
func handleRemoteForward(newRequest *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	select {
	case <-sshConn.Exec:
	case <-sshConn.Close:
	case <-time.After(1 * time.Second):
	}

	cleanupOnce := &sync.Once{}

	// If the connection was torn down while we waited above (for example, the
	// client dropped right after requesting the forward), don't stand up any
	// forwarding for it: doing so would reserve the address for a dead session.
	select {
	case <-sshConn.Close:
		if err := newRequest.Reply(false, nil); err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
		return
	default:
	}

	check := &channelForwardMsg{}

	err := ssh.Unmarshal(newRequest.Payload, check)
	if err != nil {
		slog.Error(
			"error unmarshaling remote forward payload",
			"err", err,
		)

		err = newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
		return
	}

	originalCheck := &channelForwardMsg{
		Addr:  check.Addr,
		Rport: check.Rport,
	}

	originalAddress := check.Addr
	check.Addr = strings.ToLower(check.Addr)

	bindPort := check.Rport
	stringPort := strconv.FormatUint(uint64(bindPort), 10)

	listenerType := utils.HTTPListener

	comparePortHTTP := viper.GetUint32("http-port-override")
	comparePortHTTPS := viper.GetUint32("https-port-override")

	httpRequestPortOverride := viper.GetUint32("http-request-port-override")
	httpsRequestPortOverride := viper.GetUint32("https-request-port-override")

	if httpRequestPortOverride != 0 {
		comparePortHTTP = httpRequestPortOverride
	}

	if httpsRequestPortOverride != 0 {
		comparePortHTTPS = httpsRequestPortOverride
	}

	if comparePortHTTP == 0 {
		comparePortHTTP = 80
	}

	if comparePortHTTPS == 0 {
		comparePortHTTPS = 443
	}

	tcpAliasForced := viper.GetBool("tcp-aliases") && sshConn.TCPAlias
	sniProxyForced := viper.GetBool("sni-proxy") && sshConn.SNIProxy

	if tcpAliasForced {
		listenerType = utils.AliasListener
	} else if sniProxyForced {
		listenerType = utils.TCPListener
	} else if bindPort != comparePortHTTP && bindPort != comparePortHTTPS {
		testAddr := net.ParseIP(check.Addr)
		if check.Addr != "localhost" && testAddr == nil {
			listenerType = utils.AliasListener
		} else if check.Addr == "localhost" || testAddr != nil {
			listenerType = utils.TCPListener
		}
	}

	tmpfile, err := os.CreateTemp("", strings.ReplaceAll(sshConn.SSHConn.RemoteAddr().String()+":"+stringPort, ":", "_"))
	if err != nil {
		slog.Error(
			"error creating temporary file",
			"err", err,
		)

		err = newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
		return
	}

	err = tmpfile.Close()
	if err != nil {
		slog.Error(
			"error closing temporary file",
			"err", err,
		)
	}

	err = os.Remove(tmpfile.Name())
	if err != nil {
		slog.Error(
			"error removing temporary file",
			"err", err,
		)
	}

	listenAddr := tmpfile.Name()

	chanListener, err := net.Listen("unix", listenAddr)
	if err != nil {
		slog.Error(
			"error listening to unix socket",
			"err", err,
		)

		err = newRequest.Reply(false, nil)
		if err != nil {
			slog.Error(
				"error replying to socket request",
				"err", err,
			)
		}
		return
	}

	listenerHolder := &utils.ListenerHolder{
		ListenAddr:   listenAddr,
		Listener:     chanListener,
		Type:         listenerType,
		SSHConn:      sshConn,
		OriginalAddr: originalCheck.Addr,
		OriginalPort: originalCheck.Rport,
	}

	state.Listeners.Store(listenAddr, listenerHolder)
	sshConn.Listeners.Store(listenAddr, listenerHolder)

	deferHandler := func() {}

	// Set once a forward is actually established (see the switch below); used
	// to log when it is later torn down, mirroring the "forwarding started"
	// logs. Left empty for setups that never completed, so we don't log a stop
	// for a forward that never started.
	forwardingType := ""
	forwardingName := ""

	cleanupChanListener := func() {
		err := listenerHolder.Close()
		if err != nil {
			slog.Error(
				"error closing listener",
				"err", err,
			)
		}

		state.Listeners.Delete(listenAddr)
		sshConn.Listeners.Delete(listenAddr)

		// Closing the listener usually removes the socket already.
		err = os.Remove(listenAddr)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Error(
				"error removing unix socket",
				"err", err,
			)
		}

		deferHandler()

		if forwardingType != "" {
			sshConn.Logger().Info(
				"forwarding stopped",
				"forwardingType", forwardingType,
				"name", forwardingName,
				"listenerAddr", listenAddr,
			)
		}
	}

	connType := "tcp"
	if sniProxyForced {
		connType = "tls"
	} else if !tcpAliasForced && stringPort == strconv.FormatUint(uint64(comparePortHTTP), 10) {
		connType = "http"
	} else if !tcpAliasForced && stringPort == strconv.FormatUint(uint64(comparePortHTTPS), 10) {
		connType = "https"
	}

	portChannelForwardReplyPayload := channelForwardReply{bindPort}

	mainRequestMessages := sshConn.FormatLog(slog.LevelInfo, fmt.Sprintf("Starting SSH Forwarding service for %s. Forwarded connections can be accessed via the following methods:\r\n", aurora.Sprintf(aurora.Green("%s:%s"), connType, stringPort)), "")

	switch listenerType {
	case utils.HTTPListener:
		pH, serverURL, requestMessages, err := handleHTTPListener(check, stringPort, mainRequestMessages, listenerHolder, state, sshConn, connType)
		if err != nil {
			slog.Error(
				"error setting up HTTPListener",
				"err", err,
			)

			err = newRequest.Reply(false, nil)
			if err != nil {
				slog.Error(
					"error replying to socket request",
					"err", err,
				)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		mainRequestMessages = requestMessages

		forwardingType = strings.ToUpper(connType)
		forwardingName = pH.TunnelId()

		deferHandler = func() {
			err := pH.Balancer.RemoveServer(serverURL)
			if err != nil {
				slog.Error(
					"error removing server from balancer",
					"err", err,
				)
			}

			pH.SSHConnections.Delete(listenerHolder.Addr().String())

			if len(pH.Balancer.Servers()) == 0 {
				state.HTTPListeners.Delete(pH.HTTPUrl.String())

				if viper.GetBool("admin-console") || viper.GetBool("service-console") {
					state.Console.RemoveRoute(pH.HTTPUrl.String())
				}
			}
		}
	case utils.AliasListener:
		aH, serverURL, validAlias, requestMessages, err := handleAliasListener(check, stringPort, mainRequestMessages, listenerHolder, state, sshConn)
		if err != nil {
			slog.Error(
				"error setting up AliasListener",
				"err", err,
			)

			err = newRequest.Reply(false, nil)
			if err != nil {
				slog.Error(
					"error replying to socket request",
					"err", err,
				)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		mainRequestMessages = requestMessages

		forwardingType = "TCP Alias"
		forwardingName = validAlias

		deferHandler = func() {
			err := aH.Balancer.RemoveServer(serverURL)
			if err != nil {
				slog.Error(
					"unable to remove server from balancer",
					"err", err,
				)
			}

			aH.SSHConnections.Delete(listenerHolder.Addr().String())

			if len(aH.Balancer.Servers()) == 0 {
				state.AliasListeners.Delete(validAlias)
			}
		}
	case utils.TCPListener:
		tH, balancer, balancerName, serverURL, tcpAddr, requestMessages, err := handleTCPListener(check, bindPort, mainRequestMessages, listenerHolder, state, sshConn, sniProxyForced)
		if err != nil {
			slog.Error(
				"error setting up TCPListener",
				"err", err,
			)

			err = newRequest.Reply(false, nil)
			if err != nil {
				slog.Error(
					"error replying to socket request",
					"err", err,
				)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		portChannelForwardReplyPayload.Rport = uint32(tH.Listener.Addr().(*multilistener.MultiListener).Addresses()[0].(*net.TCPAddr).Port)

		mainRequestMessages = requestMessages

		forwardingType = strings.ToUpper(connType)
		forwardingName = tcpAddr

		if !tH.NoHandle {
			go tH.Handle(state)
		}

		deferHandler = func() {
			err := balancer.RemoveServer(serverURL)
			if err != nil {
				slog.Error(
					"error removing server from balancer",
					"err", err,
				)
			}

			tH.SSHConnections.Delete(listenerHolder.Addr().String())

			if len(balancer.Servers()) == 0 {
				tH.Balancers.Delete(balancerName)

				balancers := 0
				tH.Balancers.Range(func(n string, b *roundrobin.RoundRobin) bool {
					balancers += 1
					return false
				})

				if balancers == 0 {
					err := tH.Listener.Close()
					if err != nil {
						slog.Error(
							"error closing TCPListener",
							"err", err,
						)
					}

					state.Listeners.Delete(tcpAddr)
					state.TCPListeners.Delete(tcpAddr)
				}
			}
		}
	}

	// Only now that deferHandler has been assigned by the switch above do we
	// start watching for connection teardown. Wiring this up earlier races
	// with that assignment and can run cleanup against the no-op handler,
	// leaking the registered route. If the connection already closed during
	// setup, this fires immediately and tears everything back down.
	go func() {
		<-sshConn.Close
		cleanupOnce.Do(cleanupChanListener)
	}()

	if check.Rport != 0 {
		portChannelForwardReplyPayload.Rport = check.Rport
	}

	listenerHolder.BoundPort = portChannelForwardReplyPayload.Rport

	err = newRequest.Reply(true, ssh.Marshal(portChannelForwardReplyPayload))
	if err != nil {
		slog.Error(
			"error replying to port forward request",
			"err", err,
		)
		cleanupOnce.Do(cleanupChanListener)
		return
	}

	sshConn.SendMessage(mainRequestMessages, true)

	go func() {
		defer cleanupOnce.Do(cleanupChanListener)
		for {
			cl, err := listenerHolder.Accept()
			if err != nil {
				break
			}

			go func() {
				// RFC 4254 requires the originator address of a
				// forwarded-tcpip channel to be an IP address. The requested
				// bind address can be a hostname (localhost, HTTP subdomain
				// routes), which strict clients such as golang.org/x/crypto/ssh
				// reject, breaking every forwarded connection. The real
				// originator is not recoverable at this layer (the connection
				// arrives through a unix socket hop), so fall back to the
				// loopback address: the literal peer here is sish's own
				// internal dispatcher.
				originAddr := originalAddress
				if _, err := netip.ParseAddr(originAddr); err != nil {
					originAddr = "127.0.0.1"
				}
				resp := &forwardedTCPPayload{
					Addr:       originalAddress,
					Port:       portChannelForwardReplyPayload.Rport,
					OriginAddr: originAddr,
					OriginPort: portChannelForwardReplyPayload.Rport,
				}

				newChan, newReqs, err := sshConn.SSHConn.OpenChannel("forwarded-tcpip", ssh.Marshal(resp))
				if err != nil {
					sshConn.SendLog(
						slog.LevelError,
						err.Error(),
						"unable to open forwarded connection",
						"err", err,
					)

					err := cl.Close()
					if err != nil {
						slog.Error(
							"error closing client connection",
							"err", err,
						)
					}
					return
				}

				go ssh.DiscardRequests(newReqs)
				utils.CopyBoth(cl, newChan)
			}()
		}
	}()
}
