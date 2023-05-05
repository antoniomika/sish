package sshmuxer

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
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

// handleRemoteForward will handle a remote forward request
// and stand up the relevant listeners.
func handleRemoteForward(newRequest *ssh.Request, sshConn *utils.SSHConnection, state *utils.State) {
	select {
	case <-sshConn.Exec:
	case <-time.After(1 * time.Second):
		break
	}

	cleanupOnce := &sync.Once{}
	check := &channelForwardMsg{}

	err := ssh.Unmarshal(newRequest.Payload, check)
	if err != nil {
		log.Println("Error unmarshaling remote forward payload:", err)
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

	if viper.GetBool("tcp-disabled") && bindPort != comparePortHTTP {
		log.Println("Tcp listeners are disabled for requested port: ", bindPort, ". User: ", sshConn.SSHConn.User())
		sshConn.SSHConn.Close()
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
		log.Println("Error creating temporary file:", err)

		err = newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
		return
	}
	tmpfile.Close()
	os.Remove(tmpfile.Name())

	listenAddr := tmpfile.Name()

	chanListener, err := net.Listen("unix", listenAddr)
	if err != nil {
		log.Println("Error listening on unix socket:", err)

		err = newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
		return
	}

	listenerHolder := &utils.ListenerHolder{
		ListenAddr: listenAddr,
		Listener:   chanListener,
		Type:       listenerType,
		SSHConn:    sshConn,
	}

	state.Listeners.Store(listenAddr, listenerHolder)
	sshConn.Listeners.Store(listenAddr, listenerHolder)

	deferHandler := func() {}

	cleanupChanListener := func() {
		listenerHolder.Close()
		state.Listeners.Delete(listenAddr)
		sshConn.Listeners.Delete(listenAddr)
		os.Remove(listenAddr)
		deferHandler()
	}

	go func() {
		<-sshConn.Close
		cleanupOnce.Do(cleanupChanListener)
	}()

	connType := "tcp"
	if sniProxyForced {
		connType = "tls"
	} else if !tcpAliasForced && stringPort == strconv.FormatUint(uint64(comparePortHTTP), 10) {
		connType = "http"
	} else if !tcpAliasForced && stringPort == strconv.FormatUint(uint64(comparePortHTTPS), 10) {
		connType = "https"
	}
	if viper.GetBool("debug") {
		log.Println("listenerType", listenerType, "connType:", connType, "stringPort:", stringPort, "comparePortHTTP:", comparePortHTTP, "comparePortHTTPS:", comparePortHTTPS)
	}
	portChannelForwardReplyPayload := channelForwardReply{bindPort}

	mainRequestMessages := fmt.Sprintf("Starting SSH Forwarding service for %s. Forwarded connections can be accessed via the following methods:\r\n", aurora.Sprintf(aurora.Green("%s:%s"), connType, stringPort))

	switch listenerType {
	case utils.HTTPListener:
		pH, serverURL, requestMessages, err := handleHTTPListener(check, stringPort, mainRequestMessages, listenerHolder, state, sshConn, connType)
		if err != nil {
			log.Println("Error setting up HTTPListener:", err)

			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		mainRequestMessages = requestMessages

		deferHandler = func() {
			err := pH.Balancer.RemoveServer(serverURL)
			if err != nil {
				log.Println("Unable to remove server from balancer:", err)
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
			log.Println("Error setting up AliasListener:", err)

			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		mainRequestMessages = requestMessages

		deferHandler = func() {
			err := aH.Balancer.RemoveServer(serverURL)
			if err != nil {
				log.Println("Unable to remove server from balancer:", err)
			}

			aH.SSHConnections.Delete(listenerHolder.Addr().String())

			if len(aH.Balancer.Servers()) == 0 {
				state.AliasListeners.Delete(validAlias)
			}
		}
	case utils.TCPListener:
		tH, balancer, balancerName, serverURL, tcpAddr, requestMessages, err := handleTCPListener(check, bindPort, mainRequestMessages, listenerHolder, state, sshConn, sniProxyForced)
		if err != nil {
			log.Println("Error setting up TCPListener:", err)

			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}

			cleanupOnce.Do(cleanupChanListener)

			return
		}

		portChannelForwardReplyPayload.Rport = uint32(tH.Listener.Addr().(*net.TCPAddr).Port)

		mainRequestMessages = requestMessages

		if !tH.NoHandle {
			go tH.Handle(state)
		}

		deferHandler = func() {
			err := balancer.RemoveServer(serverURL)
			if err != nil {
				log.Println("Unable to remove server from balancer:", err)
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
					tH.Listener.Close()
					state.Listeners.Delete(tcpAddr)
					state.TCPListeners.Delete(tcpAddr)
				}
			}
		}
	}

	if check.Rport != 0 {
		portChannelForwardReplyPayload.Rport = check.Rport
	}

	err = newRequest.Reply(true, ssh.Marshal(portChannelForwardReplyPayload))
	if err != nil {
		log.Println("Error replying to port forwarding request:", err)
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

			resp := &forwardedTCPPayload{
				Addr:       originalAddress,
				Port:       portChannelForwardReplyPayload.Rport,
				OriginAddr: originalAddress,
				OriginPort: portChannelForwardReplyPayload.Rport,
			}

			newChan, newReqs, err := sshConn.SSHConn.OpenChannel("forwarded-tcpip", ssh.Marshal(resp))
			if err != nil {
				sshConn.SendMessage(err.Error(), true)
				cl.Close()
				continue
			}

			if sshConn.ProxyProto != 0 && listenerType == utils.TCPListener {
				var sourceInfo *net.TCPAddr
				var destInfo *net.TCPAddr
				if _, ok := cl.RemoteAddr().(*net.TCPAddr); !ok {
					sourceInfo = sshConn.SSHConn.RemoteAddr().(*net.TCPAddr)
					destInfo = sshConn.SSHConn.LocalAddr().(*net.TCPAddr)
				} else {
					sourceInfo = cl.RemoteAddr().(*net.TCPAddr)
					destInfo = cl.LocalAddr().(*net.TCPAddr)
				}

				proxyProtoHeader := proxyproto.Header{
					Version:           sshConn.ProxyProto,
					Command:           proxyproto.ProtocolVersionAndCommand(proxyproto.PROXY),
					TransportProtocol: proxyproto.AddressFamilyAndProtocol(proxyproto.TCPv4),
					SourceAddr:        sourceInfo,
					DestinationAddr:   destInfo,
				}

				_, err := proxyProtoHeader.WriteTo(newChan)
				if err != nil && viper.GetBool("debug") {
					log.Println("Error writing to channel:", err)
				}
			}

			go utils.CopyBoth(cl, newChan)
			go ssh.DiscardRequests(newReqs)
		}
	}()
}
