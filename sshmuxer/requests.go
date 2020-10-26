package sshmuxer

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/antoniomika/go-proxyproto"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
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
	cleanupOnce := &sync.Once{}
	check := &channelForwardMsg{}

	err := ssh.Unmarshal(newRequest.Payload, check)
	if err != nil {
		log.Println("Error unmarshaling remote forward payload:", err)
	}

	bindPort := check.Rport
	stringPort := strconv.FormatUint(uint64(bindPort), 10)

	listenerType := utils.HTTPListener
	if bindPort != uint32(80) && bindPort != uint32(443) {
		testAddr := net.ParseIP(check.Addr)
		if viper.GetBool("tcp-aliases") && check.Addr != "localhost" && testAddr == nil {
			listenerType = utils.AliasListener
		} else if check.Addr == "localhost" || testAddr != nil {
			listenerType = utils.TCPListener
		}
	}

	tmpfile, err := ioutil.TempFile("", sshConn.SSHConn.RemoteAddr().String()+":"+stringPort)
	if err != nil {
		err = newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
		return
	}
	os.Remove(tmpfile.Name())

	listenAddr := tmpfile.Name()

	chanListener, err := net.Listen("unix", listenAddr)
	if err != nil {
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
	if stringPort == "80" {
		connType = "http"
	} else if stringPort == "443" {
		connType = "https"
	}

	portChannelForwardReplyPayload := channelForwardReply{bindPort}

	mainRequestMessages := fmt.Sprintf("Starting SSH Forwarding service for %s. Forwarded connections can be accessed via the following methods:\r\n", aurora.Sprintf(aurora.Green("%s:%s"), connType, stringPort))

	switch listenerType {
	case utils.HTTPListener:
		pH, serverURL, host, requestMessages, err := handleHTTPListener(check, stringPort, mainRequestMessages, listenerHolder, state, sshConn)
		if err != nil {
			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}
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
				state.HTTPListeners.Delete(host)

				if viper.GetBool("admin-console") || viper.GetBool("service-console") {
					state.Console.RemoveRoute(host)
				}
			}
		}
	case utils.AliasListener:
		aH, serverURL, validAlias, requestMessages, err := handleAliasListener(check, stringPort, mainRequestMessages, listenerHolder, state, sshConn)
		if err != nil {
			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}
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
		tH, serverURL, tcpAddr, requestMessages, err := handleTCPListener(check, bindPort, mainRequestMessages, listenerHolder, state, sshConn)
		if err != nil {
			err = newRequest.Reply(false, nil)
			if err != nil {
				log.Println("Error replying to socket request:", err)
			}
			return
		}

		portChannelForwardReplyPayload.Rport = uint32(tH.Listener.Addr().(*net.TCPAddr).Port)

		mainRequestMessages = requestMessages

		go tH.Handle(state)

		deferHandler = func() {
			err := tH.Balancer.RemoveServer(serverURL)
			if err != nil {
				log.Println("Unable to remove server from balancer:", err)
			}

			tH.SSHConnections.Delete(listenerHolder.Addr().String())

			if len(tH.Balancer.Servers()) == 0 {
				tH.Listener.Close()
				state.Listeners.Delete(tcpAddr)
				state.TCPListeners.Delete(tcpAddr)
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
				Addr:       check.Addr,
				Port:       portChannelForwardReplyPayload.Rport,
				OriginAddr: check.Addr,
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
					Version:            sshConn.ProxyProto,
					Command:            proxyproto.ProtocolVersionAndCommand(proxyproto.PROXY),
					TransportProtocol:  proxyproto.AddressFamilyAndProtocol(proxyproto.TCPv4),
					SourceAddress:      sourceInfo.IP,
					DestinationAddress: destInfo.IP,
					SourcePort:         uint16(sourceInfo.Port),
					DestinationPort:    uint16(destInfo.Port),
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
