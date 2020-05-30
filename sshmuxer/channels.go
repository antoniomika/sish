package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// proxyProtoPrefix is used when deciding what proxy protocol
// version to use.
var proxyProtoPrefix = "proxyproto:"

// handleSession handles the channel when a user requests a session.
// This is how we send console messages.
func handleSession(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	if viper.GetBool("debug") {
		log.Println("Handling session for connection:", connection)
	}

	writeToSession(connection, aurora.BgRed("Press Ctrl-C to close the session.").String()+"\r\n")

	go func() {
		for {
			select {
			case c := <-sshConn.Messages:
				writeToSession(connection, c)
			case <-sshConn.Close:
				return
			}
		}
	}()

	go func() {
		for {
			data := make([]byte, 4096)
			dataRead, err := connection.Read(data)
			if err != nil && err == io.EOF {
				break
			} else if err != nil {
				select {
				case <-sshConn.Close:
					break
				default:
					sshConn.CleanUp(state)
				}
				break
			}

			if dataRead != 0 {
				if data[0] == 3 {
					sshConn.CleanUp(state)
				}
			}
		}
	}()

	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				err := req.Reply(true, nil)
				if err != nil {
					log.Println("Error replying to socket request:", err)
				}
			case "exec":
				payloadString := string(req.Payload[4:])
				if strings.HasPrefix(payloadString, proxyProtoPrefix) && viper.GetBool("proxy-protocol") {
					sshConn.ProxyProto = getProxyProtoVersion(strings.TrimPrefix(payloadString, proxyProtoPrefix))
					if sshConn.ProxyProto != 0 {
						sshConn.SendMessage(fmt.Sprintf("Proxy protocol enabled for TCP connections. Using protocol version %d", int(sshConn.ProxyProto)), true)
					}
				}
			default:
				if viper.GetBool("debug") {
					log.Println("Sub Channel Type", req.Type, req.WantReply, string(req.Payload))
				}
			}
		}
	}()
}

// handleAlias is used when handling a SSH connection to attach to an alias listener.
func handleAlias(newChannel ssh.NewChannel, sshConn *utils.SSHConnection, state *utils.State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	go ssh.DiscardRequests(requests)

	if viper.GetBool("debug") {
		log.Println("Handling alias connection for:", connection)
	}

	check := &forwardedTCPPayload{}
	err = ssh.Unmarshal(newChannel.ExtraData(), check)
	if err != nil {
		log.Println("Error unmarshaling information:", err)
		sshConn.CleanUp(state)
		return
	}

	tcpAliasToConnect := fmt.Sprintf("%s:%d", check.Addr, check.Port)
	loc, ok := state.AliasListeners.Load(tcpAliasToConnect)
	if !ok {
		log.Println("Unable to load tcp alias:", tcpAliasToConnect)
		sshConn.CleanUp(state)
		return
	}

	aH := loc.(*utils.AliasHolder)

	connectionLocation, err := aH.Balancer.NextServer()
	if err != nil {
		log.Println("Unable to load connection location:", err)
		sshConn.CleanUp(state)
		return
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		log.Println("Unable to decode connection location:", err)
		sshConn.CleanUp(state)
		return
	}

	aliasAddr := string(host)

	logLine := fmt.Sprintf("Accepted connection from %s -> %s", sshConn.SSHConn.RemoteAddr().String(), tcpAliasToConnect)
	log.Println(logLine)

	if viper.GetBool("log-to-client") {
		aH.SSHConnections.Range(func(key, val interface{}) bool {
			sshConn := val.(*utils.SSHConnection)

			sshConn.Listeners.Range(func(key, val interface{}) bool {
				listenerAddr := key.(string)

				if listenerAddr == aliasAddr {
					sshConn.SendMessage(logLine, true)

					return false
				}

				return true
			})

			return true
		})
	}

	conn, err := net.Dial("unix", aliasAddr)
	if err != nil {
		log.Println("Error connecting to alias:", err)
		sshConn.CleanUp(state)
		return
	}

	sshConn.Listeners.Store(aliasAddr, conn)

	utils.CopyBoth(conn, connection)

	select {
	case <-sshConn.Close:
		break
	default:
		sshConn.CleanUp(state)
	}
}

// writeToSession is where we write to the underlying session channel.
func writeToSession(connection ssh.Channel, c string) {
	_, err := connection.Write(append([]byte(c), []byte{'\r', '\n'}...))
	if err != nil && viper.GetBool("debug") {
		log.Println("Error trying to write message to socket:", err)
	}
}

// getProxyProtoVersion returns the proxy proto version selected by the client.
func getProxyProtoVersion(proxyProtoUserVersion string) byte {
	if viper.GetString("proxy-protocol-version") != "userdefined" {
		proxyProtoUserVersion = viper.GetString("proxy-protocol-version")
	}

	realProtoVersion := 0
	if proxyProtoUserVersion == "1" {
		realProtoVersion = 1
	} else if proxyProtoUserVersion == "2" {
		realProtoVersion = 2
	}

	return byte(realProtoVersion)
}
