package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/logrusorgru/aurora"
	"golang.org/x/crypto/ssh"
)

var proxyProtoPrefix = "proxyproto:"

func handleSession(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	if *debug {
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
				if strings.HasPrefix(payloadString, proxyProtoPrefix) && *proxyProtoEnabled {
					sshConn.ProxyProto = getProxyProtoVersion(strings.TrimPrefix(payloadString, proxyProtoPrefix))
					if sshConn.ProxyProto != 0 {
						sendMessage(sshConn, fmt.Sprintf("Proxy protocol enabled for TCP connections. Using protocol version %d", int(sshConn.ProxyProto)), true)
					}
				}
			default:
				if *debug {
					log.Println("Sub Channel Type", req.Type, req.WantReply, string(req.Payload))
				}
			}
		}
	}()
}

func handleAlias(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		sshConn.CleanUp(state)
		return
	}

	go ssh.DiscardRequests(requests)

	if *debug {
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
	loc, ok := state.TCPListeners.Load(tcpAliasToConnect)
	if !ok {
		log.Println("Unable to load tcp alias:", tcpAliasToConnect)
		sshConn.CleanUp(state)
		return
	}

	conn, err := net.Dial("unix", loc.(string))
	if err != nil {
		log.Println("Error connecting to alias:", err)
		sshConn.CleanUp(state)
		return
	}

	sshConn.Listeners.Store(conn.RemoteAddr(), conn)

	copyBoth(conn, connection)

	select {
	case <-sshConn.Close:
		break
	default:
		sshConn.CleanUp(state)
	}
}

func writeToSession(connection ssh.Channel, c string) {
	_, err := connection.Write(append([]byte(c), []byte{'\r', '\n'}...))
	if err != nil && *debug {
		log.Println("Error trying to write message to socket:", err)
	}
}

func getProxyProtoVersion(proxyProtoUserVersion string) byte {
	if *proxyProtoVersion != "userdefined" {
		proxyProtoUserVersion = *proxyProtoVersion
	}

	realProtoVersion := 0
	if proxyProtoUserVersion == "1" {
		realProtoVersion = 1
	} else if proxyProtoUserVersion == "2" {
		realProtoVersion = 2
	}

	return byte(realProtoVersion)
}
