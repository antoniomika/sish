package main

import (
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
)

var proxyProtoPrefix = "proxyproto:"

func handleSession(newChannel ssh.NewChannel, sshConn *SSHConnection, state *State) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		return
	}

	if *debug {
		log.Println("Handling session for connection:", connection)
	}

	go func() {
		for {
			select {
			case c := <-sshConn.Messages:
				connection.Write([]byte(c))
				connection.Write([]byte{'\r', '\n'})
			case <-sshConn.Close:
				return
			}
		}
	}()

	sshConn.Messages <- "Press Ctrl-C to close the session."

	go func() {
		for {
			data := make([]byte, 4096)
			dataRead, err := connection.Read(data)
			if err != nil && err == io.EOF {
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
				req.Reply(true, nil)
			case "exec":
				payloadString := string(req.Payload[4:])
				if strings.HasPrefix(payloadString, proxyProtoPrefix) && *proxyProtoEnabled {
					sshConn.ProxyProto = getProxyProtoVersion(strings.TrimPrefix(payloadString, proxyProtoPrefix))
					if sshConn.ProxyProto != 0 {
						sshConn.Messages <- fmt.Sprintf("Proxy protocol enabled for TCP connections. Using protocol version %d", int(sshConn.ProxyProto))
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
