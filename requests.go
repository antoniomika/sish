package main

import (
	"log"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
	"golang.org/x/crypto/ssh"
)

type channelForwardMsg struct {
	Addr  string
	Rport uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func handleRemoteForward(newRequest *ssh.Request, sshConn *SSHConnection, state *State) {
	check := &channelForwardMsg{}

	ssh.Unmarshal(newRequest.Payload, check)

	stringPort := strconv.FormatUint(uint64(check.Rport), 10)
	listenAddr := check.Addr + ":" + stringPort

	if stringPort == "80" || stringPort == "443" {
		listenAddr = check.Addr + ":0"
	}

	chanListener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		newRequest.Reply(false, nil)
		return
	}

	state.Listeners.Store(chanListener.Addr(), chanListener)
	sshConn.Listeners.Store(chanListener.Addr(), chanListener)

	defer func() {
		chanListener.Close()
		state.Listeners.Delete(chanListener.Addr())
		sshConn.Listeners.Delete(chanListener.Addr())
	}()

	sshConn.Messages <- "Connections being forwarded to " + chanListener.Addr().String()

	if stringPort == "80" || stringPort == "443" {
		pH := &ProxyHolder{
			ProxyClient: &fasthttp.HostClient{
				Addr: chanListener.Addr().String(),
			},
		}

		host := strings.ToLower(RandStringBytesMaskImprSrc(3) + "." + *rootDomain)

		state.HTTPListeners.Store(host, pH)
		defer state.HTTPListeners.Delete(host)

		sshConn.Messages <- "HTTP requests for 80 and 443 can be reached on host: " + host
	}

	go func() {
		for {
			select {
			case <-sshConn.Close:
				log.Println(chanListener.Close())
				return
			default:
				break
			}
		}
	}()

	for {
		cl, err := chanListener.Accept()
		if err != nil {
			log.Println(err)
			break
		}

		defer cl.Close()

		addr := cl.RemoteAddr().(*net.TCPAddr)

		resp := &forwardedTCPPayload{
			Addr:       check.Addr,
			Port:       check.Rport,
			OriginAddr: addr.IP.String(),
			OriginPort: uint32(addr.Port),
		}

		newChan, newReqs, err := sshConn.SSHConn.OpenChannel("forwarded-tcpip", ssh.Marshal(resp))
		if err != nil {
			sshConn.Messages <- err.Error()
			cl.Close()
			continue
		}

		defer newChan.Close()

		go copyBoth(cl, newChan)

		ssh.DiscardRequests(newReqs)
	}
}

func copyBoth(writer net.Conn, reader ssh.Channel) {
	defer func() {
		writer.Close()
		reader.Close()
	}()

	go io.Copy(writer, reader)
	io.Copy(reader, writer)
}
