package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"

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

	bindPort := check.Rport

	if bindPort != uint32(80) && bindPort != uint32(443) {
		checkedPort, err := checkPort(check.Rport, *bindRange)
		if err != nil && !*bindRandom {
			newRequest.Reply(false, nil)
			return
		}

		bindPort = checkedPort
		if *bindRandom {
			bindPort = 0
		}
	}

	stringPort := strconv.FormatUint(uint64(bindPort), 10)
	listenAddr := ":" + stringPort
	listenType := "tcp"

	tmpfile, err := ioutil.TempFile("", sshConn.SSHConn.RemoteAddr().String()+":"+stringPort)
	if err != nil {
		newRequest.Reply(false, nil)
		return
	}
	os.Remove(tmpfile.Name())

	if stringPort == "80" || stringPort == "443" {
		listenType = "unix"
		listenAddr = tmpfile.Name()
	}

	chanListener, err := net.Listen(listenType, listenAddr)
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
		os.Remove(tmpfile.Name())
	}()

	if stringPort == "80" || stringPort == "443" {
		scheme := "http"
		if stringPort == "443" {
			scheme = "https"
		}

		host := getOpenHost(check.Addr, state, sshConn)

		pH := &ProxyHolder{
			ProxyHost: host,
			ProxyTo:   chanListener.Addr().String(),
			Scheme:    scheme,
		}

		state.HTTPListeners.Store(host, pH)
		defer state.HTTPListeners.Delete(host)

		sshConn.Messages <- fmt.Sprintf("HTTP requests for 80 and 443 can be reached on host: %s", host)
	} else {
		sshConn.Messages <- fmt.Sprintf("Connections being forwarded to %s:%d", *rootDomain, chanListener.Addr().(*net.TCPAddr).Port)
	}

	go func() {
		for {
			select {
			case <-sshConn.Close:
				chanListener.Close()
				return
			}
		}
	}()

	for {
		cl, err := chanListener.Accept()
		if err != nil {
			break
		}

		defer cl.Close()

		resp := &forwardedTCPPayload{
			Addr:       check.Addr,
			Port:       check.Rport,
			OriginAddr: check.Addr,
			OriginPort: check.Rport,
		}

		newChan, newReqs, err := sshConn.SSHConn.OpenChannel("forwarded-tcpip", ssh.Marshal(resp))
		if err != nil {
			sshConn.Messages <- err.Error()
			cl.Close()
			continue
		}

		defer newChan.Close()

		go copyBoth(cl, newChan)
		go ssh.DiscardRequests(newReqs)
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
