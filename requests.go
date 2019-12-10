package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
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

	err := ssh.Unmarshal(newRequest.Payload, check)
	if err != nil {
		log.Println("Error unmarshaling remote forward payload:", err)
	}

	bindPort := check.Rport

	handleTCPAliasing := false
	if bindPort != uint32(80) && bindPort != uint32(443) {
		if *tcpAlias && check.Addr != "localhost" {
			handleTCPAliasing = true
		} else {
			checkedPort, err := checkPort(check.Rport, *bindRange)
			if err != nil && !*bindRandom {
				err = newRequest.Reply(false, nil)
				if err != nil {
					log.Println("Error replying to socket request:", err)
				}
				return
			}

			bindPort = checkedPort
			if *bindRandom {
				bindPort = 0

				if *bindRange != "" {
					bindPort = getRandomPortInRange(*bindRange)
				}
			}
		}
	}

	stringPort := strconv.FormatUint(uint64(bindPort), 10)
	listenAddr := ":" + stringPort
	listenType := "tcp"

	tmpfile, err := ioutil.TempFile("", sshConn.SSHConn.RemoteAddr().String()+":"+stringPort)
	if err != nil {
		err = newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
		return
	}
	os.Remove(tmpfile.Name())

	if stringPort == "80" || stringPort == "443" || handleTCPAliasing {
		listenType = "unix"
		listenAddr = tmpfile.Name()
	}

	chanListener, err := net.Listen(listenType, listenAddr)
	if err != nil {
		err = newRequest.Reply(false, nil)
		if err != nil {
			log.Println("Error replying to socket request:", err)
		}
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

	connType := "tcp"
	if stringPort == "80" {
		connType = "http"
	} else if stringPort == "443" {
		connType = "https"
	}

	requestMessages := fmt.Sprintf("Starting SSH Fowarding service for %s. Forwarded connections can be accessed via the following methods:\r\n", aurora.Sprintf(aurora.Green("%s:%s"), connType, stringPort))

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
			SSHConn:   sshConn,
		}

		state.HTTPListeners.Store(host, pH)
		defer state.HTTPListeners.Delete(host)

		httpPortString := ""
		if httpPort != 80 {
			httpPortString = fmt.Sprintf(":%d", httpPort)
		}

		requestMessages += fmt.Sprintf("%s: http://%s%s\r\n", aurora.BgBlue("HTTP"), host, httpPortString)
		log.Printf("%s forwarding started: http://%s%s -> %s for client: %s\n", aurora.BgBlue("HTTP"), host, httpPortString, chanListener.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

		if *httpsEnabled {
			httpsPortString := ""
			if httpsPort != 443 {
				httpsPortString = fmt.Sprintf(":%d", httpsPort)
			}

			requestMessages += fmt.Sprintf("%s: https://%s%s\r\n", aurora.BgBlue("HTTPS"), host, httpsPortString)
			log.Printf("%s forwarding started: https://%s%s -> %s for client: %s\n", aurora.BgBlue("HTTPS"), host, httpPortString, chanListener.Addr().String(), sshConn.SSHConn.RemoteAddr().String())
		}
	} else {
		if handleTCPAliasing {
			validAlias := getOpenAlias(check.Addr, stringPort, state, sshConn)

			state.TCPListeners.Store(validAlias, chanListener.Addr().String())
			defer state.TCPListeners.Delete(validAlias)

			requestMessages += fmt.Sprintf("%s: %s\r\n", aurora.BgBlue("TCP Alias"), validAlias)
			log.Printf("%s forwarding started: %s -> %s for client: %s\n", aurora.BgBlue("TCP Alias"), validAlias, chanListener.Addr().String(), sshConn.SSHConn.RemoteAddr().String())
		} else {
			requestMessages += fmt.Sprintf("%s: %s:%d\r\n", aurora.BgBlue("TCP"), *rootDomain, chanListener.Addr().(*net.TCPAddr).Port)
			log.Printf("%s forwarding started: %s:%d -> %s for client: %s\n", aurora.BgBlue("TCP"), *rootDomain, chanListener.Addr().(*net.TCPAddr).Port, chanListener.Addr().String(), sshConn.SSHConn.RemoteAddr().String())
		}
	}

	sendMessage(sshConn, requestMessages, false)

	go func() {
		<-sshConn.Close
		chanListener.Close()
	}()

	for {
		cl, err := chanListener.Accept()
		if err != nil {
			break
		}

		defer cl.Close()

		if connType == "tcp" {
			logLine := fmt.Sprintf("Accepted connection from %s -> %s", cl.RemoteAddr().String(), sshConn.SSHConn.RemoteAddr().String())
			log.Println(logLine)

			if *logToClient {
				sendMessage(sshConn, logLine, true)
			}
		}

		resp := &forwardedTCPPayload{
			Addr:       check.Addr,
			Port:       check.Rport,
			OriginAddr: check.Addr,
			OriginPort: check.Rport,
		}

		newChan, newReqs, err := sshConn.SSHConn.OpenChannel("forwarded-tcpip", ssh.Marshal(resp))
		if err != nil {
			sendMessage(sshConn, err.Error(), true)
			cl.Close()
			continue
		}

		defer newChan.Close()

		if sshConn.ProxyProto != 0 && (listenType != "unix" || handleTCPAliasing) {
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
			if err != nil && *debug {
				log.Println("Error writing to channel:", err)
			}
		}

		go copyBoth(cl, newChan)
		go ssh.DiscardRequests(newReqs)
	}
}

// IdleTimeoutConn handles the connection with a context deadline
// code adapted from https://qiita.com/kwi/items/b38d6273624ad3f6ae79
type IdleTimeoutConn struct {
	Conn net.Conn
}

// Read is needed to implement the reader part
func (i IdleTimeoutConn) Read(buf []byte) (int, error) {
	err := i.Conn.SetDeadline(time.Now().Add(*idleTimeout * time.Second))
	if err != nil {
		return 0, err
	}

	return i.Conn.Read(buf)
}

// Write is needed to implement the writer part
func (i IdleTimeoutConn) Write(buf []byte) (int, error) {
	err := i.Conn.SetDeadline(time.Now().Add(*idleTimeout * time.Second))
	if err != nil {
		return 0, err
	}

	return i.Conn.Write(buf)
}

func copyBoth(writer net.Conn, reader ssh.Channel) {
	closeBoth := func() {
		reader.Close()
		writer.Close()
	}

	tcon := IdleTimeoutConn{
		Conn: writer,
	}

	copyToReader := func() {
		_, err := io.Copy(reader, tcon)
		if err != nil && *debug {
			log.Println("Error copying to reader:", err)
		}

		closeBoth()
	}

	copyToWriter := func() {
		_, err := io.Copy(tcon, reader)
		if err != nil && *debug {
			log.Println("Error copying to writer:", err)
		}

		closeBoth()
	}

	go copyToReader()
	copyToWriter()
}
