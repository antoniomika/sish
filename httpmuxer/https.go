package httpmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
)

type proxyListener struct {
	Listener net.Listener
	Holder   *utils.TCPHolder
	State    *utils.State
}

func (pL *proxyListener) Accept() (net.Conn, error) {
	for {
		cl, err := pL.Listener.Accept()
		if err != nil {
			return nil, err
		}

		clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

		if err != nil || pL.State.IPFilter.Blocked(clientRemote) {
			cl.Close()
			continue
		}

		tlsHello, buf, teeConn, peekErr := utils.PeekTLSHello(cl)
		if peekErr != nil && tlsHello == nil {
			return teeConn, nil
		}

		balancerName := tlsHello.ServerName
		balancer, ok := pL.Holder.Balancers.Load(balancerName)
		if balancerName == "" || !ok {
			return teeConn, nil
		}

		connectionLocation, err := balancer.NextServer()
		if err != nil {
			log.Println("Unable to load connection location:", err)
			cl.Close()
			continue
		}

		host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
		if err != nil {
			log.Println("Unable to decode connection location:", err)
			cl.Close()
			continue
		}

		hostAddr := string(host)

		logLine := fmt.Sprintf("Accepted connection from %s -> %s", cl.RemoteAddr().String(), cl.LocalAddr().String())
		log.Println(logLine)

		if viper.GetBool("log-to-client") {
			pL.Holder.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
				sshConn.Listeners.Range(func(listenerAddr string, val net.Listener) bool {
					if listenerAddr == hostAddr {
						sshConn.SendMessage(logLine, true)

						return false
					}

					return true
				})

				return true
			})
		}

		conn, err := net.Dial("unix", hostAddr)
		if err != nil {
			log.Println("Error connecting to tcp balancer:", err)
			cl.Close()
			continue
		}

		_, err = conn.Write(buf.Bytes())
		if err != nil {
			log.Println("Unable to write to conn:", err)
			cl.Close()
			continue
		}

		go utils.CopyBoth(conn, cl)
	}
}

func (pL *proxyListener) Close() error {
	return pL.Listener.Close()
}

// Addr returns the listener's network address.
func (pL *proxyListener) Addr() net.Addr {
	return pL.Listener.Addr()
}
