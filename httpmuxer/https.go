package httpmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
)

type proxyListener struct {
	Listener net.Listener
	Holder   *utils.TCPHolder
	State    *utils.State
}

func (pL *proxyListener) Accept() (net.Conn, error) {
	cl, err := pL.Listener.Accept()
	if err != nil {
		return nil, err
	}

	clientRemote, _, err := net.SplitHostPort(cl.RemoteAddr().String())

	if err != nil || pL.State.IPFilter.Blocked(clientRemote) {
		err := cl.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
		}

		if viper.GetBool("debug") {
			log.Printf("Blocked connection from %s to %s", cl.RemoteAddr().String(), cl.LocalAddr().String())
		}

		return pL.Accept()
	}

	tlsHello, teeConn, _ := utils.PeekTLSHello(cl)
	if tlsHello == nil {
		return teeConn, nil
	}

	balancerName := tlsHello.ServerName
	if balancerName == "" {
		return teeConn, nil
	}

	balancer, ok := pL.Holder.Balancers.Load(balancerName)
	if !ok {
		pL.Holder.Balancers.Range(func(n string, b *roundrobin.RoundRobin) bool {
			if utils.MatchesWildcardHost(balancerName, n) {
				balancer = b
				return false
			}
			return true
		})

		if balancer == nil {
			return teeConn, nil
		}
	}

	connectionLocation, err := balancer.NextServer()
	if err != nil {
		log.Println("Unable to load connection location:", err)

		err := teeConn.Close()
		if err != nil {
			log.Println("Error closing teeConn:", err)
		}

		return pL.Accept()
	}

	host, err := base64.StdEncoding.DecodeString(connectionLocation.Host)
	if err != nil {
		log.Println("Unable to decode connection location:", err)

		err := teeConn.Close()
		if err != nil {
			log.Println("Error closing teeConn:", err)
		}

		return pL.Accept()
	}

	hostAddr := string(host)

	logLine := fmt.Sprintf("Accepted connection from %s -> %s", teeConn.RemoteAddr().String(), teeConn.LocalAddr().String())
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

		err := teeConn.Close()
		if err != nil {
			log.Println("Error closing teeConn:", err)
		}

		return pL.Accept()
	}

	go utils.CopyBoth(conn, teeConn)

	return pL.Accept()
}

func (pL *proxyListener) Close() error {
	return pL.Listener.Close()
}

// Addr returns the listener's network address.
func (pL *proxyListener) Addr() net.Addr {
	return pL.Listener.Addr()
}
