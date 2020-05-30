package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"

	"github.com/antoniomika/oxy/roundrobin"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
)

// handleTCPListener handles the creation of the tcpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleTCPListener(check *channelForwardMsg, bindPort uint32, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.TCPHolder, *url.URL, string, string, error) {
	tcpAddr, _, tH := utils.GetOpenPort(check.Addr, bindPort, state, sshConn)

	if tH == nil {
		lb, err := roundrobin.New(nil)

		if err != nil {
			log.Println("Error initializing tcp balancer:", err)
			return nil, nil, "", "", err
		}

		tH = &utils.TCPHolder{
			TCPHost:        tcpAddr,
			SSHConnections: &sync.Map{},
			Balancer:       lb,
		}

		l, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			log.Println("Error listening on addr:", err)
			return nil, nil, "", "", err
		}

		ln := &proxyproto.Listener{
			Listener: l,
		}

		tH.Listener = ln

		state.Listeners.Store(tcpAddr, ln)
		state.TCPListeners.Store(tcpAddr, tH)
	}

	tH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host: base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
	}

	err := tH.Balancer.UpsertServer(serverURL)
	if err != nil {
		log.Println("Unable to add server to balancer")
	}

	listenPort := tH.Listener.Addr().(*net.TCPAddr).Port
	requestMessages += fmt.Sprintf("%s: %s:%d\r\n", aurora.BgBlue("TCP"), viper.GetString("domain"), listenPort)
	log.Printf("%s forwarding started: %s:%d -> %s for client: %s\n", aurora.BgBlue("TCP"), viper.GetString("domain"), listenPort, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

	return tH, serverURL, tcpAddr, requestMessages, nil
}
