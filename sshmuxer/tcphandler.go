package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/antoniomika/go-proxyproto"
	"github.com/antoniomika/oxy/roundrobin"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
)

// handleTCPListener handles the creation of the tcpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleTCPListener(check *channelForwardMsg, bindPort uint32, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.TCPHolder, *url.URL, string, string, error) {
	tcpAddr, tcpPort, tH := utils.GetOpenPort(check.Addr, bindPort, state, sshConn)

	if tcpPort != bindPort && viper.GetBool("force-requested-ports") {
		return nil, nil, "", "", fmt.Errorf("Error assigning requested port to tunnel")
	}

	if tH == nil {
		lb, err := roundrobin.New(nil)

		if err != nil {
			log.Println("Error initializing tcp balancer:", err)
			return nil, nil, "", "", err
		}

		lis, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			log.Println("Error listening on addr:", err)
			return nil, nil, "", "", err
		}

		realAddr := lis.Addr().(*net.TCPAddr)

		tcpAddr = strings.ReplaceAll(realAddr.String(), "[::]", "")

		tH = &utils.TCPHolder{
			TCPHost:        tcpAddr,
			SSHConnections: &sync.Map{},
			Balancer:       lb,
		}

		var l net.Listener

		if viper.GetBool("proxy-protocol-listener") {
			ln := &proxyproto.Listener{
				Listener: lis,
			}

			utils.LoadProxyProtoConfig(ln)
			l = ln
		} else {
			l = lis
		}

		tH.Listener = l

		state.Listeners.Store(tcpAddr, l)
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
