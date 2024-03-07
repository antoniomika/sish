package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
)

// handleTCPListener handles the creation of the tcpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleTCPListener(check *channelForwardMsg, bindPort uint32, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection, sniProxyEnabled bool) (*utils.TCPHolder, *roundrobin.RoundRobin, string, *url.URL, string, string, error) {
	tcpAddr, tcpPort, tH := utils.GetOpenPort(check.Addr, bindPort, state, sshConn, sniProxyEnabled)

	if tcpPort != bindPort && viper.GetBool("force-requested-ports") {
		return nil, nil, "", nil, "", "", fmt.Errorf("error assigning requested port to tunnel")
	}

	var balancer *roundrobin.RoundRobin

	balancerName := ""
	if tH != nil && tH.SNIProxy {
		balancerName = check.Addr
	}

	if tH == nil {
		lis, err := utils.Listen(tcpAddr)
		if err != nil {
			log.Println("Error listening on addr:", err)
			return nil, nil, "", nil, "", "", err
		}

		realAddr := lis.Addr().(*net.TCPAddr)

		tcpAddr = strings.ReplaceAll(realAddr.String(), "[::]", "")

		tH = &utils.TCPHolder{
			TCPHost:        tcpAddr,
			SSHConnections: syncmap.New[string, *utils.SSHConnection](),
			Balancers:      syncmap.New[string, *roundrobin.RoundRobin](),
			SNIProxy:       sshConn.SNIProxy,
		}

		if sshConn.SNIProxy {
			balancerName = check.Addr
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

	if sniProxyEnabled {
		newName, err := utils.GetOpenSNIHost(balancerName, state, sshConn, tH)

		if err != nil || (!strings.HasPrefix(newName, check.Addr) && viper.GetBool("force-requested-subdomains")) {
			return nil, nil, "", nil, "", "", fmt.Errorf("error assigning requested address to tunnel")
		}

		balancerName = newName
	}

	foundBalancer, ok := tH.Balancers.Load(balancerName)
	if ok {
		balancer = foundBalancer
	} else {
		newBalancer, err := roundrobin.New(nil)

		if err != nil {
			log.Println("Error initializing tcp balancer:", err)
			return nil, nil, "", nil, "", "", err
		}

		tH.Balancers.Store(balancerName, newBalancer)

		balancer = newBalancer
	}

	tH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host: base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
	}

	err := balancer.UpsertServer(serverURL)
	if err != nil {
		log.Println("Unable to add server to balancer")
	}

	domainName := viper.GetString("domain")
	if balancerName != "" {
		domainName = balancerName
	}

	connType := "TCP"
	if sniProxyEnabled {
		connType = "TLS"
	}

	listenPort := tH.Listener.Addr().(*net.TCPAddr).Port
	requestMessages += fmt.Sprintf("%s: %s:%d\r\n", aurora.BgBlue(connType), domainName, listenPort)
	log.Printf("%s forwarding started: %s:%d -> %s for client: %s\n", aurora.BgBlue(connType), domainName, listenPort, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

	return tH, balancer, balancerName, serverURL, tcpAddr, requestMessages, nil
}
