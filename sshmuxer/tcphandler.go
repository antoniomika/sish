package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/logrusorgru/aurora"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

// handleTCPListener handles the creation of the tcpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleTCPListener(check *channelForwardMsg, bindPort uint32, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection, sniProxyEnabled bool) (*utils.TCPHolder, *roundrobin.RoundRobin, string, *url.URL, string, string, error) {
	tcpAddr, tcpPort, tH, err := utils.GetOpenPort(check.Addr, bindPort, state, sshConn, sniProxyEnabled)
	if err != nil {
		return nil, nil, "", nil, "", "", err
	}

	if tcpPort != bindPort && viper.GetBool("force-requested-ports") {
		return nil, nil, "", nil, "", "", fmt.Errorf("error assigning requested port to tunnel")
	}

	var balancer *roundrobin.RoundRobin

	balancerName := ""
	if tH != nil && tH.SNIProxy {
		balancerName = check.Addr
	}

	created := tH == nil

	// A listener this call created is removed again if the binding fails before
	// anyone uses it. Callers hold BindLock so no other binding registers on it meanwhile.
	fail := func(err error) (*utils.TCPHolder, *roundrobin.RoundRobin, string, *url.URL, string, string, error) {
		if created {
			inUse := false
			tH.Balancers.Range(func(string, *roundrobin.RoundRobin) bool {
				inUse = true
				return false
			})

			if !inUse {
				utils.RemoveTCPHolder(state, tcpAddr, tH)
			}
		}

		return nil, nil, "", nil, "", "", err
	}

	if tH == nil {
		lis, err := utils.Listen(tcpAddr)
		if err != nil {
			slog.Error(
				"error listening on address",
				"err", err,
			)
			return nil, nil, "", nil, "", "", err
		}

		// Every kernel-assigned port would share the key addr:0, so use what it bound to.
		if tcpPort == 0 {
			tcpAddr = utils.ListenerAddressKey(lis)
		}

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

	// Picking a name can wait on the client, so it happens before taking the lock.
	var sniName string
	var sniErr error
	if sniProxyEnabled {
		sniName, sniErr = utils.GetOpenSNIHost(balancerName, state, sshConn, tH)
	}

	// Registering and tearing down a listener's balancers happen under the same
	// lock, so a listener can't be closed between this check and the registration below.
	state.BindLock.Lock()
	defer state.BindLock.Unlock()

	// Whoever closed the listener has already removed it.
	if registered, ok := state.TCPListeners.Load(tcpAddr); !ok || registered != tH {
		return nil, nil, "", nil, "", "", fmt.Errorf("listener %s was closed while binding", tcpAddr)
	}

	if sniProxyEnabled {
		if sniErr != nil || (!strings.HasPrefix(sniName, check.Addr) && viper.GetBool("force-requested-subdomains")) {
			return fail(fmt.Errorf("error assigning requested address to tunnel"))
		}

		balancerName = sniName

		// Another binding may have taken the name since it was checked.
		if utils.SNINameTaken(state, tH, balancerName, sshConn) {
			return fail(fmt.Errorf("sni name %s was bound by another tunnel", balancerName))
		}
	}

	foundBalancer, ok := tH.Balancers.Load(balancerName)
	if ok {
		balancer = foundBalancer
	} else {
		newBalancer, err := roundrobin.New(nil)

		if err != nil {
			slog.Error(
				"error initializing tcp balancer",
				"err", err,
			)
			return fail(err)
		}

		tH.Balancers.Store(balancerName, newBalancer)

		balancer = newBalancer
	}

	tH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host: base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
	}

	err = balancer.UpsertServer(serverURL)
	if err != nil {
		slog.Error(
			"unable to add server to balancer",
			"err", err,
		)
	}

	domainName := viper.GetString("domain")
	if balancerName != "" {
		domainName = balancerName
	}

	connType := "TCP"
	if sniProxyEnabled {
		connType = "TLS"
	}

	listenPort := utils.ListenerPort(tH.Listener)
	requestMessages += sshConn.FormatLog(
		slog.LevelInfo,
		fmt.Sprintf("%s: %s:%d\r\n", aurora.BgBlue(connType), domainName, listenPort),
		"forwarding started",
		"forwardingType", connType,
		"addr", fmt.Sprintf("%s:%d", domainName, listenPort),
	)
	sshConn.Logger().Info(
		"forwarding started",
		"forwardingType", connType,
		"addr", fmt.Sprintf("%s:%d", domainName, listenPort),
		"listenerAddr", listenerHolder.Addr().String(),
	)

	return tH, balancer, balancerName, serverURL, tcpAddr, requestMessages, nil
}
