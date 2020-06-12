package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"

	"github.com/antoniomika/oxy/forward"
	"github.com/antoniomika/oxy/roundrobin"
	"github.com/antoniomika/sish/httpmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
)

// handleHTTPListener handles the creation of the httpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleHTTPListener(check *channelForwardMsg, stringPort string, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.HTTPHolder, *url.URL, string, string, error) {
	scheme := "http"
	if stringPort == "443" {
		scheme = "https"
	}

	host, pH := utils.GetOpenHost(check.Addr, state, sshConn)

	if !strings.HasPrefix(host, check.Addr) && viper.GetBool("force-requested-subdomains") {
		return nil, nil, "", "", fmt.Errorf("Error assigning requested subdomain to tunnel")
	}

	if pH == nil {
		rT := httpmuxer.RoundTripper()

		fwd, err := forward.New(
			forward.PassHostHeader(true),
			forward.RoundTripper(rT),
			forward.WebsocketRoundTripper(rT),
		)

		if err != nil {
			log.Println("Error initializing HTTP forwarder:", err)
			return nil, nil, "", "", err
		}

		lb, err := roundrobin.New(fwd)

		if err != nil {
			log.Println("Error initializing HTTP balancer:", err)
			return nil, nil, "", "", err
		}

		pH = &utils.HTTPHolder{
			HTTPHost:       host,
			Scheme:         scheme,
			SSHConnections: &sync.Map{},
			Forward:        fwd,
			Balancer:       lb,
		}

		state.HTTPListeners.Store(host, pH)
	}

	pH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host:   base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
		Scheme: pH.Scheme,
	}

	err := pH.Balancer.UpsertServer(serverURL)
	if err != nil {
		log.Println("Unable to add server to balancer")
	}

	if viper.GetBool("admin-console") || viper.GetBool("service-console") {
		routeToken := viper.GetString("service-console-token")
		sendToken := false
		routeExists := state.Console.RouteExists(host)

		if routeToken == "" {
			sendToken = true

			if routeExists {
				routeToken, _ = state.Console.RouteToken(host)
			} else {
				routeToken = utils.RandStringBytesMaskImprSrc(20)
			}
		}

		if !routeExists {
			state.Console.AddRoute(host, routeToken)
		}

		if viper.GetBool("service-console") && sendToken {
			scheme := "http"
			portString := ""
			if httpPort != 80 {
				portString = fmt.Sprintf(":%d", httpPort)
			}

			if viper.GetBool("https") {
				scheme = "https"
				if httpsPort != 443 {
					portString = fmt.Sprintf(":%d", httpsPort)
				}
			}

			consoleURL := fmt.Sprintf("%s://%s%s", scheme, host, portString)

			requestMessages += fmt.Sprintf("Service console can be accessed here: %s/_sish/console?x-authorization=%s\r\n", consoleURL, routeToken)
		}
	}

	httpPortString := ""
	if httpPort != 80 {
		httpPortString = fmt.Sprintf(":%d", httpPort)
	}

	requestMessages += fmt.Sprintf("%s: http://%s%s\r\n", aurora.BgBlue("HTTP"), host, httpPortString)
	log.Printf("%s forwarding started: http://%s%s -> %s for client: %s\n", aurora.BgBlue("HTTP"), host, httpPortString, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

	if viper.GetBool("https") {
		httpsPortString := ""
		if httpsPort != 443 {
			httpsPortString = fmt.Sprintf(":%d", httpsPort)
		}

		requestMessages += fmt.Sprintf("%s: https://%s%s\r\n", aurora.BgBlue("HTTPS"), host, httpsPortString)
		log.Printf("%s forwarding started: https://%s%s -> %s for client: %s\n", aurora.BgBlue("HTTPS"), host, httpPortString, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())
	}

	return pH, serverURL, host, requestMessages, nil
}
