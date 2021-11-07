package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"

	"github.com/antoniomika/sish/httpmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/roundrobin"
)

// handleHTTPListener handles the creation of the httpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleHTTPListener(check *channelForwardMsg, stringPort string, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection) (*utils.HTTPHolder, *url.URL, string, error) {
	scheme := "http"
	if stringPort == "443" {
		scheme = "https"
	}

	hostUrl, pH := utils.GetOpenHost(check.Addr, state, sshConn)

	if !strings.HasPrefix(hostUrl.Host, check.Addr) && viper.GetBool("force-requested-subdomains") {
		return nil, nil, "", fmt.Errorf("error assigning requested subdomain to tunnel")
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
			return nil, nil, "", err
		}

		lb, err := roundrobin.New(fwd)

		if err != nil {
			log.Println("Error initializing HTTP balancer:", err)
			return nil, nil, "", err
		}

		hostUrl.Scheme = scheme

		pH = &utils.HTTPHolder{
			HTTPUrl:        hostUrl,
			SSHConnections: &sync.Map{},
			Forward:        fwd,
			Balancer:       lb,
		}

		state.HTTPListeners.Store(pH.HTTPUrl.String(), pH)
	}

	pH.SSHConnections.Store(listenerHolder.Addr().String(), sshConn)

	serverURL := &url.URL{
		Host:   base64.StdEncoding.EncodeToString([]byte(listenerHolder.Addr().String())),
		Scheme: pH.HTTPUrl.Scheme,
	}

	err := pH.Balancer.UpsertServer(serverURL)
	if err != nil {
		log.Println("Unable to add server to balancer")
	}

	if viper.GetBool("admin-console") || viper.GetBool("service-console") {
		routeToken := viper.GetString("service-console-token")
		sendToken := false
		routeExists := state.Console.RouteExists(pH.HTTPUrl.String())

		if routeToken == "" {
			sendToken = true

			if routeExists {
				routeToken, _ = state.Console.RouteToken(pH.HTTPUrl.String())
			} else {
				routeToken = utils.RandStringBytesMaskImprSrc(20)
			}
		}

		if !routeExists {
			state.Console.AddRoute(pH.HTTPUrl.String(), routeToken)
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

			consoleURL := fmt.Sprintf("%s://%s%s", scheme, pH.HTTPUrl.Host, portString)

			requestMessages += fmt.Sprintf("Service console can be accessed here: %s/_sish/console?x-authorization=%s\r\n", consoleURL, routeToken)
		}
	}

	httpPortString := ""
	if httpPort != 80 {
		httpPortString = fmt.Sprintf(":%d", httpPort)
	}

	var userPass string
	password, _ := pH.HTTPUrl.User.Password()
	if pH.HTTPUrl.User.Username() != "" || password != "" {
		userPass = fmt.Sprintf("%s:%s@", pH.HTTPUrl.User.Username(), password)
	}

	requestMessages += fmt.Sprintf("%s: http://%s%s%s%s\r\n", aurora.BgBlue("HTTP"), userPass, pH.HTTPUrl.Host, httpPortString, pH.HTTPUrl.Path)

	log.Printf("%s forwarding started: http://%s%s%s%s -> %s for client: %s\n", aurora.BgBlue("HTTP"), userPass, pH.HTTPUrl.Host, httpPortString, pH.HTTPUrl.Path, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())

	if viper.GetBool("https") {
		httpsPortString := ""
		if httpsPort != 443 {
			httpsPortString = fmt.Sprintf(":%d", httpsPort)
		}

		requestMessages += fmt.Sprintf("%s: https://%s%s%s%s\r\n", aurora.BgBlue("HTTPS"), userPass, pH.HTTPUrl.Host, httpPortString, pH.HTTPUrl.Path)
		log.Printf("%s forwarding started: https://%s%s%s%s -> %s for client: %s\n", aurora.BgBlue("HTTPS"), userPass, pH.HTTPUrl.Host, httpsPortString, pH.HTTPUrl.Path, listenerHolder.Addr().String(), sshConn.SSHConn.RemoteAddr().String())
	}

	return pH, serverURL, requestMessages, nil
}
