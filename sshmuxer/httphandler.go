package sshmuxer

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/antoniomika/sish/httpmuxer"
	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

// handleHTTPListener handles the creation of the httpHandler
// (or addition for load balancing) and set's up the underlying listeners.
func handleHTTPListener(check *channelForwardMsg, _ string, requestMessages string, listenerHolder *utils.ListenerHolder, state *utils.State, sshConn *utils.SSHConnection, scheme string) (*utils.HTTPHolder, *url.URL, string, error) {
	hostUrl, pH := utils.GetOpenHost(check.Addr, state, sshConn)

	if (hostUrl == nil || !strings.HasPrefix(hostUrl.Host, check.Addr)) && viper.GetBool("force-requested-subdomains") {
		return nil, nil, "", fmt.Errorf("error assigning requested subdomain to tunnel")
	}

	if pH == nil {
		fwd := httpmuxer.NewForwarder()

		lb, err := roundrobin.New(fwd)

		if err != nil {
			slog.Error(
				"error initializing http balancer",
				"err", err,
			)
			return nil, nil, "", err
		}

		hostUrl.Scheme = scheme

		pH = &utils.HTTPHolder{
			HTTPUrl:        hostUrl,
			SSHConnections: syncmap.New[string, *utils.SSHConnection](),
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
		slog.Error(
			"error adding server to balancer",
			"err", err,
		)
	}

	var userPass string
	password, _ := pH.HTTPUrl.User.Password()
	if pH.HTTPUrl.User.Username() != "" || password != "" {
		userPass = fmt.Sprintf("%s:%s@", pH.HTTPUrl.User.Username(), password)
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
			if state.Ports.HTTPPort != 80 {
				portString = fmt.Sprintf(":%d", state.Ports.HTTPPort)
			}

			if viper.GetBool("https") {
				scheme = "https"
				if state.Ports.HTTPSPort != 443 {
					portString = fmt.Sprintf(":%d", state.Ports.HTTPSPort)
				}
			}

			pathParam := ""
			if pH.HTTPUrl.Path != "/" {
				pathParam = pH.HTTPUrl.Path
			}

			consoleURL := fmt.Sprintf("%s://%s%s%s%s", scheme, userPass, pH.HTTPUrl.Host, portString, pathParam)

			consoleURL = fmt.Sprintf("%s/_sish/console?x-authorization=%s", consoleURL, routeToken)
			requestMessages += sshConn.FormatLog(
				slog.LevelInfo,
				fmt.Sprintf("Service console can be accessed here: %s\r\n", consoleURL),
				"service console",
				"url", consoleURL,
			)
		}
	}

	if !viper.GetBool("proxy-ssl-termination") {
		httpPortString := ""
		if state.Ports.HTTPPort != 80 {
			httpPortString = fmt.Sprintf(":%d", state.Ports.HTTPPort)
		}

		httpURL := fmt.Sprintf("http://%s%s%s%s", userPass, pH.HTTPUrl.Host, httpPortString, pH.HTTPUrl.Path)
		requestMessages += sshConn.FormatLog(
			slog.LevelInfo,
			fmt.Sprintf("%s: %s\r\n", aurora.BgBlue("HTTP"), httpURL),
			"forwarding started",
			"forwardingType", "HTTP",
			"url", httpURL,
		)
		sshConn.Logger().Info(
			"forwarding started",
			"forwardingType", "HTTP",
			"url", fmt.Sprintf("http://%s%s%s", pH.HTTPUrl.Host, httpPortString, pH.HTTPUrl.Path),
			"listenerAddr", listenerHolder.Addr().String(),
		)
	}

	if viper.GetBool("https") || viper.GetBool("proxy-ssl-termination") {
		httpsPortString := ""
		if state.Ports.HTTPSPort != 443 {
			httpsPortString = fmt.Sprintf(":%d", state.Ports.HTTPSPort)
		}

		httpsURL := fmt.Sprintf("https://%s%s%s%s", userPass, pH.HTTPUrl.Host, httpsPortString, pH.HTTPUrl.Path)
		requestMessages += sshConn.FormatLog(
			slog.LevelInfo,
			fmt.Sprintf("%s: %s\r\n", aurora.BgBlue("HTTPS"), httpsURL),
			"forwarding started",
			"forwardingType", "HTTPS",
			"url", httpsURL,
		)
		sshConn.Logger().Info(
			"forwarding started",
			"forwardingType", "HTTPS",
			"url", fmt.Sprintf("https://%s%s%s", pH.HTTPUrl.Host, httpsPortString, pH.HTTPUrl.Path),
			"listenerAddr", listenerHolder.Addr().String(),
		)
	}

	return pH, serverURL, requestMessages, nil
}
