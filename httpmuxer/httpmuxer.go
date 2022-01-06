// Package httpmuxer handles all of the HTTP connections made
// to sish. This implements the http multiplexing necessary for
// sish's core feature.
package httpmuxer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/caddyserver/certmagic"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"

	"github.com/gin-gonic/gin"
)

// Start initializes the HTTP service.
func Start(state *utils.State) {
	releaseMode := gin.ReleaseMode
	if viper.GetBool("debug") {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)
	gin.DefaultWriter = state.LogWriter
	gin.ForceConsoleColor()

	r := gin.New()

	if viper.GetBool("load-templates") {
		r.LoadHTMLGlob(viper.GetString("load-templates-directory"))
	}

	r.Use(func(c *gin.Context) {
		// startTime is used for calculating latencies.
		c.Set("startTime", time.Now())

		// Here is where we check whether or not an IP is blocked.
		clientIPAddr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if state.IPFilter.Blocked(c.ClientIP()) || state.IPFilter.Blocked(clientIPAddr) || err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}, gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Here is the logger we use to format each incoming request.
		var statusColor, methodColor, resetColor string
		if param.IsOutputColor() {
			statusColor = param.StatusCodeColor()
			methodColor = param.MethodColor()
			resetColor = param.ResetColor()
		}

		if param.Latency > time.Minute {
			// Truncate in a golang < 1.8 safe way
			param.Latency = param.Latency - param.Latency%time.Second
		}

		originalURI := param.Keys["originalURI"].(string)

		if viper.GetString("admin-console-token") != "" && strings.Contains(originalURI, viper.GetString("admin-console-token")) {
			originalURI = strings.Replace(originalURI, viper.GetString("admin-console-token"), "[REDACTED]", 1)
		}

		if viper.GetString("service-console-token") != "" && strings.Contains(originalURI, viper.GetString("service-console-token")) {
			originalURI = strings.Replace(originalURI, viper.GetString("service-console-token"), "[REDACTED]", 1)
		}

		logLine := fmt.Sprintf("%v | %s |%s %3d %s| %13v | %15s |%s %-7s %s %s\n%s",
			param.TimeStamp.Format(viper.GetString("time-format")),
			param.Request.Host,
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			originalURI,
			param.ErrorMessage,
		)

		if viper.GetBool("log-to-client") && param.Keys["httpHolder"] != nil {
			currentListener := param.Keys["httpHolder"].(*utils.HTTPHolder)

			if currentListener != nil {
				sshConnTmp, ok := currentListener.SSHConnections.Load(param.Keys["proxySocket"])
				if ok {
					sshConn := sshConnTmp.(*utils.SSHConnection)
					sshConn.SendMessage(strings.TrimSpace(logLine), true)
				} else {
					currentListener.SSHConnections.Range(func(key, val interface{}) bool {
						sshConn := val.(*utils.SSHConnection)
						sshConn.SendMessage(strings.TrimSpace(logLine), true)
						return true
					})
				}
			}
		}

		return logLine
	}), gin.Recovery(), func(c *gin.Context) {
		c.Set("originalURI", c.Request.RequestURI)
		c.Set("originalPath", c.Request.URL.Path)
		c.Set("originalRawPath", c.Request.URL.RawPath)

		hostSplit := strings.Split(c.Request.Host, ":")
		hostname := hostSplit[0]
		hostIsRoot := hostname == viper.GetString("domain")

		if viper.GetBool("admin-console") && hostIsRoot && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest("", hostIsRoot, c)
			return
		}

		var currentListener *utils.HTTPHolder

		requestUsername, requestPassword, _ := c.Request.BasicAuth()
		authNeeded := true

		state.HTTPListeners.Range(func(key, value interface{}) bool {
			locationListener := value.(*utils.HTTPHolder)

			parsedPassword, _ := locationListener.HTTPUrl.User.Password()

			if hostname == locationListener.HTTPUrl.Host && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
				currentListener = locationListener

				credsEmpty := locationListener.HTTPUrl.User.Username() == "" && parsedPassword == ""
				credsMatch := requestUsername == locationListener.HTTPUrl.User.Username() && requestPassword == parsedPassword

				if credsEmpty || credsMatch {
					authNeeded = false

					if credsMatch {
						return false
					}
				}
			}

			return true
		})

		if currentListener == nil && hostIsRoot {
			if viper.GetBool("redirect-root") && !strings.HasPrefix(c.Request.URL.Path, "/favicon.ico") {
				c.Redirect(http.StatusFound, viper.GetString("redirect-root-location"))
				return
			}

			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if currentListener == nil {
			err := c.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", hostname))
			if err != nil {
				log.Println("Aborting with error", err)
			}
			return
		}

		c.Set("httpHolder", currentListener)

		if authNeeded {
			c.Header("WWW-Authenticate", "Basic realm=\"sish\"")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		stripPath := viper.GetBool("strip-http-path")

		currentListener.SSHConnections.Range(func(key, val interface{}) bool {
			sshConn := val.(*utils.SSHConnection)
			newHost := sshConn.HostHeader

			if sshConn.StripPath != viper.GetBool("strip-http-path") {
				stripPath = sshConn.StripPath
			}

			if newHost == "" {
				return true
			}

			if len(hostSplit) > 1 {
				newHost = fmt.Sprintf("%s:%s", newHost, hostSplit[1])
			}

			c.Request.Host = newHost
			return false
		})

		if viper.GetBool("strip-http-path") && stripPath {
			c.Request.RequestURI = strings.TrimPrefix(c.Request.RequestURI, currentListener.HTTPUrl.Path)
			c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, currentListener.HTTPUrl.Path)
			c.Request.URL.RawPath = strings.TrimPrefix(c.Request.URL.RawPath, currentListener.HTTPUrl.Path)
		}

		if viper.GetBool("rewrite-host-header") {
			currentListener.SSHConnections.Range(func(key, val interface{}) bool {
				sshConn := val.(*utils.SSHConnection)
				newHost := sshConn.HostHeader

				if newHost == "" {
					return true
				}

				if len(hostSplit) > 1 {
					newHost = fmt.Sprintf("%s:%s", newHost, hostSplit[1])
				}

				c.Request.Host = newHost
				return false
			})
		}

		if (viper.GetBool("admin-console") || viper.GetBool("service-console")) && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest(currentListener.HTTPUrl.String(), hostIsRoot, c)
			return
		}

		reqBody, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			log.Println("Error reading request body:", err)
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

		err = forward.ResponseModifier(ResponseModifier(state, hostname, reqBody, c, currentListener))(currentListener.Forward)
		if err != nil {
			log.Println("Unable to set response modifier:", err)
		}

		gin.WrapH(currentListener.Balancer)(c)
	})

	// If HTTPS is enabled, setup certmagic to allow us to provision HTTPS certs on the fly.
	// You can use sish without a wildcard cert, but you really should. If you get a lot of clients
	// with many random subdomains, you'll burn through your Let's Encrypt quota. Be careful!
	if viper.GetBool("https") {
		certmagic.Default.Storage = &certmagic.FileStorage{
			Path: filepath.Join(viper.GetString("https-certificate-directory"), "certmagic"),
		}

		certManager := certmagic.NewDefault()

		acmeManager := certmagic.NewACMEManager(certManager, certmagic.DefaultACME)

		acmeManager.Agreed = viper.GetBool("https-ondemand-certificate-accept-terms")
		acmeManager.Email = viper.GetString("https-ondemand-certificate-email")

		certManager.Issuers = []certmagic.Issuer{acmeManager}

		certManager.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(name string) error {
				if !viper.GetBool("https-ondemand-certificate") {
					return fmt.Errorf("ondemand certificate retrieval is not enabled")
				}

				ok := false

				state.HTTPListeners.Range(func(key, value interface{}) bool {
					locationListener := value.(*utils.HTTPHolder)

					if name == locationListener.HTTPUrl.Host {
						ok = true
						return false
					}

					return true
				})

				if !ok {
					return fmt.Errorf("cannot find connection for host: %s", name)
				}

				log.Println("Requesting certificate for host:", name)
				return nil
			},
		}

		utils.WatchCerts(certManager)

		httpsServer := &http.Server{
			Addr:      viper.GetString("https-address"),
			TLSConfig: certManager.TLSConfig(),
			Handler:   r,
		}

		go func() {
			var httpsListener net.Listener

			l, err := net.Listen("tcp", httpsServer.Addr)
			if err != nil {
				log.Fatalf("couldn't listen to %q: %q\n", httpsServer.Addr, err.Error())
			}

			if viper.GetBool("proxy-protocol-listener") {
				hListener := &proxyproto.Listener{
					Listener: l,
				}

				utils.LoadProxyProtoConfig(hListener)
				httpsListener = hListener
			} else {
				httpsListener = l
			}

			defer httpsListener.Close()

			log.Fatal(httpsServer.ServeTLS(httpsListener, "", ""))
		}()
	}

	httpServer := &http.Server{
		Addr:    viper.GetString("http-address"),
		Handler: r,
	}

	var httpListener net.Listener

	l, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", httpServer.Addr, err.Error())
	}

	if viper.GetBool("proxy-protocol-listener") {
		hListener := &proxyproto.Listener{
			Listener: l,
		}

		utils.LoadProxyProtoConfig(hListener)
		httpListener = hListener
	} else {
		httpListener = l
	}

	defer httpListener.Close()

	log.Fatal(httpServer.Serve(httpListener))
}
