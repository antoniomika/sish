// Package httpmuxer handles all of the HTTP connections made
// to sish. This implements the http multiplexing necessary for
// sish's core feature.
package httpmuxer

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/caddyserver/certmagic"
	"github.com/pires/go-proxyproto"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/oxy/roundrobin"

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
		clientIPAddrBlocked := state.IPFilter.Blocked(clientIPAddr)
		cClientIP := c.ClientIP()
		cClientIPBlocked := state.IPFilter.Blocked(cClientIP)

		if clientIPAddrBlocked || cClientIPBlocked || err != nil {
			status := http.StatusForbidden
			c.AbortWithStatus(status)
			if viper.GetBool("debug") {
				log.Println("Aborting with status", status)
				if clientIPAddrBlocked {
					log.Println("Blocked:", clientIPAddr)
				}
				if cClientIPBlocked {
					log.Println("Blocked:", cClientIP)
				}
			}
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
				proxySock, _ := param.Keys["proxySocket"].(string)
				sshConnTmp, ok := currentListener.SSHConnections.Load(proxySock)
				if ok {
					sshConn := sshConnTmp
					sshConn.SendMessage(strings.TrimSpace(logLine), true)
				} else {
					currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
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
		if strings.Contains(c.Request.Host, "[") && strings.Contains(c.Request.Host, "]") {
			hostSplit = strings.Split(c.Request.Host, "]:")
			if len(hostSplit) > 1 {
				hostSplit[0] = hostSplit[0] + "]"
			}
		}

		hostname := hostSplit[0]
		hostIsRoot := hostname == viper.GetString("domain")

		if viper.GetBool("admin-console") && hostIsRoot && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest("", hostIsRoot, c)
			return
		}

		var currentListener *utils.HTTPHolder

		requestUsername, requestPassword, _ := c.Request.BasicAuth()
		authNeeded := true

		state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
			parsedPassword, _ := locationListener.HTTPUrl.User.Password()

			if hostname == locationListener.HTTPUrl.Host && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
				credsNeeded := locationListener.HTTPUrl.User.Username() != "" && parsedPassword != ""
				credsMatch := requestUsername == locationListener.HTTPUrl.User.Username() && requestPassword == parsedPassword

				if credsNeeded {
					currentListener = locationListener

					if credsMatch {
						authNeeded = false
						return false
					}
				}
			}

			return true
		})

		if currentListener == nil {
			state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
				if hostname == locationListener.HTTPUrl.Host && strings.HasPrefix(c.Request.URL.Path, locationListener.HTTPUrl.Path) {
					currentListener = locationListener
					authNeeded = false
					return false
				}

				return true
			})
		}

		if currentListener == nil && hostIsRoot {
			if viper.GetBool("redirect-root") && !strings.HasPrefix(c.Request.URL.Path, "/favicon.ico") {
				c.Redirect(http.StatusFound, viper.GetString("redirect-root-location"))
				return
			}

			status := http.StatusNotFound
			c.AbortWithStatus(status)
			if viper.GetBool("debug") {
				log.Println("Aborting with status", status)
			}
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
			status := http.StatusUnauthorized
			c.AbortWithStatus(status)
			if viper.GetBool("debug") {
				log.Println("Aborting with status", status)
			}
			return
		}

		stripPath := viper.GetBool("strip-http-path")

		currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
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
			currentListener.SSHConnections.Range(func(key string, sshConn *utils.SSHConnection) bool {
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

		reqBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			log.Println("Error reading request body:", err)
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(reqBody))

		err = forward.ResponseModifier(ResponseModifier(state, hostname, reqBody, c, currentListener))(currentListener.Forward)
		if err != nil {
			log.Println("Unable to set response modifier:", err)
		}

		gin.WrapH(currentListener.Balancer)(c)
	})

	var acmeIssuer *certmagic.ACMEIssuer = nil

	// If HTTPS is enabled, setup certmagic to allow us to provision HTTPS certs on the fly.
	// You can use sish without a wildcard cert, but you really should. If you get a lot of clients
	// with many random subdomains, you'll burn through your Let's Encrypt quota. Be careful!
	if viper.GetBool("https") {
		certmagic.Default.Storage = &certmagic.FileStorage{
			Path: filepath.Join(viper.GetString("https-certificate-directory"), "certmagic"),
		}

		certManager := certmagic.NewDefault()

		acmeIssuer = certmagic.NewACMEIssuer(certManager, certmagic.DefaultACME)

		acmeIssuer.Agreed = viper.GetBool("https-ondemand-certificate-accept-terms")
		acmeIssuer.Email = viper.GetString("https-ondemand-certificate-email")

		certManager.Issuers = []certmagic.Issuer{acmeIssuer}

		certManager.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(name string) error {
				if !viper.GetBool("https-ondemand-certificate") {
					return fmt.Errorf("ondemand certificate retrieval is not enabled")
				}

				ok := false

				state.HTTPListeners.Range(func(key string, locationListener *utils.HTTPHolder) bool {
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

		tlsConfig := certManager.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		httpsServer := &http.Server{
			Addr:      viper.GetString("https-address"),
			TLSConfig: tlsConfig,
			Handler:   r,
		}

		go func() {
			// We'll replace this with a custom listener
			// That listener will then check the hostname of the request and choose the connection to send it to
			portListener, err := net.Listen("tcp", httpsServer.Addr)
			if err != nil {
				log.Fatalf("couldn't listen to %q: %q\n", httpsServer.Addr, err.Error())
			}

			pListener := portListener

			if viper.GetBool("proxy-protocol-listener") {
				hListener := &proxyproto.Listener{
					Listener: portListener,
				}

				utils.LoadProxyProtoConfig(hListener)
				pListener = hListener
			}

			httpsListener := pListener

			var tH *utils.TCPHolder

			if viper.GetBool("sni-proxy-https") {
				tH = &utils.TCPHolder{
					TCPHost:        httpsServer.Addr,
					SSHConnections: syncmap.New[string, *utils.SSHConnection](),
					Balancers:      syncmap.New[string, *roundrobin.RoundRobin](),
					SNIProxy:       true,
					NoHandle:       true,
				}

				balancer, err := roundrobin.New(nil)
				if err != nil {
					log.Fatal("Error initializing tcp balancer:", err)
				}

				err = balancer.UpsertServer(&url.URL{
					Host: base64.StdEncoding.EncodeToString([]byte("_sish_https_root")),
				})

				if err != nil {
					log.Fatal("Error upserting empty balancer:", err)
				}

				tH.Balancers.Store("", balancer)

				httpsListener = &proxyListener{
					Listener: pListener,
					Holder:   tH,
					State:    state,
				}
			}

			if tH != nil {
				tH.Listener = httpsListener

				state.Listeners.Store(httpsServer.Addr, httpsListener)
				state.TCPListeners.Store(httpsServer.Addr, tH)
			}

			defer httpsListener.Close()

			log.Fatal(httpsServer.ServeTLS(httpsListener, "", ""))
		}()
	}

	httpServer := &http.Server{
		Addr:    viper.GetString("http-address"),
		Handler: r,
	}
	if acmeIssuer != nil {
		httpServer.Handler = acmeIssuer.HTTPChallengeHandler(r)
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
