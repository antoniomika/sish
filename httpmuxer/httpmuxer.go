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

	"github.com/antoniomika/go-proxyproto"
	"github.com/antoniomika/oxy/forward"
	"github.com/antoniomika/sish/utils"
	"github.com/caddyserver/certmagic"
	"github.com/spf13/viper"

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

		if viper.GetString("admin-console-token") != "" && strings.Contains(param.Path, viper.GetString("admin-console-token")) {
			param.Path = strings.Replace(param.Path, viper.GetString("admin-console-token"), "[REDACTED]", 1)
		}

		if viper.GetString("service-console-token") != "" && strings.Contains(param.Path, viper.GetString("service-console-token")) {
			param.Path = strings.Replace(param.Path, viper.GetString("service-console-token"), "[REDACTED]", 1)
		}

		logLine := fmt.Sprintf("%v | %s |%s %3d %s| %13v | %15s |%s %-7s %s %s\n%s",
			param.TimeStamp.Format(viper.GetString("time-format")),
			param.Request.Host,
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			param.Path,
			param.ErrorMessage,
		)

		if viper.GetBool("log-to-client") {
			hostname := strings.Split(param.Request.Host, ":")[0]
			loc, ok := state.HTTPListeners.Load(hostname)
			if ok {
				proxyHolder := loc.(*utils.HTTPHolder)
				sshConnTmp, ok := proxyHolder.SSHConnections.Load(param.Keys["proxySocket"])
				if ok {
					sshConn := sshConnTmp.(*utils.SSHConnection)
					sshConn.SendMessage(strings.TrimSpace(logLine), true)
				} else {
					proxyHolder.SSHConnections.Range(func(key, val interface{}) bool {
						sshConn := val.(*utils.SSHConnection)
						sshConn.SendMessage(strings.TrimSpace(logLine), true)
						return true
					})
				}
			}
		}

		return logLine
	}), gin.Recovery(), func(c *gin.Context) {
		hostname := strings.Split(c.Request.Host, ":")[0]
		hostIsRoot := hostname == viper.GetString("domain")

		// Return a 404 for the favicon.
		if hostIsRoot && strings.HasPrefix(c.Request.URL.Path, "/favicon.ico") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if (viper.GetBool("admin-console") || viper.GetBool("service-console")) && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest(hostname, hostIsRoot, c)
			return
		}

		if hostIsRoot && viper.GetBool("redirect-root") {
			c.Redirect(http.StatusFound, viper.GetString("redirect-root-location"))
			return
		}

		loc, ok := state.HTTPListeners.Load(hostname)
		if !ok {
			err := c.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", hostname))
			if err != nil {
				log.Println("Aborting with error", err)
			}
			return
		}

		reqBody, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			log.Println("Error reading request body:", err)
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

		proxyHolder := loc.(*utils.HTTPHolder)

		err = forward.ResponseModifier(ResponseModifier(state, hostname, reqBody, c))(proxyHolder.Forward)
		if err != nil {
			log.Println("Unable to set response modifier:", err)
		}

		gin.WrapH(proxyHolder.Balancer)(c)
	})

	// If HTTPS is enabled, setup certmagic to allow us to provision HTTPS certs on the fly.
	// You can use sish without a wildcard cert, but you really should. If you get a lot of clients
	// with many random subdomains, you'll burn through your Let's Encrypt quota. Be careful!
	if viper.GetBool("https") {
		certManager := certmagic.NewDefault()

		acmeManager := certmagic.NewACMEManager(certManager, certmagic.DefaultACME)

		acmeManager.Agreed = viper.GetBool("https-ondemand-certificate-accept-terms")
		acmeManager.Email = viper.GetString("https-ondemand-certificate-email")

		certManager.Issuer = acmeManager

		certManager.Storage = &certmagic.FileStorage{
			Path: filepath.Join(viper.GetString("https-certificate-directory"), "certmagic"),
		}

		certManager.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(name string) error {
				if !viper.GetBool("https-ondemand-certificate") {
					return fmt.Errorf("ondemand certificate retrieval is not enabled")
				}

				_, ok := state.HTTPListeners.Load(name)
				if !ok {
					return fmt.Errorf("cannot find connection for host: %s", name)
				}

				log.Println("Requesting certificate for host:", name)
				return nil
			},
		}

		certFiles, err := filepath.Glob(filepath.Join(viper.GetString("https-certificate-directory"), "*.crt"))
		if err != nil {
			log.Println("Error loading unmanaged certificates:", err)
		}

		for _, v := range certFiles {
			err := certManager.CacheUnmanagedCertificatePEMFile(v, fmt.Sprintf("%s.key", strings.TrimSuffix(v, ".crt")), []string{})
			if err != nil {
				log.Println("Error loading unmanaged certificate:", err)
			}
		}

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
