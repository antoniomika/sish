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

	"github.com/antoniomika/oxy/forward"
	"github.com/antoniomika/sish/utils"
	"github.com/caddyserver/certmagic"
	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
)

// Start initializes the HTTP service
func Start(state *utils.State) {
	releaseMode := gin.ReleaseMode
	if viper.GetBool("debug") {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)
	gin.DefaultWriter = state.LogWriter
	gin.ForceConsoleColor()

	r := gin.New()
	r.LoadHTMLGlob("templates/*")
	r.Use(func(c *gin.Context) {
		c.Set("startTime", time.Now())
		clientIPAddr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if state.IPFilter.Blocked(c.ClientIP()) || state.IPFilter.Blocked(clientIPAddr) || err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}, gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
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
				sshConnTmp, ok := proxyHolder.SSHConns.Load(param.Keys["proxySocket"])
				if ok {
					sshConn := sshConnTmp.(*utils.SSHConnection)
					sshConn.SendMessage(strings.TrimSpace(logLine), true)
				} else {
					proxyHolder.SSHConns.Range(func(key, val interface{}) bool {
						sshConn := val.(*utils.SSHConnection)
						sshConn.SendMessage(strings.TrimSpace(logLine), true)
						return true
					})
				}
			}
		}

		return logLine
	}), gin.Recovery(), func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/favicon.ico") {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		hostname := strings.Split(c.Request.Host, ":")[0]
		hostIsRoot := hostname == viper.GetString("domain")

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

	if viper.GetBool("https") {
		certManager := certmagic.NewDefault()

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

		err := certManager.CacheUnmanagedCertificatePEMFile(
			filepath.Join(viper.GetString("https-certificate-directory"), "fullchain.pem"),
			filepath.Join(viper.GetString("https-certificate-directory"), "privkey.pem"),
			[]string{},
		)

		if err != nil {
			log.Println("Error loading unmanaged certificates:", err)
		}

		s := &http.Server{
			Addr:      viper.GetString("https-address"),
			TLSConfig: certManager.TLSConfig(),
			Handler:   r,
		}

		go func() {
			log.Fatal(s.ListenAndServeTLS("", ""))
		}()
	}
	log.Fatal(r.Run(viper.GetString("http-address")))
}
