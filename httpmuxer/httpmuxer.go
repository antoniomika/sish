package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"
	"github.com/spf13/viper"

	"github.com/gin-gonic/gin"
)

// StartHTTPHandler initializes the HTTP service
func StartHTTPHandler(state *utils.State) {
	releaseMode := gin.ReleaseMode
	if viper.GetBool("debug") {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)

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

		if viper.GetBool("enable-log-to-client") {
			hostname := strings.Split(param.Request.Host, ":")[0]
			loc, ok := state.HTTPListeners.Load(hostname)
			if ok {
				proxyHolder := loc.(*utils.ProxyHolder)
				proxyHolder.SSHConn.SendMessage(strings.TrimSpace(logLine), true)
			}
		}

		return logLine
	}), gin.Recovery(), func(c *gin.Context) {
		hostname := strings.Split(c.Request.Host, ":")[0]
		hostIsRoot := hostname == viper.GetString("domain")

		if (viper.GetBool("enable-admin-console") || viper.GetBool("enable-service-console")) && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest(hostname, hostIsRoot, c)
			return
		}

		if hostIsRoot && viper.GetBool("enable-redirect-root") {
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

		requestedScheme := "http"

		if c.Request.TLS != nil {
			requestedScheme = "https"
		}

		c.Request.Header.Set("X-Forwarded-Proto", requestedScheme)

		proxyHolder := loc.(*utils.ProxyHolder)

		url := *c.Request.URL
		url.Host = "local"
		url.Path = ""
		url.RawQuery = ""
		url.Fragment = ""
		url.Scheme = proxyHolder.Scheme

		dialer := func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", proxyHolder.ProxyTo)
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: !viper.GetBool("verify-ssl"),
		}

		if c.IsWebsocket() {
			scheme := "ws"
			if url.Scheme == "https" {
				scheme = "wss"
			}

			var checkOrigin func(r *http.Request) bool
			if !viper.GetBool("verify-origin") {
				checkOrigin = func(r *http.Request) bool {
					return true
				}
			}

			url.Scheme = scheme
			wsProxy := websocketproxy.NewProxy(&url)
			wsProxy.Upgrader = &websocket.Upgrader{
				ReadBufferSize:  1024,
				WriteBufferSize: 1024,
				CheckOrigin:     checkOrigin,
			}
			wsProxy.Dialer = &websocket.Dialer{
				NetDial:         dialer,
				TLSClientConfig: tlsConfig,
			}
			gin.WrapH(wsProxy)(c)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(&url)
		proxy.Transport = &http.Transport{
			Dial:            dialer,
			TLSClientConfig: tlsConfig,
		}

		if viper.GetBool("enable-admin-console") || viper.GetBool("enable-service-console") {
			proxy.ModifyResponse = func(response *http.Response) error {
				resBody, err := ioutil.ReadAll(response.Body)
				if err != nil {
					log.Println("error reading response for webconsole:", err)
				}

				response.Body = ioutil.NopCloser(bytes.NewBuffer(resBody))

				startTime := c.GetTime("startTime")
				currentTime := time.Now()
				diffTime := currentTime.Sub(startTime)

				roundTime := 10 * time.Microsecond
				if diffTime > time.Second {
					roundTime = 10 * time.Millisecond
				}

				if response.Header.Get("Content-Encoding") == "gzip" {
					gzData := bytes.NewBuffer(resBody)
					gzReader, err := gzip.NewReader(gzData)
					if err != nil {
						log.Println("error reading gzip data:", err)
					}

					resBody, err = ioutil.ReadAll(gzReader)
					if err != nil {
						log.Println("error reading gzip data:", err)
					}
				}

				requestHeaders := c.Request.Header.Clone()
				requestHeaders.Add("Host", hostname)

				data, err := json.Marshal(map[string]interface{}{
					"startTime":       startTime,
					"startTimePretty": startTime.Format(viper.GetString("time-format")),
					"currentTime":     currentTime,
					"requestIP":       c.ClientIP(),
					"requestTime":     diffTime.Round(roundTime).String(),
					"requestMethod":   c.Request.Method,
					"requestUrl":      c.Request.URL,
					"requestHeaders":  requestHeaders,
					"requestBody":     base64.StdEncoding.EncodeToString(reqBody),
					"responseHeaders": response.Header,
					"responseCode":    response.StatusCode,
					"responseStatus":  response.Status,
					"responseBody":    base64.StdEncoding.EncodeToString(resBody),
				})

				if err != nil {
					log.Println("error marshaling json for webconsole:", err)
				}

				state.Console.BroadcastRoute(hostname, data)

				return nil
			}
		}

		gin.WrapH(proxy)(c)
	})

	if viper.GetBool("enable-https") {
		go func() {
			log.Fatal(r.RunTLS(viper.GetString("https-address"), filepath.Join(viper.GetString("certificate-directory"), "fullchain.pem"), filepath.Join(viper.GetString("certificate-directory"), "privkey.pem")))
		}()
	}
	log.Fatal(r.Run(viper.GetString("http-address")))
}
