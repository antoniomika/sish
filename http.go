package main

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

	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"

	"github.com/gin-gonic/gin"
)

// ProxyHolder holds proxy and connection info
type ProxyHolder struct {
	ProxyHost string
	ProxyTo   string
	Scheme    string
	SSHConn   *SSHConnection
}

func startHTTPHandler(state *State) {
	releaseMode := gin.ReleaseMode
	if *debug {
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

		if *adminToken != "" && strings.Contains(param.Path, *adminToken) {
			param.Path = strings.Replace(param.Path, *adminToken, "[REDACTED]", 1)
		}

		if *serviceConsoleToken != "" && strings.Contains(param.Path, *serviceConsoleToken) {
			param.Path = strings.Replace(param.Path, *serviceConsoleToken, "[REDACTED]", 1)
		}

		logLine := fmt.Sprintf("%v | %s |%s %3d %s| %13v | %15s |%s %-7s %s %s\n%s",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			param.Request.Host,
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			param.Path,
			param.ErrorMessage,
		)

		if *logToClient {
			hostname := strings.Split(param.Request.Host, ":")[0]
			loc, ok := state.HTTPListeners.Load(hostname)
			if ok {
				proxyHolder := loc.(*ProxyHolder)
				sendMessage(proxyHolder.SSHConn, strings.TrimSpace(logLine), true)
			}
		}

		return logLine
	}), gin.Recovery(), func(c *gin.Context) {
		hostname := strings.Split(c.Request.Host, ":")[0]
		hostIsRoot := hostname == *rootDomain

		if (*adminEnabled || *serviceConsoleEnabled) && strings.HasPrefix(c.Request.URL.Path, "/_sish/") {
			state.Console.HandleRequest(hostname, hostIsRoot, c)
			return
		}

		if hostIsRoot && *redirectRoot {
			c.Redirect(http.StatusFound, *redirectRootLocation)
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

		proxyHolder := loc.(*ProxyHolder)

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
			InsecureSkipVerify: !*verifySSL,
		}

		if c.IsWebsocket() {
			scheme := "ws"
			if url.Scheme == "https" {
				scheme = "wss"
			}

			var checkOrigin func(r *http.Request) bool
			if !*verifyOrigin {
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

		if *adminEnabled || *serviceConsoleEnabled {
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

	if *httpsEnabled {
		go func() {
			log.Fatal(r.RunTLS(*httpsAddr, filepath.Join(*httpsPems, "fullchain.pem"), filepath.Join(*httpsPems, "privkey.pem")))
		}()
	}
	log.Fatal(r.Run(*httpAddr))
}
