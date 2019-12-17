package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"
	"github.com/logrusorgru/aurora"
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
	r.Use(func(c *gin.Context) {
		clientIPAddr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if state.IPFilter.Blocked(c.ClientIP()) || state.IPFilter.Blocked(clientIPAddr) || err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Return if the hostname is an IP
		hostname := strings.Split(c.Request.Host, ":")[0]
		hostnameIsIp := net.ParseIP(hostname)
		if hostnameIsIp != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		c.Next()
	}, gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		if param.Latency > time.Minute {
			// Truncate in a golang < 1.8 safe way
			param.Latency = param.Latency - param.Latency%time.Second
		}

		// Client log
		if *logToClient {
			hostname := strings.Split(param.Request.Host, ":")[0]
			loc, ok := state.HTTPListeners.Load(hostname)
			if ok {
				proxyHolder := loc.(*ProxyHolder)
				sendMessage(proxyHolder.SSHConn, strings.TrimSpace(formatLog(clientLogFormatParts, &param)), true)
			}
		}

		// Server log line
		return formatLog(serverLogFormatParts, &param) + "\n"
	}), gin.Recovery(), func(c *gin.Context) {
		hostname := strings.Split(c.Request.Host, ":")[0]

		if hostname == *rootDomain && *redirectRoot {
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
		gin.WrapH(proxy)(c)
	})

	if *httpsEnabled {
		go func() {
			log.Fatal(r.RunTLS(*httpsAddr, filepath.Join(*httpsPems, "fullchain.pem"), filepath.Join(*httpsPems, "privkey.pem")))
		}()
	}
	log.Fatal(r.Run(*httpAddr))
}

// Round duration to N decimal points. Original source here: https://play.golang.org/p/WjfKwhhjL5
func RoundN(d time.Duration, n int) time.Duration {
	if n < 1 {
		return d
	}
	if d >= time.Hour {
		k := digits(d / time.Hour)
		if k >= n {
			return d.Round(time.Hour*time.Duration(math.Pow10(k-n)))
		}
		n -= k
		k = digits(d % time.Hour / time.Minute)
		if k >= n {
			return d.Round(time.Minute*time.Duration(math.Pow10(k-n)))
		}
		return d.Round(time.Duration(float64(100*time.Second)*math.Pow10(k-n)))
	}
	if d >= time.Minute {
		k := digits(d / time.Minute)
		if k >= n {
			return d.Round(time.Minute*time.Duration(math.Pow10(k-n)))
		}
		return d.Round(time.Duration(float64(100*time.Second)*math.Pow10(k-n)))
	}
	if k := digits(d); k > n {
		return d.Round(time.Duration(math.Pow10(k-n)))
	}
	return d
}

func digits(d time.Duration) int {
	if d < 0 {
		d = -d
	}
	i := 1
	for d > 9 {
		d /= 10
		i++
	}
	return i
}

func formatLog(logFormatParts []string, param *gin.LogFormatterParams) string {
	statusFormatted := fmt.Sprintf("%3d", param.StatusCode)

	if param.IsOutputColor() {
		switch {
		case param.StatusCode >= http.StatusOK && param.StatusCode < http.StatusMultipleChoices:
			statusFormatted = aurora.Sprintf(aurora.Green("%3d"), param.StatusCode)
		case param.StatusCode >= http.StatusMultipleChoices && param.StatusCode < http.StatusBadRequest:
			statusFormatted = aurora.Sprintf(aurora.Yellow("%3d"), param.StatusCode)
		case param.StatusCode >= http.StatusBadRequest && param.StatusCode < http.StatusInternalServerError:
			statusFormatted = aurora.Sprintf(aurora.Red("%3d"), param.StatusCode)
		default:
			statusFormatted = aurora.Sprintf(aurora.Red("%3d"), param.StatusCode)
		}
	}

	logLine := ""
	for _, logPart := range logFormatParts {
		switch logPart {
		case "{timestamp}":
			logLine += fmt.Sprintf("%v", param.TimeStamp.Format(*logTimestampFormat))
		case "{host}":
			logLine += param.Request.Host
		case "{status}":
			logLine += statusFormatted
		case "{latency}":
			logLine += RoundN(param.Latency, 4).String()
		case "{latencyp}":
			logLine += fmt.Sprintf("% 8s", RoundN(param.Latency, 4))
		case "{clientip}":
			logLine += param.ClientIP
		case "{clientipp}":
			logLine += fmt.Sprintf("%15s", param.ClientIP)
		case "{method}":
			logLine += param.Method
		case "{methodp}":
			logLine += fmt.Sprintf("%-4s", param.Method)
		case "{path}":
			logLine += param.Path
		case "{error}":
			logLine += param.ErrorMessage
		case "{newline}":
			logLine += "\n"
		default:
			logLine += logPart
		}
	}

	return logLine
}
