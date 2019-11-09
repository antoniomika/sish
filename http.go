package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"

	"github.com/gin-gonic/gin"
)

// ProxyHolder holds proxy and connection info
type ProxyHolder struct {
	ProxyHost string
	ProxyTo   string
	Scheme    string
}

func startHTTPHandler(state *State) {
	releaseMode := gin.ReleaseMode
	if *debug {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		clientIPAddr, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if state.IPFilter.Blocked(c.ClientIP()) || state.IPFilter.Blocked(clientIPAddr) || err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}, gin.Logger(), gin.Recovery(), func(c *gin.Context) {
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
