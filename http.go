package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path/filepath"

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
	}, gin.Logger(), gin.Recovery())
	r.GET("/*proxy", func(c *gin.Context) {
		hostname, _, err := net.SplitHostPort(c.Request.Host)

		if err != nil || (hostname == *rootDomain && *redirectRoot) {
			c.Redirect(http.StatusFound, *redirectRootLocation)
			return
		}

		loc, ok := state.HTTPListeners.Load(hostname)
		if !ok {
			c.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", hostname))
			return
		}

		proxyHolder := loc.(*ProxyHolder)

		url := c.Request.URL
		url.Host = "local"
		url.Scheme = proxyHolder.Scheme

		dialer := func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", proxyHolder.ProxyTo)
		}

		if websocket.IsWebSocketUpgrade(c.Request) {
			scheme := "ws"
			if url.Scheme == "https" {
				scheme = "wss"
			}

			url.Scheme = scheme
			wsProxy := websocketproxy.NewProxy(url)
			wsProxy.Dialer = &websocket.Dialer{
				NetDial: dialer,
			}
			gin.WrapH(wsProxy)(c)
		} else {
			proxy := httputil.NewSingleHostReverseProxy(url)
			proxy.Transport = &http.Transport{
				Dial: dialer,
			}
			gin.WrapH(proxy)(c)
		}
	})

	if *httpsEnabled {
		go func() {
			log.Fatal(r.RunTLS(*httpsAddr, filepath.Join(*httpsPems, "fullchain.pem"), filepath.Join(*httpsPems, "privkey.pem")))
		}()
	}
	log.Fatal(r.Run(*httpAddr))
}
