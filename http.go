package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
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
	r := gin.Default()
	r.GET("/*proxy", func(c *gin.Context) {
		hostname := strings.Split(c.Request.Host, ":")[0]

		loc, ok := state.HTTPListeners.Load(hostname)
		if !ok {
			c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("cannot find connection for host: %s", hostname))
			return
		}

		proxyHolder := loc.(*ProxyHolder)

		url := c.Request.URL
		url.Host = proxyHolder.ProxyTo
		url.Scheme = proxyHolder.Scheme

		if websocket.IsWebSocketUpgrade(c.Request) {
			scheme := "ws"
			if url.Scheme == "https" {
				scheme = "wss"
			}

			url.Scheme = scheme
			wsProxy := websocketproxy.NewProxy(url)
			gin.WrapH(wsProxy)(c)
		} else {
			proxy := httputil.NewSingleHostReverseProxy(url)
			gin.WrapH(proxy)(c)
		}
	})
	r.Run(*httpAddr)
}
