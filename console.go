package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// WebClient represents a primitive web console client
type WebClient struct {
	Conn    *websocket.Conn
	Console *WebConsole
	Send    chan []byte
	Route   string
}

// WebConsole represents the data structure that stores web console client information
// Clients is a map[string][]*WebClient
type WebConsole struct {
	Clients     *sync.Map
	RouteTokens *sync.Map
	State       *State
}

// NewWebConsole set's up the WebConsole
func NewWebConsole() *WebConsole {
	return &WebConsole{
		Clients:     &sync.Map{},
		RouteTokens: &sync.Map{},
	}
}

// HandleRequest handles an incoming WS request
func (c *WebConsole) HandleRequest(hostname string, hostIsRoot bool, g *gin.Context) {
	userAuthed := false
	userIsAdmin := false
	if (*adminEnabled && *adminToken != "") && (g.Request.URL.Query().Get("x-authorization") == *adminToken || g.Request.Header.Get("x-authorization") == *adminToken) {
		userIsAdmin = true
		userAuthed = true
	}

	tokenInterface, ok := c.RouteTokens.Load(hostname)
	if ok {
		routeToken, ok := tokenInterface.(string)
		if *serviceConsoleEnabled && ok && (g.Request.URL.Query().Get("x-authorization") == routeToken || g.Request.Header.Get("x-authorization") == routeToken) {
			userAuthed = true
		}
	}

	if strings.HasPrefix(g.Request.URL.Path, "/_sish/console/ws") && userAuthed {
		c.HandleWebSocket(hostname, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/console") && userAuthed {
		c.HandleTemplate(hostname, hostIsRoot, userIsAdmin, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/") && userIsAdmin {
		c.HandleDisconnectClient(hostname, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/") && userIsAdmin {
		c.HandleDisconnectRoute(hostname, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/routes") && hostIsRoot && userIsAdmin {
		c.HandleRoutes(hostname, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/allroutes") && hostIsRoot && userIsAdmin {
		c.HandleAllRoutes(hostname, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/clients") && hostIsRoot && userIsAdmin {
		c.HandleClients(hostname, g)
		return
	}
}

// HandleTemplate handles rendering the console template
func (c *WebConsole) HandleTemplate(hostname string, hostIsRoot bool, userIsAdmin bool, g *gin.Context) {
	if hostIsRoot && userIsAdmin {
		g.HTML(http.StatusOK, "routes", nil)
		return
	}

	if c.RouteExists(hostname) {
		g.HTML(http.StatusOK, "console", nil)
		return
	}

	err := g.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", hostname))
	if err != nil {
		log.Println("Aborting with error", err)
	}
}

// HandleWebSocket handles the websocket route
func (c *WebConsole) HandleWebSocket(hostname string, g *gin.Context) {
	conn, err := upgrader.Upgrade(g.Writer, g.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}

	client := &WebClient{
		Conn:    conn,
		Console: c,
		Send:    make(chan []byte),
		Route:   hostname,
	}

	c.AddClient(hostname, client)

	go client.Handle()
}

// HandleDisconnectClient handles the disconnection request for a client
func (c *WebConsole) HandleDisconnectClient(hostname string, g *gin.Context) {
	client := strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/")

	c.State.SSHConnections.Range(func(key interface{}, val interface{}) bool {
		clientName := key.(*net.TCPAddr)

		if clientName.String() == client {
			holderConn := val.(*SSHConnection)
			holderConn.CleanUp(c.State)

			return false
		}

		return true
	})

	data := map[string]interface{}{
		"status": true,
	}

	g.JSON(http.StatusOK, data)
}

// HandleDisconnectRoute handles the disconnection request for a route
func (c *WebConsole) HandleDisconnectRoute(hostname string, g *gin.Context) {
	route := strings.Split(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/"), "/")
	routeType := route[0]
	routeName := route[1]

	var listenerAddr string

	switch routeType {
	case "tcpalias":
		c.State.TCPListeners.Range(func(key interface{}, val interface{}) bool {
			tcpAlias := key.(string)
			if routeName == tcpAlias {
				listenerAddr = val.(string)
			}

			return true
		})
	case "httplistener":
		c.State.HTTPListeners.Range(func(key interface{}, val interface{}) bool {
			httpListener := key.(string)
			if routeName == httpListener {
				listenerAddrTmp := val.(*ProxyHolder)
				listenerAddr = listenerAddrTmp.ProxyTo
			}

			return true
		})
	}

	if listenerAddr == "" {
		listenerAddr = routeName
	}

	c.State.Listeners.Range(func(key interface{}, val interface{}) bool {
		var tcpListener *net.TCPAddr
		unixListener, ok := key.(*net.UnixAddr)
		if !ok {
			tcpListener = key.(*net.TCPAddr)
		}

		var name string

		if unixListener != nil {
			name = unixListener.String()
		} else {
			name = tcpListener.String()
		}

		if listenerAddr == name {
			if unixListener != nil {
				actualUnixListener := val.(*net.UnixListener)
				actualUnixListener.Close()
			} else {
				actualTCPListener := val.(*net.TCPListener)
				actualTCPListener.Close()
			}
		}

		return true
	})

	data := map[string]interface{}{
		"status": true,
	}

	g.JSON(http.StatusOK, data)
}

// HandleRoutes handles returning available http routes to join
func (c *WebConsole) HandleRoutes(hostname string, g *gin.Context) {
	data := map[string]interface{}{
		"status": true,
	}

	routes := []string{}
	c.Clients.Range(func(key interface{}, val interface{}) bool {
		routeName := key.(string)
		routes = append(routes, routeName)

		return true
	})

	data["routes"] = routes

	g.JSON(http.StatusOK, data)
}

// HandleClients handles returning all connected clients
func (c *WebConsole) HandleClients(hostname string, g *gin.Context) {
	data := map[string]interface{}{
		"status": true,
	}

	clients := map[string]map[string]interface{}{}
	c.State.SSHConnections.Range(func(key interface{}, val interface{}) bool {
		clientName := key.(*net.TCPAddr)
		sshConn := val.(*SSHConnection)

		listeners := []string{}
		routeListeners := map[string]map[string]string{}

		sshConn.Listeners.Range(func(key interface{}, val interface{}) bool {
			var tcpListener *net.TCPAddr
			unixListener, ok := key.(*net.UnixAddr)
			if !ok {
				tcpListener = key.(*net.TCPAddr)
			}

			var name string

			if ok {
				name = unixListener.String()
			} else {
				name = tcpListener.String()
			}

			altName, ok := val.(string)
			if ok {
				name = altName
			}

			listeners = append(listeners, name)

			return true
		})

		tcpAliases := map[string]string{}
		c.State.TCPListeners.Range(func(key interface{}, val interface{}) bool {
			tcpAlias := key.(string)
			aliasAddress := val.(string)

			for _, v := range listeners {
				if v == aliasAddress {
					tcpAliases[tcpAlias] = aliasAddress
				}
			}

			return true
		})

		listenerParts := map[string]string{}
		c.State.Listeners.Range(func(key interface{}, val interface{}) bool {
			var tcpListener *net.TCPAddr
			unixListener, ok := key.(*net.UnixAddr)
			if !ok {
				tcpListener = key.(*net.TCPAddr)
			}

			var addr string
			if unixListener != nil {
				addr = unixListener.String()
			} else {
				addr = tcpListener.String()
			}

			for _, v := range listeners {
				if v == addr {
					listenerParts[addr] = addr
				}
			}

			return true
		})

		httpListeners := map[string]string{}
		c.State.HTTPListeners.Range(func(key interface{}, val interface{}) bool {
			httpListener := key.(string)
			aliasAddress := val.(*ProxyHolder)

			for _, v := range listeners {
				if v == aliasAddress.ProxyTo {
					httpListeners[httpListener] = aliasAddress.ProxyTo
				}
			}

			return true
		})

		routeListeners["tcpAliases"] = tcpAliases
		routeListeners["listeners"] = listenerParts
		routeListeners["httpListeners"] = httpListeners

		clients[clientName.String()] = map[string]interface{}{
			"remoteAddr":     sshConn.SSHConn.RemoteAddr().String(),
			"user":           sshConn.SSHConn.User(),
			"version":        string(sshConn.SSHConn.ClientVersion()),
			"session":        sshConn.SSHConn.SessionID(),
			"listeners":      listeners,
			"routeListeners": routeListeners,
		}

		return true
	})

	data["clients"] = clients

	g.JSON(http.StatusOK, data)
}

// HandleAllRoutes handles returning all connected routes (tunnels)
func (c *WebConsole) HandleAllRoutes(hostname string, g *gin.Context) {
	data := map[string]interface{}{
		"status": true,
	}

	tcpAliases := []string{}
	c.State.TCPListeners.Range(func(key interface{}, val interface{}) bool {
		tcpAlias := key.(string)
		tcpAliases = append(tcpAliases, tcpAlias)

		return true
	})

	listeners := []string{}
	c.State.Listeners.Range(func(key interface{}, val interface{}) bool {
		var tcpListener *net.TCPAddr
		unixListener, ok := key.(*net.UnixAddr)
		if !ok {
			tcpListener = key.(*net.TCPAddr)
		}

		if unixListener != nil {
			listeners = append(listeners, unixListener.String())
		} else {
			listeners = append(listeners, tcpListener.String())
		}

		return true
	})

	httpListeners := []string{}
	c.State.HTTPListeners.Range(func(key interface{}, val interface{}) bool {
		httpListener := key.(string)
		httpListeners = append(httpListeners, httpListener)

		return true
	})

	data["tcpAliases"] = tcpAliases
	data["listeners"] = listeners
	data["httpListeners"] = httpListeners

	g.JSON(http.StatusOK, data)
}

// RouteExists check if a route exists
func (c *WebConsole) RouteExists(route string) bool {
	_, ok := c.Clients.Load(route)
	return ok
}

// AddRoute adds a route to the console
func (c *WebConsole) AddRoute(route string, token string) {
	c.Clients.LoadOrStore(route, []*WebClient{})
	c.RouteTokens.Store(route, token)
}

// RemoveRoute adds a route to the console
func (c *WebConsole) RemoveRoute(route string) {
	data, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	clients, ok := data.([]*WebClient)

	if !ok {
		return
	}

	for _, client := range clients {
		client.Conn.Close()
	}

	c.Clients.Delete(route)
	c.RouteTokens.Delete(route)
}

// AddClient adds a client to the console
func (c *WebConsole) AddClient(route string, w *WebClient) {
	data, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	clients, ok := data.([]*WebClient)

	if !ok {
		return
	}

	clients = append(clients, w)

	c.Clients.Store(route, clients)
}

// RemoveClient removes a client from the console
func (c *WebConsole) RemoveClient(route string, w *WebClient) {
	data, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	clients, ok := data.([]*WebClient)

	if !ok {
		return
	}

	found := false
	toRemove := 0
	for i, client := range clients {
		if client == w {
			found = true
			toRemove = i
			break
		}
	}

	if found {
		clients[toRemove] = clients[len(clients)-1]
		c.Clients.Store(route, clients[:len(clients)-1])
	}
}

// BroadcastRoute sends a message to all clients on a route
func (c *WebConsole) BroadcastRoute(route string, message []byte) {
	data, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	clients, ok := data.([]*WebClient)

	if !ok {
		return
	}

	for _, client := range clients {
		client.Send <- message
	}
}

// Handle is the only place socket reads and writes happen
func (c *WebClient) Handle() {
	defer func() {
		c.Conn.Close()
		c.Console.RemoveClient(c.Route, c)
	}()

	for message := range c.Send {
		w, err := c.Conn.NextWriter(websocket.TextMessage)
		if err != nil {
			return
		}

		_, err = w.Write(message)
		if err != nil {
			return
		}

		if err := w.Close(); err != nil {
			return
		}
	}

	err := c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
	if err != nil {
		log.Println("error writing to websocket:", err)
	}
}
