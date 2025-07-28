package utils

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/antoniomika/syncmap"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/roundrobin"
)

// upgrader is the default WS upgrader that we use for webconsole clients.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WebClient represents a primitive web console client. It maintains
// references that allow us to communicate and track a client connection.
type WebClient struct {
	Conn    *websocket.Conn
	Console *WebConsole
	Send    chan []byte
	Route   string
}

// WebConsole represents the data structure that stores web console client information.
type WebConsole struct {
	Clients     *syncmap.Map[string, []*WebClient]
	RouteTokens *syncmap.Map[string, string]
	State       *State
}

// NewWebConsole sets up the WebConsole.
func NewWebConsole() *WebConsole {
	return &WebConsole{
		Clients:     syncmap.New[string, []*WebClient](),
		RouteTokens: syncmap.New[string, string](),
	}
}

// HandleRequest handles an incoming web request, handles auth, and then routes it.
func (c *WebConsole) HandleRequest(proxyUrl string, hostIsRoot bool, g *gin.Context) {
	userAuthed := false
	userIsAdmin := false
	if (viper.GetBool("admin-console") && viper.GetString("admin-console-token") != "") && (g.Request.URL.Query().Get("x-authorization") == viper.GetString("admin-console-token") || g.Request.Header.Get("x-authorization") == viper.GetString("admin-console-token")) {
		userIsAdmin = true
		userAuthed = true
	}

	tokenInterface, ok := c.RouteTokens.Load(proxyUrl)
	if ok {
		routeToken := tokenInterface
		if routeToken == "" {
			ok = false
		}

		if viper.GetBool("service-console") && ok && (g.Request.URL.Query().Get("x-authorization") == routeToken || g.Request.Header.Get("x-authorization") == routeToken) {
			userAuthed = true
		}
	}

	if userAuthed && hostIsRoot && userIsAdmin {
		if strings.HasPrefix(g.Request.URL.Path, "/_sish/console/ws") {
			c.HandleWebSocket(proxyUrl, g)
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/console") {
			c.HandleTemplate(proxyUrl, hostIsRoot, userIsAdmin, g)
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/") {
			c.HandleDisconnectClient(proxyUrl, g)
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/") {
			c.HandleDisconnectRoute(proxyUrl, g)
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/retry/") {
			client := strings.Split(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/retry/"), "/")
			c.State.RetryTimer.Reset(client[0])
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/filter/") {
			// /_sish/api/filter/[block|allow]/[ip|code|user]/[realIpAddress|realCode|realUser]
			path := strings.Split(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/filter/"), "/")
			if len(path) != 3 || (path[0] != "block" && path[0] != "allow") || (path[1] != "ip" && path[1] != "code" && path[1] != "user") {
				g.String(http.StatusBadRequest, "wrong path")
				return
			}
			if path[0] == "block" {
				c.blockEntity(path[1], path[2], g)
			} else if path[0] == "allow" {
				c.allowEntity(path[1], path[2], g)
			}
			return
		} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/clients") {
			c.HandleClients(proxyUrl, g)
			return
		}
	}
}

// HandleTemplate handles rendering the console templates.
func (c *WebConsole) HandleTemplate(proxyUrl string, hostIsRoot bool, userIsAdmin bool, g *gin.Context) {
	if hostIsRoot && userIsAdmin {
		g.HTML(http.StatusOK, "routes", nil)
		return
	}

	if c.RouteExists(proxyUrl) {
		g.HTML(http.StatusOK, "console", nil)
		return
	}

	err := g.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", proxyUrl))
	if err != nil {
		log.Println("Aborting with error", err)
	}
}

// HandleWebSocket handles the websocket route.
func (c *WebConsole) HandleWebSocket(proxyUrl string, g *gin.Context) {
	conn, err := upgrader.Upgrade(g.Writer, g.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}

	client := &WebClient{
		Conn:    conn,
		Console: c,
		Send:    make(chan []byte),
		Route:   proxyUrl,
	}

	c.AddClient(proxyUrl, client)

	go client.Handle()
}

// HandleDisconnectClient handles the disconnection request for a SSH client.
func (c *WebConsole) HandleDisconnectClient(proxyUrl string, g *gin.Context) {
	client := strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/")

	disconnectClient(c, client)

	data := map[string]any{
		"status": true,
	}

	g.JSON(http.StatusOK, data)
}

func disconnectClient(c *WebConsole, client string) {
	c.State.SSHConnections.Range(func(clientName string, holderConn *SSHConnection) bool {
		if clientName == client {
			holderConn.CleanUp(c.State)

			return false
		}

		return true
	})
}

// HandleDisconnectRoute handles the disconnection request for a forwarded route.
func (c *WebConsole) HandleDisconnectRoute(proxyUrl string, g *gin.Context) {
	route := strings.Split(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/"), "/")
	encRouteName := route[1]

	decRouteName, err := base64.StdEncoding.DecodeString(encRouteName)
	if err != nil {
		log.Println("Error decoding route name:", err)
		err := g.AbortWithError(http.StatusInternalServerError, err)

		if err != nil {
			log.Println("Error aborting with error:", err)
		}
		return
	}

	routeName := string(decRouteName)

	listenerTmp, ok := c.State.Listeners.Load(routeName)
	if ok {
		listener, ok := listenerTmp.(*ListenerHolder)

		if ok {
			err := listener.Close()
			if err != nil {
				log.Println("Error closing listener:", err)
			}
		}
	}

	data := map[string]any{
		"status": true,
	}

	g.JSON(http.StatusOK, data)
}

// HandleClients handles returning all connected SSH clients. This will
// also go through all of the forwarded connections for the SSH client and
// return them.
func (c *WebConsole) HandleClients(proxyUrl string, g *gin.Context) {
	data := map[string]any{
		"status": true,
	}

	clients := map[string]map[string]any{}
	c.State.SSHConnections.Range(func(clientName string, sshConn *SSHConnection) bool {
		listeners := []string{}
		routeListeners := map[string]map[string]any{}

		sshConn.Listeners.Range(func(name string, val net.Listener) bool {
			if name != "" {
				listeners = append(listeners, name)
			}

			return true
		})

		tcpAliases := map[string]any{}
		c.State.AliasListeners.Range(func(tcpAlias string, aliasHolder *AliasHolder) bool {
			for _, v := range listeners {
				for _, server := range aliasHolder.Balancer.Servers() {
					serverAddr, err := base64.StdEncoding.DecodeString(server.Host)
					if err != nil {
						log.Println("Error decoding server host:", err)
						continue
					}

					aliasAddress := string(serverAddr)

					if v == aliasAddress {
						tcpAliases[tcpAlias] = aliasAddress
					}
				}
			}

			return true
		})

		listenerParts := map[string]any{}
		c.State.TCPListeners.Range(func(tcpAlias string, aliasHolder *TCPHolder) bool {
			for _, v := range listeners {
				aliasHolder.Balancers.Range(func(ikey string, balancer *roundrobin.RoundRobin) bool {
					newAlias := tcpAlias
					if aliasHolder.SNIProxy {
						newAlias = fmt.Sprintf("%s-%s", tcpAlias, ikey)
					}

					for _, server := range balancer.Servers() {
						serverAddr, err := base64.StdEncoding.DecodeString(server.Host)
						if err != nil {
							log.Println("Error decoding server host:", err)
							continue
						}

						aliasAddress := string(serverAddr)

						if v == aliasAddress {
							listenerParts[newAlias] = aliasAddress
						}
					}

					return true
				})
			}

			return true
		})

		httpListeners := map[string]any{}
		c.State.HTTPListeners.Range(func(key string, httpHolder *HTTPHolder) bool {
			listenerHandlers := []string{}
			httpHolder.SSHConnections.Range(func(httpAddr string, val *SSHConnection) bool {
				for _, v := range listeners {
					if v == httpAddr {
						listenerHandlers = append(listenerHandlers, httpAddr)
					}
				}
				return true
			})

			if len(listenerHandlers) > 0 {
				var userPass string
				password, _ := httpHolder.HTTPUrl.User.Password()
				if httpHolder.HTTPUrl.User.Username() != "" || password != "" {
					userPass = fmt.Sprintf("%s:%s@", httpHolder.HTTPUrl.User.Username(), password)
				}

				httpListeners[fmt.Sprintf("%s%s%s", userPass, httpHolder.HTTPUrl.Hostname(), httpHolder.HTTPUrl.Path)] = listenerHandlers
			}

			return true
		})

		routeListeners["tcpAliases"] = tcpAliases
		routeListeners["listeners"] = listenerParts
		routeListeners["httpListeners"] = httpListeners

		pubKey := ""
		pubKeyFingerprint := ""
		if sshConn.SSHConn.Permissions != nil {
			if _, ok := sshConn.SSHConn.Permissions.Extensions["pubKey"]; ok {
				pubKey = sshConn.SSHConn.Permissions.Extensions["pubKey"]
				pubKeyFingerprint = sshConn.SSHConn.Permissions.Extensions["pubKeyFingerprint"]
			}
		}

		clients[clientName] = map[string]any{
			"remoteAddr":        sshConn.SSHConn.RemoteAddr().String(),
			"user":              sshConn.SSHConn.User(),
			"version":           string(sshConn.SSHConn.ClientVersion()),
			"session":           sshConn.SSHConn.SessionID(),
			"pubKey":            pubKey,
			"pubKeyFingerprint": pubKeyFingerprint,
			"listeners":         listeners,
			"routeListeners":    routeListeners,
			"created":           sshConn.Created.UnixMilli(),
		}

		return true
	})

	data["clients"] = clients

	retry := map[string]any{}
	for k, v := range c.State.RetryTimer {
		retry[k] = map[string]any{
			"counter":   v.counter,
			"timestamp": v.timestamp,
			"blocked":   v.counter >= MAX_RETRY,
			"unBlockIn": v.timestamp + v.counter - time.Now().Unix(),
		}
	}
	data["retry"] = retry

	data["filter"] = map[string]any{
		"ips":   GetUnexportedField(reflect.ValueOf(c.State.IPFilter).Elem().FieldByName("ips")),
		"codes": GetUnexportedField(reflect.ValueOf(c.State.IPFilter).Elem().FieldByName("codes")),
		"users": c.State.UserFilter,
	}

	history := map[string]*HistoryHolder{}
	c.State.History.Range(func(key string, val *HistoryHolder) bool {
		history[key] = val
		return true
	})
	data["history"] = history

	g.JSON(http.StatusOK, data)
}

func GetUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

// RouteToken returns the route token for a specific route.
func (c *WebConsole) RouteToken(route string) (string, bool) {
	token, ok := c.RouteTokens.Load(route)
	routeToken := ""

	if ok {
		routeToken = token
	}

	return routeToken, ok
}

// RouteExists check if a route token exists.
func (c *WebConsole) RouteExists(route string) bool {
	_, ok := c.RouteToken(route)
	return ok
}

// AddRoute adds a route token to the console.
func (c *WebConsole) AddRoute(route string, token string) {
	c.Clients.LoadOrStore(route, []*WebClient{})
	c.RouteTokens.Store(route, token)
}

// RemoveRoute removes a route token from the console.
func (c *WebConsole) RemoveRoute(route string) {
	clients, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	for _, client := range clients {
		err := client.Conn.Close()
		if err != nil {
			log.Println("Error closing websocket connection:", err)
		}
	}

	c.Clients.Delete(route)
	c.RouteTokens.Delete(route)
}

// AddClient adds a client to the console route.
func (c *WebConsole) AddClient(route string, w *WebClient) {
	clients, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	clients = append(clients, w)

	c.Clients.Store(route, clients)
}

// RemoveClient removes a client from the console route.
func (c *WebConsole) RemoveClient(route string, w *WebClient) {
	clients, ok := c.Clients.Load(route)

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

// BroadcastRoute sends a message to all clients on a route.
func (c *WebConsole) BroadcastRoute(route string, message []byte) {
	clients, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	for _, client := range clients {
		client.Send <- message
	}
}

func (c *WebConsole) blockEntity(key string, value string, g *gin.Context) {
	switch {
	case key == "ip":
		if value != "127.0.0.1" && value != "::1" && !c.State.IPFilter.Blocked(value) {
			log.Println("Block ip address:", value)
			g.String(http.StatusOK, fmt.Sprint(c.State.IPFilter.BlockIP(value)))
			return
		}
		g.String(http.StatusBadRequest, "false")
	case key == "code":
		log.Println("Block country code:", value)
		c.State.IPFilter.BlockCountry(value)
		g.String(http.StatusOK, "true")
	case key == "user":
		c.State.UserFilter[value] = 0
		disconnectClient(c, value)
		g.String(http.StatusOK, "true")
	}
}

func (c *WebConsole) allowEntity(key string, value string, g *gin.Context) {
	switch {
	case key == "ip":
		if c.State.IPFilter.Blocked(value) {
			log.Println("Allow ip address:", value)
			g.String(http.StatusOK, fmt.Sprint(c.State.IPFilter.AllowIP(value)))
			return
		}
		g.String(http.StatusBadRequest, "false")
	case key == "code":
		log.Println("Allow country code:", value)
		g.String(http.StatusOK, "true")
	case key == "user":
		delete(c.State.UserFilter, value)
		g.String(http.StatusOK, "true")
	}
}

// Handle is the only place socket reads and writes happen.
func (c *WebClient) Handle() {
	defer func() {
		err := c.Conn.Close()
		if err != nil {
			log.Println("Error closing websocket connection:", err)
		}
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
		log.Println("Error writing to websocket:", err)
	}
}
