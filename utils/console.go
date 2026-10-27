package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniomika/sish/assets"
	"github.com/antoniomika/syncmap"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
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
	Done    chan struct{}
	Route   string

	dropped atomic.Int64
}

// clientQueue is how many live messages can wait for a slow page before new ones are dropped.
const clientQueue = 512

// consoleRecord is a request kept for consoles that connect later, with the WebSocket events that followed it.
type consoleRecord struct {
	id      uint64
	message []byte
	events  [][]byte
}

// WebConsole represents the data structure that stores web console client information.
type WebConsole struct {
	Clients     *syncmap.Map[string, []*WebClient]
	RouteTokens *syncmap.Map[string, string]
	State       *State

	requestID   atomic.Uint64
	history     map[string][]*consoleRecord
	historyLock sync.Mutex
}

// NewWebConsole sets up the WebConsole.
func NewWebConsole() *WebConsole {
	c := &WebConsole{
		Clients:     syncmap.New[string, []*WebClient](),
		RouteTokens: syncmap.New[string, string](),
		history:     map[string][]*consoleRecord{},
	}

	// Ids keep increasing across restarts so a reconnecting page doesn't drop new requests as already seen.
	c.requestID.Store(uint64(time.Now().UnixMicro()))

	return c
}

// HandleRequest handles an incoming web request, handles auth, and then routes it.
func (c *WebConsole) HandleRequest(proxyUrl string, hostIsRoot bool, g *gin.Context) {
	if strings.HasPrefix(g.Request.URL.Path, "/_sish/assets/") {
		HandleAsset(g)
		return
	}

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

	if strings.HasPrefix(g.Request.URL.Path, "/_sish/console/ws") && userAuthed {
		c.HandleWebSocket(proxyUrl, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/console") && userAuthed {
		c.HandleTemplate(proxyUrl, hostIsRoot, userIsAdmin, g)
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/") && userIsAdmin {
		if requirePost(g) {
			c.HandleDisconnectClient(proxyUrl, g)
		}
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/") && userIsAdmin {
		if requirePost(g) {
			c.HandleDisconnectRoute(proxyUrl, g)
		}
		return
	} else if strings.HasPrefix(g.Request.URL.Path, "/_sish/api/clients") && hostIsRoot && userIsAdmin {
		c.HandleClients(proxyUrl, g)
		return
	}
}

// requirePost rejects requests that would change state unless they are POSTs.
func requirePost(g *gin.Context) bool {
	if g.Request.Method == http.MethodPost {
		return true
	}

	g.Header("Allow", http.MethodPost)
	g.AbortWithStatus(http.StatusMethodNotAllowed)
	return false
}

// HandleAsset serves the shared stylesheets and icons. They hold nothing private, so they don't need a token.
func HandleAsset(g *gin.Context) {
	name := strings.TrimPrefix(g.Request.URL.Path, "/_sish/assets/")
	if name == "" || strings.HasSuffix(name, "/") {
		g.AbortWithStatus(http.StatusNotFound)
		return
	}

	g.FileFromFS(name, http.FS(assets.FS))
}

// HandleTemplate handles rendering the console templates.
func (c *WebConsole) HandleTemplate(proxyUrl string, hostIsRoot bool, userIsAdmin bool, g *gin.Context) {
	// Consoles for path routes are served under the route's path, so links to assets need that prefix.
	base := g.GetString("originalPath")
	if i := strings.Index(base, "/_sish/"); i >= 0 {
		base = base[:i]
	} else {
		base = ""
	}

	if hostIsRoot && userIsAdmin {
		g.HTML(http.StatusOK, "routes", gin.H{"Title": "Admin", "Base": base})
		return
	}

	if c.RouteExists(proxyUrl) {
		g.HTML(http.StatusOK, "console", gin.H{"Title": "Requests", "Base": base})
		return
	}

	err := g.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", proxyUrl))
	if err != nil {
		slog.Error(
			"aborting with error",
			"error", err,
		)
	}
}

// HandleWebSocket handles the websocket route.
func (c *WebConsole) HandleWebSocket(proxyUrl string, g *gin.Context) {
	// The upgrade hijacks the connection past gin's writer, which would
	// otherwise log the 404 gin starts unrouted requests with. A failed
	// upgrade writes its own status over this one.
	g.Status(http.StatusSwitchingProtocols)

	conn, err := upgrader.Upgrade(g.Writer, g.Request, nil)
	if err != nil {
		slog.Error(
			"error handling websockets",
			"error", err,
		)
		return
	}

	client := &WebClient{
		Conn:    conn,
		Console: c,
		Send:    make(chan []byte, clientQueue),
		Done:    make(chan struct{}),
		Route:   proxyUrl,
	}

	c.AddClient(proxyUrl, client)

	go client.Handle()

	// History is one batch so it can't fill the queue that live messages use.
	// It can interleave with live messages, so the page orders requests by id and events by seq.
	if history := c.History(proxyUrl); len(history) > 0 {
		batch := append([]byte("["), bytes.Join(history, []byte(","))...)
		batch = append(batch, ']')

		go client.send(batch)
	}
}

// HandleDisconnectClient handles the disconnection request for a SSH client.
func (c *WebConsole) HandleDisconnectClient(proxyUrl string, g *gin.Context) {
	client := strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectclient/")

	c.State.SSHConnections.Range(func(clientName string, holderConn *SSHConnection) bool {
		if clientName == client {
			holderConn.CleanUp(c.State)

			return false
		}

		return true
	})

	data := map[string]any{
		"status": true,
	}

	g.JSON(http.StatusOK, data)
}

// HandleDisconnectRoute handles the disconnection request for a forwarded route.
func (c *WebConsole) HandleDisconnectRoute(proxyUrl string, g *gin.Context) {
	route := strings.Split(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/"), "/")
	encRouteName := route[1]

	decRouteName, err := base64.StdEncoding.DecodeString(encRouteName)
	if err != nil {
		slog.Error(
			"error decoding route name",
			"error", err,
		)

		err := g.AbortWithError(http.StatusInternalServerError, err)
		if err != nil {
			slog.Error(
				"aborting with error",
				"error", err,
			)
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
				slog.Error(
					"error closing listener",
					"error", err,
				)
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
						slog.Error(
							"error decoding server host",
							"error", err,
						)
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
							slog.Error(
								"error decoding server host",
								"error", err,
							)
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
			"user":              sshConn.User(),
			"version":           string(sshConn.SSHConn.ClientVersion()),
			"session":           sshConn.SSHConn.SessionID(),
			"pubKey":            pubKey,
			"pubKeyFingerprint": pubKeyFingerprint,
			"connectedAt":       sshConn.ConnectedAt,
			"listeners":         listeners,
			"routeListeners":    routeListeners,
		}

		return true
	})

	data["clients"] = clients

	g.JSON(http.StatusOK, data)
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
			slog.Error(
				"error closing websocket connection",
				"error", err,
			)
		}
	}

	c.Clients.Delete(route)
	c.RouteTokens.Delete(route)

	c.historyLock.Lock()
	delete(c.history, route)
	c.historyLock.Unlock()
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

// BroadcastRoute records a request made to a route and sends it to all of the route's clients.
// It returns the request's id, or 0 if the route has no console.
func (c *WebConsole) BroadcastRoute(route string, data map[string]any) uint64 {
	clients, ok := c.Clients.Load(route)

	if !ok {
		return 0
	}

	id := c.requestID.Add(1)
	data["id"] = id

	message, err := json.Marshal(data)
	if err != nil {
		slog.Error(
			"unable to marshal console data",
			"error", err,
		)
		return 0
	}

	c.addHistory(route, id, message)

	for _, client := range clients {
		client.queue(message)
	}

	return id
}

// BroadcastEvent sends an event that belongs to an earlier request, such as a WebSocket message, to the route's clients.
func (c *WebConsole) BroadcastEvent(route string, requestID uint64, data map[string]any) {
	clients, ok := c.Clients.Load(route)

	if !ok {
		return
	}

	data["requestId"] = requestID

	message, err := json.Marshal(data)
	if err != nil {
		slog.Error(
			"unable to marshal console data",
			"error", err,
		)
		return
	}

	c.addEvent(route, requestID, message)

	for _, client := range clients {
		client.queue(message)
	}
}

// addHistory keeps the most recent requests for a route, up to service-console-history.
func (c *WebConsole) addHistory(route string, id uint64, message []byte) {
	limit := viper.GetInt("service-console-history")
	if limit <= 0 {
		return
	}

	c.historyLock.Lock()
	defer c.historyLock.Unlock()

	if !c.RouteExists(route) {
		return
	}

	history := c.history[route]
	if len(history) >= limit {
		history = append(history[:0], history[len(history)-limit+1:]...)
	}

	c.history[route] = append(history, &consoleRecord{id: id, message: message})
}

// addEvent keeps an event with its request, up to service-console-websocket-messages per request.
func (c *WebConsole) addEvent(route string, requestID uint64, message []byte) {
	limit := viper.GetInt("service-console-websocket-messages")
	if limit <= 0 {
		return
	}

	c.historyLock.Lock()
	defer c.historyLock.Unlock()

	history := c.history[route]
	for i := len(history) - 1; i >= 0; i-- {
		record := history[i]
		if record.id != requestID {
			continue
		}

		if len(record.events) >= limit {
			record.events = append(record.events[:0], record.events[len(record.events)-limit+1:]...)
		}

		record.events = append(record.events, message)
		return
	}
}

// History returns the recorded requests for a route, oldest first, each followed by its events.
func (c *WebConsole) History(route string) [][]byte {
	c.historyLock.Lock()
	defer c.historyLock.Unlock()

	var messages [][]byte
	for _, record := range c.history[route] {
		messages = append(messages, record.message)
		messages = append(messages, record.events...)
	}

	return messages
}

// send passes a message to the client's writer, waiting for room. It returns false if the client has closed.
func (c *WebClient) send(message []byte) bool {
	select {
	case c.Send <- message:
		return true
	case <-c.Done:
		return false
	}
}

// queue passes a live message to the client's writer without waiting, so a slow page can't hold up
// the request or connection that produced it. Messages that don't fit are counted and reported to the page.
func (c *WebClient) queue(message []byte) {
	select {
	case c.Send <- message:
	default:
		c.dropped.Add(1)
	}
}

// Handle is the only place socket reads and writes happen.
func (c *WebClient) Handle() {
	defer func() {
		close(c.Done)

		err := c.Conn.Close()
		if err != nil {
			slog.Error(
				"error closing websocket connection",
				"error", err,
			)
		}

		c.Console.RemoveClient(c.Route, c)
	}()

	// Reading answers close frames and notices when the page goes away.
	closed := make(chan struct{})
	go func() {
		defer close(closed)

		for {
			if _, _, err := c.Conn.NextReader(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case message := <-c.Send:
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

			if n := c.dropped.Swap(0); n > 0 {
				notice := fmt.Appendf(nil, `{"type":"dropped","count":%d}`, n)
				if err := c.Conn.WriteMessage(websocket.TextMessage, notice); err != nil {
					return
				}
			}
		case <-closed:
			return
		}
	}
}
