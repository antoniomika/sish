package utils

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
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
	queued  atomic.Int64
}

const (
	// clientQueue is how many live messages can wait for a slow page before new ones are dropped.
	clientQueue = 512

	// maxClientQueued bounds the bytes of live messages waiting for one page.
	maxClientQueued = 32 << 20

	// maxRouteHistory and maxHistory bound the bytes of history kept for one
	// route and for all of them, since visitors choose how much each request holds.
	maxRouteHistory = 64 << 20
	maxHistory      = 512 << 20
)

// consoleRecord is a request kept for consoles that connect later, with the WebSocket events that followed it.
type consoleRecord struct {
	id      uint64
	message []byte
	events  [][]byte
	size    int
}

// WebConsole represents the data structure that stores web console client information.
type WebConsole struct {
	Clients     *syncmap.Map[string, []*WebClient]
	RouteTokens *syncmap.Map[string, string]
	State       *State

	// routeIDs and routesByID name routes in admin console URLs without the
	// basic auth password that route keys carry.
	routeIDs   map[string]string
	routesByID map[string]string

	// routeOwners is the holder each route belongs to, so traffic a previous
	// binding of the same route serves late doesn't reach the next one's console.
	routeOwners map[string]*HTTPHolder

	// routesLock orders route changes with clients joining and leaving them.
	routesLock sync.Mutex

	requestID    atomic.Uint64
	history      map[string][]*consoleRecord
	historyBytes map[string]int
	historyTotal int
	historyLock  sync.Mutex
}

// NewWebConsole sets up the WebConsole.
func NewWebConsole() *WebConsole {
	c := &WebConsole{
		Clients:      syncmap.New[string, []*WebClient](),
		RouteTokens:  syncmap.New[string, string](),
		routeIDs:     map[string]string{},
		routesByID:   map[string]string{},
		routeOwners:  map[string]*HTTPHolder{},
		history:      map[string][]*consoleRecord{},
		historyBytes: map[string]int{},
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
	queryToken := g.Request.URL.Query().Get("x-authorization")
	headerToken := g.Request.Header.Get("x-authorization")
	tokenMatches := func(expected string) bool {
		// Check both so the time doesn't show where the token was sent.
		queryMatches := TokenMatches(queryToken, expected)
		headerMatches := TokenMatches(headerToken, expected)
		return queryMatches || headerMatches
	}

	// Tenant hosts serve content their owners control, so the admin token is only used on the root domain.
	if hostIsRoot && viper.GetBool("admin-console") && tokenMatches(viper.GetString("admin-console-token")) {
		userIsAdmin = true
		userAuthed = true

		// Admins open a route's console from the root domain.
		if id := g.Request.URL.Query().Get("route"); id != "" {
			route, ok := c.RouteByID(id)
			if !ok {
				g.AbortWithStatus(http.StatusNotFound)
				return
			}

			proxyUrl = route
		}
	}

	routeToken, ok := c.RouteTokens.Load(proxyUrl)
	if ok && routeToken != "" && viper.GetBool("service-console") && tokenMatches(routeToken) {
		userAuthed = true
	}

	if strings.HasPrefix(g.Request.URL.Path, "/_sish/console/ws") && userAuthed {
		c.HandleWebSocket(proxyUrl, routeToken, g)
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

	if hostIsRoot && userIsAdmin && proxyUrl == "" {
		g.HTML(http.StatusOK, "routes", gin.H{"Title": "Admin", "Base": base})
		return
	}

	if c.RouteExists(proxyUrl) {
		data := gin.H{"Title": "Requests", "Base": base, "RouteHost": "", "RoutePath": ""}

		// A route's console on the root domain shows the route's own address.
		if hostIsRoot && userIsAdmin {
			if u, err := url.Parse(proxyUrl); err == nil {
				data["RouteHost"] = u.Hostname()
				data["RoutePath"] = strings.TrimSuffix(u.Path, "/")
			}
		}

		g.HTML(http.StatusOK, "console", data)
		return
	}

	_ = g.AbortWithError(http.StatusNotFound, fmt.Errorf("cannot find connection for host: %s", RedactRoute(proxyUrl)))
}

// HandleWebSocket handles the websocket route. routeToken is the route's token
// when the request was authorized, which ties the client to that route.
func (c *WebConsole) HandleWebSocket(proxyUrl string, routeToken string, g *gin.Context) {
	// The upgrade hijacks the connection past gin's writer, which would
	// otherwise log the 404 gin starts unrouted requests with. A failed
	// upgrade writes its own status over this one.
	g.Status(http.StatusSwitchingProtocols)

	conn, err := upgrader.Upgrade(g.Writer, g.Request, nil)
	if err != nil {
		slog.Error(
			"error handling websockets",
			"err", err,
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

	// The route may have closed and been bound by someone else during the upgrade.
	history, ok := c.AddClient(proxyUrl, routeToken, client)
	if !ok {
		CloseWebClients([]*WebClient{client})
		return
	}

	go client.Handle()

	// History is one batch so it can't fill the queue that live messages use.
	// It can interleave with live messages, so the page orders requests by id and events by seq.
	if len(history) > 0 {
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
	_, encRouteName, ok := strings.Cut(strings.TrimPrefix(g.Request.URL.Path, "/_sish/api/disconnectroute/"), "/")
	if !ok {
		g.AbortWithStatus(http.StatusNotFound)
		return
	}

	decRouteName, err := base64.StdEncoding.DecodeString(encRouteName)
	if err != nil {
		slog.Error(
			"error decoding route name",
			"err", err,
		)

		_ = g.AbortWithError(http.StatusInternalServerError, err)
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
					"err", err,
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
							"err", err,
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
								"err", err,
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
		consoleRoutes := map[string]any{}
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

				name := fmt.Sprintf("%s%s%s", userPass, httpHolder.HTTPUrl.Hostname(), httpHolder.HTTPUrl.Path)
				httpListeners[name] = listenerHandlers

				if id := c.RouteID(httpHolder.HTTPUrl.String()); id != "" {
					consoleRoutes[name] = id
				}
			}

			return true
		})

		routeListeners["tcpAliases"] = tcpAliases
		routeListeners["listeners"] = listenerParts
		routeListeners["httpListeners"] = httpListeners
		routeListeners["consoleRoutes"] = consoleRoutes

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

// AddRoute adds a route token to the console for the holder that serves the route.
func (c *WebConsole) AddRoute(route string, token string, owner *HTTPHolder) {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	c.Clients.LoadOrStore(route, []*WebClient{})
	c.RouteTokens.Store(route, token)
	c.routeOwners[route] = owner

	if _, ok := c.routeIDs[route]; !ok {
		id := RandomString(20)
		c.routeIDs[route] = id
		c.routesByID[id] = route
	}
}

// RouteID returns the id admin console URLs use for a route.
func (c *WebConsole) RouteID(route string) string {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	return c.routeIDs[route]
}

// RouteByID returns the route an admin console id names.
func (c *WebConsole) RouteByID(id string) (string, bool) {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	route, ok := c.routesByID[id]
	return route, ok
}

// RemoveRoute removes a route token from the console and closes its clients.
func (c *WebConsole) RemoveRoute(route string) {
	CloseWebClients(c.DetachRoute(route))
}

// DetachRoute removes a route token from the console and returns its clients
// for the caller to close.
func (c *WebConsole) DetachRoute(route string) []*WebClient {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	clients, ok := c.Clients.Load(route)

	if !ok {
		return nil
	}

	c.Clients.Delete(route)
	c.RouteTokens.Delete(route)

	delete(c.routesByID, c.routeIDs[route])
	delete(c.routeIDs, route)
	delete(c.routeOwners, route)

	c.historyLock.Lock()
	c.historyTotal -= c.historyBytes[route]
	delete(c.history, route)
	delete(c.historyBytes, route)
	c.historyLock.Unlock()

	return clients
}

// CloseWebClients closes console connections. Closing a TLS connection can
// wait on a stalled peer, so it shouldn't run under a lock others need.
func CloseWebClients(clients []*WebClient) {
	for _, client := range clients {
		err := client.Conn.Close()
		if err != nil {
			slog.Error(
				"error closing websocket connection",
				"err", err,
			)
		}
	}
}

// AddClient adds a client to the console route if the route still has the
// token the client was authorized with, and returns the route's history from
// the same moment, so it can't belong to a later binding of the route.
func (c *WebConsole) AddClient(route string, token string, w *WebClient) ([][]byte, bool) {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	clients, ok := c.Clients.Load(route)
	if !ok {
		return nil, false
	}

	if current, _ := c.RouteTokens.Load(route); current != token {
		return nil, false
	}

	// A new slice, since broadcasts range over the stored one without the lock.
	c.Clients.Store(route, append(slices.Clip(clients), w))

	return c.History(route), true
}

// RemoveClient removes a client from the console route.
func (c *WebConsole) RemoveClient(route string, w *WebClient) {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	clients, ok := c.Clients.Load(route)
	if !ok {
		return
	}

	remaining := slices.DeleteFunc(slices.Clone(clients), func(client *WebClient) bool { return client == w })
	if len(remaining) != len(clients) {
		c.Clients.Store(route, remaining)
	}
}

// BroadcastRoute records a request the owner served and sends it to the route's clients.
// It returns the request's id, or 0 if the route has no console.
func (c *WebConsole) BroadcastRoute(owner *HTTPHolder, data map[string]any) uint64 {
	route := owner.HTTPUrl.String()
	if _, ok := c.Clients.Load(route); !ok {
		return 0
	}

	id := c.requestID.Add(1)
	data["id"] = id

	message, err := json.Marshal(data)
	if err != nil {
		slog.Error(
			"unable to marshal console data",
			"err", err,
		)
		return 0
	}

	clients, ok := c.publish(route, owner, func() { c.addHistory(route, id, message) })
	if !ok {
		return 0
	}

	for _, client := range clients {
		client.queue(message)
	}

	return id
}

// BroadcastEvent sends an event that belongs to an earlier request, such as a WebSocket message, to the route's clients.
func (c *WebConsole) BroadcastEvent(owner *HTTPHolder, requestID uint64, data map[string]any) {
	route := owner.HTTPUrl.String()
	if _, ok := c.Clients.Load(route); !ok {
		return
	}

	data["requestId"] = requestID

	message, err := json.Marshal(data)
	if err != nil {
		slog.Error(
			"unable to marshal console data",
			"err", err,
		)
		return
	}

	clients, ok := c.publish(route, owner, func() { c.addEvent(route, requestID, message) })
	if !ok {
		return
	}

	for _, client := range clients {
		client.queue(message)
	}
}

// publish records a message with record if owner still holds the route, and
// returns the route's clients. Both happen under the lock that route changes take.
func (c *WebConsole) publish(route string, owner *HTTPHolder, record func()) ([]*WebClient, bool) {
	c.routesLock.Lock()
	defer c.routesLock.Unlock()

	clients, ok := c.Clients.Load(route)
	if !ok || c.routeOwners[route] != owner {
		return nil, false
	}

	record()

	return clients, true
}

// addHistory keeps the most recent requests for a route, up to service-console-history and the history byte limits.
func (c *WebConsole) addHistory(route string, id uint64, message []byte) {
	limit := viper.GetInt("service-console-history")
	if limit <= 0 {
		return
	}

	c.historyLock.Lock()
	defer c.historyLock.Unlock()

	history := c.history[route]
	if len(history) >= limit {
		history = c.evictRecords(route, history, len(history)-limit+1)
	}

	record := &consoleRecord{id: id, message: message, size: len(message)}
	c.historyBytes[route] += record.size
	c.historyTotal += record.size
	history = append(history, record)

	// The oldest requests go first, and a request that doesn't fit on its own isn't kept.
	for len(history) > 0 && c.overHistoryLimit(route) {
		history = c.evictRecords(route, history, 1)
	}

	if len(history) == 0 {
		history = nil
	}

	c.history[route] = history
}

// addEvent keeps an event with its request, up to service-console-websocket-messages per request and the history byte limits.
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
			c.evictEvents(route, record, len(record.events)-limit+1)
		}

		record.events = append(record.events, message)
		record.size += len(message)
		c.historyBytes[route] += len(message)
		c.historyTotal += len(message)

		// Older requests go first, then the connection's oldest messages, so its request stays listed.
		for c.overHistoryLimit(route) {
			if history[0] != record {
				history = c.evictRecords(route, history, 1)
				continue
			}

			if len(record.events) == 0 {
				break
			}

			c.evictEvents(route, record, 1)
		}

		c.history[route] = history
		return
	}
}

func (c *WebConsole) overHistoryLimit(route string) bool {
	return c.historyBytes[route] > maxRouteHistory || c.historyTotal > maxHistory
}

// evictRecords drops the oldest n records of a route's history.
func (c *WebConsole) evictRecords(route string, history []*consoleRecord, n int) []*consoleRecord {
	for _, record := range history[:n] {
		c.historyBytes[route] -= record.size
		c.historyTotal -= record.size
	}

	// Deleting clears the vacated slots, so evicted records can be collected.
	return slices.Delete(history, 0, n)
}

// evictEvents drops the oldest n events of a record.
func (c *WebConsole) evictEvents(route string, record *consoleRecord, n int) {
	for _, event := range record.events[:n] {
		record.size -= len(event)
		c.historyBytes[route] -= len(event)
		c.historyTotal -= len(event)
	}

	record.events = slices.Delete(record.events, 0, n)
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
	c.queued.Add(int64(len(message)))

	select {
	case c.Send <- message:
		return true
	case <-c.Done:
		c.queued.Add(-int64(len(message)))
		return false
	}
}

// queue passes a live message to the client's writer without waiting, so a slow page can't hold up
// the request or connection that produced it. Messages that don't fit are counted and reported to the page.
func (c *WebClient) queue(message []byte) {
	size := int64(len(message))
	if c.queued.Add(size) > maxClientQueued {
		c.queued.Add(-size)
		c.dropped.Add(1)
		return
	}

	select {
	case c.Send <- message:
	default:
		c.queued.Add(-size)
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
				"err", err,
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
			c.queued.Add(-int64(len(message)))

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
