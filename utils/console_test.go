package utils

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
)

func TestBroadcastRouteKeepsRecentHistory(t *testing.T) {
	viper.Set("service-console-history", 3)
	t.Cleanup(func() { viper.Set("service-console-history", 25) })

	c := NewWebConsole()
	owner := consoleOwner(t, "http://a.example.com")
	c.AddRoute("http://a.example.com", "token", owner)

	for i := range 5 {
		c.BroadcastRoute(owner, map[string]any{"n": i})
	}

	history := c.History("http://a.example.com")
	if len(history) != 3 {
		t.Fatalf("expected 3 requests in history, got %d", len(history))
	}

	var lastID float64
	for i, message := range history {
		var data map[string]any
		if err := json.Unmarshal(message, &data); err != nil {
			t.Fatal(err)
		}

		if data["n"] != float64(i+2) {
			t.Errorf("history[%d] has n=%v, want %d", i, data["n"], i+2)
		}

		id := data["id"].(float64)
		if id <= lastID {
			t.Errorf("history[%d] has id %v, not after %v", i, id, lastID)
		}
		lastID = id
	}

	c.RemoveRoute("http://a.example.com")
	if len(c.History("http://a.example.com")) != 0 {
		t.Error("expected history to be cleared when the route is removed")
	}
}

func TestBroadcastRouteSkipsUnknownRoutes(t *testing.T) {
	c := NewWebConsole()
	c.BroadcastRoute(consoleOwner(t, "http://missing.example.com"), map[string]any{})

	if len(c.History("http://missing.example.com")) != 0 {
		t.Error("expected no history for a route without a console")
	}
}

func TestHandleAssetServesSharedFiles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for path, want := range map[string]int{
		"/_sish/assets/theme.css":   http.StatusOK,
		"/_sish/assets/favicon.svg": http.StatusOK,
		"/_sish/assets/":            http.StatusNotFound,
		"/_sish/assets/assets.go":   http.StatusNotFound,
	} {
		w := httptest.NewRecorder()
		g, _ := gin.CreateTestContext(w)
		g.Request = httptest.NewRequest(http.MethodGet, path, nil)

		HandleAsset(g)

		if w.Code != want {
			t.Errorf("%s returned %d, want %d", path, w.Code, want)
		}
	}
}

func TestBroadcastEventKeepsEventsWithTheirRequest(t *testing.T) {
	viper.Set("service-console-websocket-messages", 2)
	t.Cleanup(func() { viper.Set("service-console-websocket-messages", 200) })

	c := NewWebConsole()
	owner := consoleOwner(t, "http://ws.example.com")
	c.AddRoute("http://ws.example.com", "token", owner)

	first := c.BroadcastRoute(owner, map[string]any{"n": "first"})
	second := c.BroadcastRoute(owner, map[string]any{"n": "second"})
	for _, n := range []string{"a", "b", "c"} {
		c.BroadcastEvent(owner, first, map[string]any{"n": n})
	}
	c.BroadcastEvent(owner, 12345, map[string]any{"n": "unknown request"})

	var got []string
	for _, message := range c.History("http://ws.example.com") {
		var data map[string]any
		if err := json.Unmarshal(message, &data); err != nil {
			t.Fatal(err)
		}
		got = append(got, data["n"].(string))

		if data["n"] == "b" && uint64(data["requestId"].(float64)) != first {
			t.Errorf("event b has requestId %v, want %d", data["requestId"], first)
		}
	}

	if want := "first b c second"; strings.Join(got, " ") != want {
		t.Errorf("history is %q, want %q", strings.Join(got, " "), want)
	}
	if second <= first {
		t.Errorf("ids %d and %d don't increase", first, second)
	}
}

func TestQueueDropsWhenTheClientFallsBehind(t *testing.T) {
	client := &WebClient{Send: make(chan []byte, 2), Done: make(chan struct{})}

	for range 5 {
		client.queue([]byte("x"))
	}

	if len(client.Send) != 2 || client.dropped.Load() != 3 {
		t.Errorf("queued %d and dropped %d, want 2 and 3", len(client.Send), client.dropped.Load())
	}
}

// sish registers no routes, so gin starts every request at 404. The console's
// websocket must still be logged as the upgrade it is.
func TestHandleWebSocketLogsSwitchingProtocols(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("service-console", true)

	console := NewWebConsole()
	console.AddRoute("http://sub.example.com", "token", nil)

	status := make(chan int, 1)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Next()
		status <- c.Writer.Status()
	}, func(c *gin.Context) {
		console.HandleRequest("http://sub.example.com", false, c)
	})

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/_sish/console/ws?x-authorization=token", nil)
	if err != nil {
		t.Fatalf("unable to open the console websocket: %s", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if got := <-status; got != http.StatusSwitchingProtocols {
		t.Errorf("expected status 101, got %d", got)
	}
}

func newConsoleEngine(t *testing.T, c *WebConsole, proxyUrl string, hostIsRoot bool) *gin.Engine {
	t.Helper()

	engine := gin.New()
	engine.SetHTMLTemplate(template.Must(template.New("console").Parse(`{{ define "console" }}console {{ .RouteHost }}{{ end }}{{ define "routes" }}routes{{ end }}`)))
	engine.Use(func(g *gin.Context) {
		g.Set("originalPath", g.Request.URL.Path)
		c.HandleRequest(proxyUrl, hostIsRoot, g)
	})

	return engine
}

// The admin token only works on the root domain, where admins open route consoles by id.
func TestAdminTokenStaysOnTheRootDomain(t *testing.T) {
	setViper(t, map[string]any{
		"admin-console":       true,
		"admin-console-token": "admin",
		"service-console":     false,
	})

	c := NewWebConsole()
	c.AddRoute("http://user:secret@app.example.com", "route-token", nil)
	id := c.RouteID("http://user:secret@app.example.com")
	if id == "" || strings.Contains(id, "secret") {
		t.Fatalf("unexpected route id %q", id)
	}

	get := func(engine *gin.Engine, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}

	tenant := newConsoleEngine(t, c, "http://user:secret@app.example.com", false)
	if rec := get(tenant, "/_sish/console?x-authorization=admin"); strings.HasPrefix(rec.Body.String(), "console") {
		t.Error("the admin token opened a console on a tenant host")
	}

	root := newConsoleEngine(t, c, "", true)
	if rec := get(root, "/_sish/console?x-authorization=admin"); rec.Body.String() != "routes" {
		t.Errorf("root without a route rendered %q", rec.Body.String())
	}
	if rec := get(root, "/_sish/console?x-authorization=admin&route="+id); rec.Body.String() != "console app.example.com" {
		t.Errorf("root with a route rendered %q", rec.Body.String())
	}
	if rec := get(root, "/_sish/console?x-authorization=admin&route=unknown"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown route answered %d", rec.Code)
	}

	c.RemoveRoute("http://user:secret@app.example.com")
	if _, ok := c.RouteByID(id); ok {
		t.Error("the route id outlived the route")
	}
}

// A client authorized for one route doesn't join a route bound under the same name later.
func TestAddClientChecksTheRouteToken(t *testing.T) {
	c := NewWebConsole()
	c.AddRoute("http://app.example.com", "old", nil)
	c.RemoveRoute("http://app.example.com")
	c.AddRoute("http://app.example.com", "new", nil)

	if _, ok := c.AddClient("http://app.example.com", "old", &WebClient{}); ok {
		t.Error("a client joined with the previous route's token")
	}

	client := &WebClient{}
	if _, ok := c.AddClient("http://app.example.com", "new", client); !ok {
		t.Fatal("a client with the current token was refused")
	}

	c.RemoveClient("http://app.example.com", client)
	if clients, _ := c.Clients.Load("http://app.example.com"); len(clients) != 0 {
		t.Errorf("%d clients left after removal", len(clients))
	}
}

func TestDisconnectRouteNeedsAKindAndName(t *testing.T) {
	setViper(t, map[string]any{
		"admin-console":       true,
		"admin-console-token": "admin",
	})

	c := NewWebConsole()
	c.State = NewState()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/_sish/api/disconnectroute/http?x-authorization=admin", nil)
	newConsoleEngine(t, c, "", true).ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("a route without a name answered %d", rec.Code)
	}
}

func consoleOwner(t *testing.T, route string) *HTTPHolder {
	t.Helper()

	u, err := url.Parse(route)
	if err != nil {
		t.Fatal(err)
	}

	return &HTTPHolder{HTTPUrl: u}
}

// Traffic a previous binding serves late stays out of the next binding's console.
func TestBroadcastsStayWithTheirBinding(t *testing.T) {
	setViper(t, map[string]any{"service-console-history": 25, "service-console-websocket-messages": 200})

	c := NewWebConsole()
	old := consoleOwner(t, "http://app.example.com")
	c.AddRoute("http://app.example.com", "old", old)
	request := c.BroadcastRoute(old, map[string]any{"n": "old"})
	c.RemoveRoute("http://app.example.com")

	current := consoleOwner(t, "http://app.example.com")
	c.AddRoute("http://app.example.com", "new", current)

	if id := c.BroadcastRoute(old, map[string]any{"n": "late"}); id != 0 {
		t.Error("a request from the previous binding was recorded")
	}
	c.BroadcastEvent(old, request, map[string]any{"n": "late event"})

	client := &WebClient{Send: make(chan []byte, 4), Done: make(chan struct{})}
	if _, ok := c.AddClient("http://app.example.com", "new", client); !ok {
		t.Fatal("the current binding's client was refused")
	}
	c.BroadcastEvent(old, request, map[string]any{"n": "late event"})

	if len(client.Send) != 0 || len(c.History("http://app.example.com")) != 0 {
		t.Errorf("the new binding got %d live messages and %d history entries", len(client.Send), len(c.History("http://app.example.com")))
	}

	if c.BroadcastRoute(current, map[string]any{"n": "new"}) == 0 || len(client.Send) != 1 {
		t.Error("the current binding's request wasn't broadcast")
	}
}

// History stays within its byte limits however much each request holds.
func TestHistoryIsBoundedInBytes(t *testing.T) {
	setViper(t, map[string]any{"service-console-history": 1000, "service-console-websocket-messages": 1000})

	c := NewWebConsole()
	owner := consoleOwner(t, "http://big.example.com")
	c.AddRoute("http://big.example.com", "token", owner)

	payload := strings.Repeat("x", 1<<20)
	for range 100 {
		c.BroadcastRoute(owner, map[string]any{"payload": payload})
	}
	if got := c.historyBytes["http://big.example.com"]; got > maxRouteHistory {
		t.Errorf("requests hold %d bytes of history", got)
	}

	// Evicted records can't stay reachable past the end of the slice.
	kept := c.history["http://big.example.com"]
	for _, record := range kept[len(kept):cap(kept)] {
		if record != nil {
			t.Fatal("an evicted record is still referenced")
		}
	}

	request := c.BroadcastRoute(owner, map[string]any{"n": "ws"})
	for range 100 {
		c.BroadcastEvent(owner, request, map[string]any{"payload": payload})
	}
	if got := c.historyBytes["http://big.example.com"]; got > maxRouteHistory {
		t.Errorf("events hold %d bytes of history", got)
	}

	history := c.History("http://big.example.com")
	var data map[string]any
	if err := json.Unmarshal(history[len(history)-1], &data); err != nil || data["payload"] != payload {
		t.Error("the newest event wasn't kept")
	}

	total := 0
	for _, message := range history {
		total += len(message)
	}
	if total != c.historyBytes["http://big.example.com"] || total != c.historyTotal {
		t.Errorf("history holds %d bytes but counts %d for the route and %d in all", total, c.historyBytes["http://big.example.com"], c.historyTotal)
	}

	c.RemoveRoute("http://big.example.com")
	if c.historyTotal != 0 {
		t.Errorf("%d bytes counted after the route was removed", c.historyTotal)
	}
}

func TestQueueIsBoundedInBytes(t *testing.T) {
	client := &WebClient{Send: make(chan []byte, clientQueue), Done: make(chan struct{})}

	message := make([]byte, 1<<20)
	for range 100 {
		client.queue(message)
	}

	if queued := len(client.Send) * len(message); queued > maxClientQueued || client.queued.Load() != int64(queued) {
		t.Errorf("queued %d bytes, counted %d", queued, client.queued.Load())
	}
}
