package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func TestBroadcastRouteKeepsRecentHistory(t *testing.T) {
	viper.Set("service-console-history", 3)
	t.Cleanup(func() { viper.Set("service-console-history", 25) })

	c := NewWebConsole()
	c.AddRoute("http://a.example.com", "token")

	for i := range 5 {
		c.BroadcastRoute("http://a.example.com", map[string]any{"n": i})
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
	c.BroadcastRoute("http://missing.example.com", map[string]any{})

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
	c.AddRoute("http://ws.example.com", "token")

	first := c.BroadcastRoute("http://ws.example.com", map[string]any{"n": "first"})
	second := c.BroadcastRoute("http://ws.example.com", map[string]any{"n": "second"})
	for _, n := range []string{"a", "b", "c"} {
		c.BroadcastEvent("http://ws.example.com", first, map[string]any{"n": n})
	}
	c.BroadcastEvent("http://ws.example.com", 12345, map[string]any{"n": "unknown request"})

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
