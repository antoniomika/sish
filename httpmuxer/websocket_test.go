package httpmuxer

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/vulcand/oxy/forward"
)

// TestWebsocketUpgradeThroughUnixSocket sends a WebSocket handshake through a
// forwarder set up like the one sish creates for each HTTP tunnel, to an
// upstream listening on the unix socket that backs the tunnel.
func TestWebsocketUpgradeThroughUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "tunnel.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("unable to listen on unix socket: %s", err)
	}

	upgrader := websocket.Upgrader{}
	upstream := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	})}

	go func() { _ = upstream.Serve(listener) }()
	t.Cleanup(func() { _ = upstream.Close() })

	rT := RoundTripper()

	fwd, err := forward.New(
		forward.Stream(true),
		forward.PassHostHeader(true),
		forward.RoundTripper(rT),
		forward.WebsocketRoundTripper(rT),
	)
	if err != nil {
		t.Fatalf("unable to create forwarder: %s", err)
	}

	target := &url.URL{
		Scheme: "http",
		Host:   base64.StdEncoding.EncodeToString([]byte(socketPath)) + ":80",
	}

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL = target
		fwd.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)

	// The forwarder overwrites websocket.DefaultDialer's NetDial, so the
	// client uses a dialer of its own.
	clientDialer := &websocket.Dialer{}

	conn, resp, err := clientDialer.Dial("ws"+proxy.URL[len("http"):]+"/ws", nil)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}

		t.Fatalf("websocket handshake failed with status %d: %s", status, err)
	}

	_ = conn.Close()
}
