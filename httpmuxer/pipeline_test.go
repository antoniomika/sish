package httpmuxer

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
)

// startTunnelBackend stands in for a tunneled client. It serves HTTP and a
// websocket echo on a unix socket named the way sshmuxer/requests.go names
// tunnel sockets, and returns the socket path.
func startTunnelBackend(t *testing.T) string {
	t.Helper()

	var sock string

	// The balancer addresses sockets by base64(path). Retry until the encoding
	// has no "/" or "+" so the test doesn't depend on the random suffix.
	for {
		f, err := os.CreateTemp("", "127.0.0.1_54321_80")
		if err != nil {
			t.Fatalf("unable to create socket path: %s", err)
		}

		sock = f.Name()
		_ = f.Close()
		_ = os.Remove(sock)

		if !strings.ContainsAny(base64.StdEncoding.EncodeToString([]byte(sock)), "/+") {
			break
		}
	}

	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("unable to listen on %s: %s", sock, err)
	}

	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(sock)
	})

	upgrader := websocket.Upgrader{}

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !websocket.IsWebSocketUpgrade(r) {
				if r.URL.Path == "/slow" {
					time.Sleep(20 * time.Millisecond)
				}

				w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
				_, _ = io.WriteString(w, "host="+r.Host)
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			// Hang up if the client never gets the upgrade, so a broken proxy
			// fails the test instead of blocking it.
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

			messageType, message, err := conn.ReadMessage()
			if err != nil {
				return
			}

			_ = conn.WriteMessage(messageType, append([]byte("echo:"), message...))
		}))
	}()

	return sock
}

// newTunnelBalancer returns a balancer over fwd with the tunnel socket as its
// only server, addressed the way sshmuxer/httphandler.go addresses it.
func newTunnelBalancer(t *testing.T, fwd http.Handler, sock string) *roundrobin.RoundRobin {
	t.Helper()

	lb, err := roundrobin.New(fwd)
	if err != nil {
		t.Fatalf("unable to create balancer: %s", err)
	}

	if err := lb.UpsertServer(&url.URL{Scheme: "http", Host: base64.StdEncoding.EncodeToString([]byte(sock))}); err != nil {
		t.Fatalf("unable to add tunnel server: %s", err)
	}

	return lb
}

// enableConsole turns on the admin console for the test, so ResponseModifier
// records every response.
func enableConsole(t *testing.T) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("admin-console", true)
	viper.Set("service-console-max-content-length", int64(-1))
}

// newTestFront serves the tunnel through fwd the way Start does, with
// ResponseModifier recording each response for the console. For each request
// it sends the recorded console data, or nil if none was recorded, on the
// returned channel.
func newTestFront(t *testing.T, fwd *httputil.ReverseProxy, sock string) (*httptest.Server, <-chan map[string]any) {
	t.Helper()

	listener := &utils.HTTPHolder{
		HTTPUrl:  &url.URL{Scheme: "http", Host: "sub.example.com"},
		Forward:  fwd,
		Balancer: newTunnelBalancer(t, fwd, sock),
	}

	recorded := make(chan map[string]any, 64)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Request = withResponseModifier(c.Request, ResponseModifier(nil, c.Request.Host, nil, c, listener))

		gin.WrapH(listener.Balancer)(c)

		data, _ := c.Get("broadcastData")
		record, _ := data.(map[string]any)
		recorded <- record
	})

	front := httptest.NewServer(router)
	t.Cleanup(front.Close)

	return front, recorded
}

// The forwarder must carry both plain HTTP and websocket upgrades to the
// tunnel socket with the console recording traffic. With the antoniomika/oxy
// fork, upgrades returned a 502.
func TestForwarderPipeline(t *testing.T) {
	enableConsole(t)

	sock := startTunnelBackend(t)
	front, recorded := newTestFront(t, NewForwarder(), sock)

	t.Run("http", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, front.URL+"/path?query=1", nil)
		if err != nil {
			t.Fatalf("unable to build request: %s", err)
		}

		req.Host = "sub.example.com"

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %s", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("unable to read response body: %s", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %q", resp.StatusCode, body)
		}

		if string(body) != "host=sub.example.com" {
			t.Errorf("expected the backend to see the original host, got %q", body)
		}

		select {
		case data := <-recorded:
			if data == nil {
				t.Fatal("expected the response modifier to record the response")
			}

			consoleBody, err := base64.StdEncoding.DecodeString(data["responseBody"].(string))
			if err != nil {
				t.Fatalf("unable to decode recorded response body: %s", err)
			}

			if !bytes.Equal(consoleBody, body) {
				t.Errorf("expected the console to record %q, got %q", body, consoleBody)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("expected the response modifier to record the response")
		}
	})

	t.Run("websocket", func(t *testing.T) {
		dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}

		conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http"), nil)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}

			t.Fatalf("websocket dial failed with status %d: %s", status, err)
		}
		defer func() { _ = conn.Close() }()

		if err := conn.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
			t.Fatalf("unable to write websocket message: %s", err)
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("unable to read websocket message: %s", err)
		}

		if string(message) != "echo:hi" {
			t.Errorf("expected echo:hi, got %q", message)
		}
	})
}

// Every request to a host goes through the same forwarder. When requests
// overlap, the console must still pair each request with its own response.
func TestForwarderPipelineConcurrentRequests(t *testing.T) {
	enableConsole(t)

	sock := startTunnelBackend(t)
	front, recorded := newTestFront(t, NewForwarder(), sock)

	const requests = 32

	var wg sync.WaitGroup

	for i := range requests {
		wg.Go(func() {
			req, err := http.NewRequest(http.MethodGet, front.URL+"/slow", nil)
			if err != nil {
				t.Errorf("unable to build request: %s", err)
				return
			}

			req.Header.Set("X-Request-Id", strconv.Itoa(i))

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("request %d failed: %s", i, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			_, _ = io.Copy(io.Discard, resp.Body)
		})
	}

	wg.Wait()

	for range requests {
		select {
		case data := <-recorded:
			if data == nil {
				t.Error("expected every request to be recorded")
				continue
			}

			requestID := data["requestHeaders"].(http.Header).Get("X-Request-Id")
			responseID := data["responseHeaders"].(http.Header).Get("X-Request-Id")

			if requestID != responseID {
				t.Errorf("request %s was recorded with the response to request %s", requestID, responseID)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("expected a console record for every request")
		}
	}
}
