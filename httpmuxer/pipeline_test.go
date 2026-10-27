package httpmuxer

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
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
// tunnel sockets, and returns the socket path. Requests to /reject, upgrades
// included, get a 401.
func startTunnelBackend(t *testing.T) string {
	t.Helper()

	sock, _ := startTunnelBackendWithStreamDone(t)

	return sock
}

// startTunnelBackendWithStreamDone is startTunnelBackend, plus a channel that
// receives once for every /stream handler that has returned.
func startTunnelBackendWithStreamDone(t *testing.T) (string, <-chan struct{}) {
	t.Helper()

	streamDone := make(chan struct{}, 16)

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
			if r.URL.Path == "/reject" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !websocket.IsWebSocketUpgrade(r) {
				switch r.URL.Path {
				case "/chunked":
					w.Header().Set("X-Test", "chunked")
					_, _ = io.WriteString(w, "first")
					w.(http.Flusher).Flush()
					_, _ = io.WriteString(w, "second")

					return
				case "/upload":
					received, _ := io.ReadAll(r.Body)
					_, _ = w.Write(received)

					return
				case "/drop":
					_, _ = io.WriteString(w, "partial")
					w.(http.Flusher).Flush()

					// net/http closes the connection without the closing
					// chunk, as a dropped tunnel does.
					panic(http.ErrAbortHandler)
				case "/stream":
					defer func() { streamDone <- struct{}{} }()

					_, _ = io.WriteString(w, "partial")
					w.(http.Flusher).Flush()
					<-r.Context().Done()

					return
				}

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

	return sock, streamDone
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

// captureLog sends the default logger's output to a buffer for the rest of
// the test and returns a function that reads it. The proxy goroutines write
// while the test reads, so the buffer is guarded by a mutex.
func captureLog(t *testing.T) func() string {
	t.Helper()

	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)

	old := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()

		return buf.Write(p)
	}), nil)))

	t.Cleanup(func() {
		slog.SetDefault(old)
	})

	return func() string {
		mu.Lock()
		defer mu.Unlock()

		return buf.String()
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// frontRecord is what the request log sees for one request.
type frontRecord struct {
	status      int
	proxySocket string

	// console is the data recorded for the console, or nil if none was.
	console map[string]any
}

// newTestFront serves the tunnel through fwd the way Start does, with
// ResponseModifier recording each response. It sends a record for each
// request on the returned channel, read like gin's logger reads it, once the
// handlers return.
func newTestFront(t *testing.T, fwd *httputil.ReverseProxy, sock string) (*httptest.Server, <-chan frontRecord) {
	t.Helper()

	return newTestFrontWithHostHeader(t, fwd, sock, "")
}

// newTestFrontWithHostHeader is newTestFront for a tunnel that overrides the
// Host header sent to it, unless hostHeader is empty.
func newTestFrontWithHostHeader(t *testing.T, fwd *httputil.ReverseProxy, sock, hostHeader string) (*httptest.Server, <-chan frontRecord) {
	t.Helper()

	listener := &utils.HTTPHolder{
		HTTPUrl:  &url.URL{Scheme: "http", Host: "sub.example.com"},
		Forward:  fwd,
		Balancer: newTunnelBalancer(t, fwd, sock),
	}

	recorded := make(chan frontRecord, 64)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Next()

		data, _ := c.Get("broadcastData")
		console, _ := data.(map[string]any)

		if console != nil {
			recordRequestBody(c.Keys, console)
		}

		recorded <- frontRecord{
			status:      c.Writer.Status(),
			proxySocket: c.GetString("proxySocket"),
			console:     console,
		}
	}, gin.CustomRecoveryWithWriter(nil, recoverPanic), recoverAbort, func(c *gin.Context) {
		hostname := c.Request.Host

		if hostHeader != "" {
			c.Request.Host = hostHeader
		}

		reqBody, err := readRequestBody(c)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.Request = withPublicHost(c.Request, hostname)
		c.Request = withResponseModifier(c.Request, ResponseModifier(nil, hostname, reqBody, c, listener))

		gin.WrapH(listener.Balancer)(c)
	})

	front := httptest.NewServer(reraiseAbort(router))
	t.Cleanup(front.Close)

	return front, recorded
}

// nextRecord returns the record of the next request the front finished.
func nextRecord(t *testing.T, recorded <-chan frontRecord) frontRecord {
	t.Helper()

	select {
	case record := <-recorded:
		return record
	case <-time.After(5 * time.Second):
		t.Fatal("expected the request to be logged")
	}

	return frontRecord{}
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

		data := nextRecord(t, recorded).console
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
		data := nextRecord(t, recorded).console
		if data == nil {
			t.Error("expected every request to be recorded")
			continue
		}

		requestID := data["requestHeaders"].(http.Header).Get("X-Request-Id")
		responseID := data["responseHeaders"].(http.Header).Get("X-Request-Id")

		if requestID != responseID {
			t.Errorf("request %s was recorded with the response to request %s", requestID, responseID)
		}
	}
}

// The request log must report the status the client received, also for
// upgrades, whose response bypasses gin's writer. It must also name the tunnel
// that served the request, so log-to-client reaches only that client.
func TestForwarderPipelineLoggedStatus(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	sock := startTunnelBackend(t)

	// Each subtest gets its own front, so a request one leaves unread can't
	// be mistaken for the next one's.
	newFront := func(t *testing.T) (*httptest.Server, func(t *testing.T, expected int)) {
		front, recorded := newTestFront(t, NewForwarder(), sock)

		return front, func(t *testing.T, expected int) {
			t.Helper()

			record := nextRecord(t, recorded)

			if record.status != expected {
				t.Errorf("expected the log to report status %d, got %d", expected, record.status)
			}

			if record.proxySocket != sock {
				t.Errorf("expected the log to name tunnel %q, got %q", sock, record.proxySocket)
			}
		}
	}

	t.Run("http", func(t *testing.T) {
		front, expectLoggedStatus := newFront(t)

		resp, err := http.Get(front.URL + "/reject")
		if err != nil {
			t.Fatalf("request failed: %s", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		expectLoggedStatus(t, http.StatusUnauthorized)
	})

	t.Run("websocket", func(t *testing.T) {
		front, expectLoggedStatus := newFront(t)

		dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}

		conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http"), nil)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}

			t.Fatalf("websocket dial failed with status %d: %s", status, err)
		}

		// The handler, and with it the log entry, finishes once the upgraded
		// connection closes.
		_ = conn.Close()

		expectLoggedStatus(t, http.StatusSwitchingProtocols)
	})

	t.Run("rejected websocket", func(t *testing.T) {
		front, expectLoggedStatus := newFront(t)

		dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}

		conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/reject", nil)
		if err == nil {
			_ = conn.Close()
			t.Fatal("expected the backend to reject the upgrade")
		}

		if resp == nil || resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected the client to receive a 401, got %v: %s", resp, err)
		}

		expectLoggedStatus(t, http.StatusUnauthorized)
	})
}

// getThroughFront requests path from the front with the tunnel's host name.
func getThroughFront(ctx context.Context, front *httptest.Server, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Host = "sub.example.com"

	return http.DefaultClient.Do(req)
}

// A tunnel that drops in the middle of a response must not look like a
// complete response to the browser. With the console on, the proxy reads the
// whole body itself, so the browser must get a 502 instead. The console still
// records what the tunnel sent.
func TestForwarderPipelineDroppedTunnelWithConsole(t *testing.T) {
	enableConsole(t)

	logs := captureLog(t)
	sock := startTunnelBackend(t)
	front, recorded := newTestFront(t, NewForwarder(), sock)

	resp, err := getThroughFront(t.Context(), front, "/drop")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", resp.StatusCode)
	}

	if strings.Contains(string(body), "partial") {
		t.Errorf("expected no part of the cut-off body to be sent, got %q", body)
	}

	record := nextRecord(t, recorded)

	if record.proxySocket != sock {
		t.Errorf("expected the log to name tunnel %q, got %q", sock, record.proxySocket)
	}

	if record.console == nil {
		t.Fatal("expected the console to record the request")
	}

	consoleBody, err := base64.StdEncoding.DecodeString(record.console["responseBody"].(string))
	if err != nil {
		t.Fatalf("unable to decode recorded response body: %s", err)
	}

	if string(consoleBody) != "partial" {
		t.Errorf("expected the console to record the partial body, got %q", consoleBody)
	}

	front.Close()

	if !strings.Contains(logs(), "sub.example.com") {
		t.Errorf("expected the log to name the host, got %q", logs())
	}
}

// Without buffering, the proxy has already sent the status when the tunnel
// drops. The browser must see the transfer fail instead of end cleanly.
func TestForwarderPipelineDroppedTunnelWithoutBuffering(t *testing.T) {
	setups := map[string]func(t *testing.T){
		"console-off": func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
		},
		"console-limited": func(t *testing.T) {
			enableConsole(t)
			viper.Set("service-console-max-content-length", int64(1024))
		},
	}

	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			setup(t)

			logs := captureLog(t)
			sock := startTunnelBackend(t)
			front, _ := newTestFront(t, NewForwarder(), sock)

			resp, err := getThroughFront(t.Context(), front, "/drop")
			if err != nil {
				t.Fatalf("request failed before the body: %s", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, readErr := io.ReadAll(resp.Body)
			if readErr == nil {
				t.Errorf("expected the transfer to fail, got status %d with body %q", resp.StatusCode, body)
			}

			front.Close()

			if !strings.Contains(logs(), "sub.example.com") {
				t.Errorf("expected the log to name the host, got %q", logs())
			}

			if lines := strings.Count(logs(), "\n"); lines != 1 {
				t.Errorf("expected one log line for the drop, got %d: %q", lines, logs())
			}
		})
	}
}

// The drop log must name the host the browser asked for, also when the tunnel
// overrides the Host header sent to it.
func TestForwarderPipelineDroppedTunnelLogsPublicHost(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	logs := captureLog(t)
	sock := startTunnelBackend(t)
	front, _ := newTestFrontWithHostHeader(t, NewForwarder(), sock, "localhost:3000")

	resp, err := getThroughFront(t.Context(), front, "/drop")
	if err != nil {
		t.Fatalf("request failed before the body: %s", err)
	}

	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	front.Close()

	if !strings.Contains(logs(), "host=sub.example.com") {
		t.Errorf("expected the log to name sub.example.com, got %q", logs())
	}
}

// A response that ends properly must still reach the browser unchanged.
func TestForwarderPipelineCompleteChunkedResponse(t *testing.T) {
	setups := map[string]func(t *testing.T){
		"console-on": enableConsole,
		"console-off": func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
		},
	}

	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			setup(t)

			sock := startTunnelBackend(t)
			front, _ := newTestFront(t, NewForwarder(), sock)

			resp, err := getThroughFront(t.Context(), front, "/chunked")
			if err != nil {
				t.Fatalf("request failed: %s", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unable to read response body: %s", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected status 200, got %d", resp.StatusCode)
			}

			if resp.Header.Get("X-Test") != "chunked" {
				t.Errorf("expected the backend header, got %q", resp.Header.Get("X-Test"))
			}

			if string(body) != "firstsecond" {
				t.Errorf("expected firstsecond, got %q", body)
			}
		})
	}
}

// With a limit set, a response of unknown length is recorded as it streams to
// the client, unless it reaches the limit.
func TestForwarderPipelineLimitedConsoleChunkedResponse(t *testing.T) {
	limits := map[string]struct {
		limit    int64
		recorded []byte
	}{
		"under-limit": {1024, []byte("firstsecond")},
		"over-limit":  {8, notCapturedResponse},
	}

	for name, tc := range limits {
		t.Run(name, func(t *testing.T) {
			enableConsole(t)
			viper.Set("service-console-max-content-length", tc.limit)

			sock := startTunnelBackend(t)
			front, recorded := newTestFront(t, NewForwarder(), sock)

			resp, err := getThroughFront(t.Context(), front, "/chunked")
			if err != nil {
				t.Fatalf("request failed: %s", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unable to read response body: %s", err)
			}

			if string(body) != "firstsecond" {
				t.Errorf("expected firstsecond, got %q", body)
			}

			record := nextRecord(t, recorded)
			if record.console == nil {
				t.Fatal("expected the console to record the request")
			}

			consoleBody, err := base64.StdEncoding.DecodeString(record.console["responseBody"].(string))
			if err != nil {
				t.Fatalf("unable to decode recorded response body: %s", err)
			}

			if !bytes.Equal(consoleBody, tc.recorded) {
				t.Errorf("expected the console to record %q, got %q", tc.recorded, consoleBody)
			}
		})
	}
}

// With a limit set, a request body of unknown length is recorded as the tunnel
// reads it, unless it reaches the limit.
func TestForwarderPipelineLimitedConsoleChunkedRequest(t *testing.T) {
	limits := map[string]struct {
		limit    int64
		recorded []byte
	}{
		"under-limit": {1024, []byte("uploaded body")},
		"over-limit":  {8, notCapturedRequest},
	}

	for name, tc := range limits {
		t.Run(name, func(t *testing.T) {
			enableConsole(t)
			viper.Set("service-console-max-content-length", tc.limit)

			sock := startTunnelBackend(t)
			front, recorded := newTestFront(t, NewForwarder(), sock)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, front.URL+"/upload", io.NopCloser(strings.NewReader("uploaded body")))
			if err != nil {
				t.Fatalf("unable to create request: %s", err)
			}

			req.Host = "sub.example.com"
			req.ContentLength = -1

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %s", err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("unable to read response body: %s", err)
			}

			if string(body) != "uploaded body" {
				t.Errorf("expected the tunnel to receive the whole body, got %q", body)
			}

			record := nextRecord(t, recorded)
			if record.console == nil {
				t.Fatal("expected the console to record the request")
			}

			consoleBody, err := base64.StdEncoding.DecodeString(record.console["requestBody"].(string))
			if err != nil {
				t.Fatalf("unable to decode recorded request body: %s", err)
			}

			if !bytes.Equal(consoleBody, tc.recorded) {
				t.Errorf("expected the console to record %q, got %q", tc.recorded, consoleBody)
			}
		})
	}
}

// A browser that leaves mid-transfer makes the body read fail on the proxy
// side. That is not a tunnel failure and must not be logged as one.
func TestForwarderPipelineClientAbortIsNotLogged(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	logs := captureLog(t)
	sock, streamDone := startTunnelBackendWithStreamDone(t)
	front, _ := newTestFront(t, NewForwarder(), sock)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	resp, err := getThroughFront(ctx, front, "/stream")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}

	received := make([]byte, len("partial"))
	if _, err := io.ReadFull(resp.Body, received); err != nil {
		t.Fatalf("unable to read the first part of the body: %s", err)
	}

	cancel()
	_ = resp.Body.Close()

	select {
	case <-streamDone:
	case <-time.After(5 * time.Second):
		t.Fatal("expected the backend to notice the aborted request")
	}

	// Close waits for the proxy to finish its in-flight request, so a late
	// log line cannot slip past the assertion.
	front.Close()

	if strings.Contains(logs(), "sub.example.com") {
		t.Errorf("expected a client abort not to be logged, got %q", logs())
	}
}

// Panics other than an aborted handler fail the request and are logged.
func TestEngineRecoversOtherPanics(t *testing.T) {
	logs := captureLog(t)

	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(gin.CustomRecoveryWithWriter(nil, recoverPanic), recoverAbort)
	engine.GET("/boom", func(*gin.Context) { panic("boom") })

	recorder := httptest.NewRecorder()
	reraiseAbort(engine).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", recorder.Code)
	}

	if out := logs(); !strings.Contains(out, `msg="panic recovered" error=boom`) {
		t.Errorf("expected the panic to be logged, got:\n%s", out)
	}
}
