package httpmuxer

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/andybalholm/brotli"
	"github.com/antoniomika/sish/utils"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/forward"
	oxyutils "github.com/vulcand/oxy/v2/utils"
)

// maxTLSTransports bounds how many server names one forwarder keeps
// transports for, since a wildcard listener can see any number of hosts.
const maxTLSTransports = 256

// RoundTripper returns the specific handler for unix connections. This
// will allow us to use our created sockets cleanly.
func RoundTripper() http.RoundTripper {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		realAddr, err := base64.StdEncoding.DecodeString(strings.Split(addr, ":")[0])
		if err != nil {
			slog.Error(
				"unable to parse socket",
				"err", err,
			)
		}

		var d net.Dialer

		return d.DialContext(ctx, "unix", string(realAddr))
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !viper.GetBool("verify-ssl"),
	}

	// Each new connection opens an SSH channel, a round trip to the client, so
	// keep enough idle ones for concurrent requests. They have to expire before
	// the idle timeout in CopyBoth closes the tunnel side.
	idleTimeout := 90 * time.Second
	if viper.GetBool("idle-connection") {
		idleTimeout = viper.GetDuration("idle-connection-timeout") / 2
	}

	return &tunnelTransport{
		base: &http.Transport{
			DialContext:         dialer,
			TLSClientConfig:     tlsConfig,
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     idleTimeout,
		},
		byName: map[string]*http.Transport{},
	}
}

// tunnelTransport sends HTTPS requests to a tunnel with the request's host as
// the TLS server name. The URL host is the encoded socket address, which is
// what the transport would use otherwise. Each name gets its own transport so
// a connection made for one host is never reused for another.
type tunnelTransport struct {
	base *http.Transport

	mu     sync.Mutex
	byName map[string]*http.Transport
}

func (t *tunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.Host == "" {
		return t.base.RoundTrip(req)
	}

	return t.forName(tlsServerName(req.Host)).RoundTrip(req)
}

func (t *tunnelTransport) forName(name string) *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()

	if transport, ok := t.byName[name]; ok {
		return transport
	}

	if len(t.byName) >= maxTLSTransports {
		for evicted, transport := range t.byName {
			transport.CloseIdleConnections()
			delete(t.byName, evicted)
			break
		}
	}

	transport := t.base.Clone()
	transport.TLSClientConfig.ServerName = name
	t.byName[name] = transport

	return transport
}

// tlsServerName returns host without its port or IPv6 brackets.
func tlsServerName(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		return name
	}

	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}

// responseModifierKey is the request context key for the response modifier
// set by withResponseModifier.
type responseModifierKey struct{}

// withResponseModifier returns a copy of req whose response the forwarder
// passes to modifier before sending it to the client.
func withResponseModifier(req *http.Request, modifier func(*http.Response) error) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), responseModifierKey{}, modifier))
}

// publicHostKey is the request context key for the host set by withPublicHost.
type publicHostKey struct{}

// withPublicHost returns a copy of req that carries the host the client asked
// for, so the forwarder's logs name it after Start rewrites the Host header.
func withPublicHost(req *http.Request, host string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), publicHostKey{}, host))
}

// publicHost returns the host set by withPublicHost, or the Host header.
func publicHost(req *http.Request) string {
	if host, ok := req.Context().Value(publicHostKey{}).(string); ok {
		return host
	}

	return req.Host
}

// loggingBody logs a failed read of an upstream response body. Both readers
// of the body stop at the first error, so it logs at most once.
type loggingBody struct {
	io.ReadCloser

	host string
	ctx  context.Context
}

func (b *loggingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)

	// A canceled context means the client went away, not the tunnel.
	if err != nil && err != io.EOF && b.ctx.Err() == nil {
		slog.Error(
			"error reading response body",
			"host", b.host,
			"err", err,
		)
	}

	return n, err
}

// NewForwarder returns the reverse proxy used for each HTTP host. It dials
// the tunnel sockets through RoundTripper and streams responses with the same
// flush interval oxy v1 used.
func NewForwarder() *httputil.ReverseProxy {
	fwd := forward.New(true)
	fwd.Transport = RoundTripper()
	fwd.FlushInterval = 100 * time.Millisecond

	// The proxy only logs failed body reads, which loggingBody already logs
	// with the host.
	fwd.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)

	fwd.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		// Once an upgrade has hijacked the connection there is no status left
		// to send.
		if gw, ok := w.(gin.ResponseWriter); ok && gw.Written() {
			slog.Error(
				"error switching protocols",
				"host", publicHost(req),
				"err", err,
			)
			return
		}

		// The tunnel closed before the response was complete.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(http.StatusText(http.StatusBadGateway)))

			return
		}

		oxyutils.DefaultHandler.ServeHTTP(w, req, err)
	}

	// All requests to a host share this proxy, so the modifier for each one
	// travels in its context rather than in ModifyResponse.
	fwd.ModifyResponse = func(response *http.Response) error {
		if response.Request == nil {
			return nil
		}

		if response.Body != nil && response.StatusCode != http.StatusSwitchingProtocols {
			response.Body = &loggingBody{
				ReadCloser: response.Body,
				host:       publicHost(response.Request),
				ctx:        response.Request.Context(),
			}
		}

		modifier, ok := response.Request.Context().Value(responseModifierKey{}).(func(*http.Response) error)
		if !ok {
			return nil
		}

		return modifier(response)
	}

	return fwd
}

// ResponseModifier implements a response modifier for the specified request.
// We don't actually modify any requests, but we do want to record which tunnel
// served the request and its status for the request log, and the request
// itself for the web console. Start installs it on every proxied request.
func ResponseModifier(state *utils.State, hostname string, reqBody []byte, c *gin.Context, currentListener *utils.HTTPHolder) func(*http.Response) error {
	return func(response *http.Response) error {
		if response.Request != nil {
			hostLocation, err := base64.StdEncoding.DecodeString(response.Request.URL.Host)
			if err != nil {
				slog.Error(
					"error loading proxy info from request",
					"err", err,
				)
			}

			c.Set("proxySocket", string(hostLocation))
		}

		// The body of a 101 is the upgraded connection to the tunnel. Reading it
		// would block until the connection closes, so only WebSockets are recorded, as they pass through.
		if response.StatusCode == http.StatusSwitchingProtocols {
			// The proxy writes the 101 to the hijacked conn, past gin's writer.
			c.Status(http.StatusSwitchingProtocols)

			if consoleEnabled() && viper.GetInt("service-console-websocket-messages") > 0 && strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
				inspectWebSocket(state, hostname, reqBody, c, currentListener, response)
			}

			return nil
		}

		if consoleEnabled() {
			limit := viper.GetInt64("service-console-max-content-length")
			encoding := response.Header.Get("Content-Encoding")

			data := requestData(c, hostname, reqBody)
			data["responseHeaders"] = response.Header
			data["responseBody"] = base64.StdEncoding.EncodeToString(notCapturedResponse)

			c.Set("broadcastRoute", currentListener.HTTPUrl.String())
			c.Set("broadcastData", data)

			switch {
			case limit == -1 || (limit > -1 && response.ContentLength > -1 && response.ContentLength < limit):
				resBody, readErr := io.ReadAll(response.Body)
				response.Body = io.NopCloser(bytes.NewBuffer(resBody))

				data["responseBody"] = base64.StdEncoding.EncodeToString(decodeConsoleBody(resBody, encoding, limit))

				// A cut-off body is still recorded, and the error makes the
				// forwarder send a 502 in place of the partial response.
				return readErr
			case limit > -1 && response.ContentLength == -1:
				// Waiting for the whole body would hold up streamed responses,
				// so it is recorded as it passes through to the client.
				response.Body = &consoleCapture{
					ReadCloser:  response.Body,
					encoding:    encoding,
					limit:       limit,
					notCaptured: notCapturedResponse,
					onClose: func(body []byte) {
						data["responseBody"] = base64.StdEncoding.EncodeToString(body)
					},
				}
			}
		}

		return nil
	}
}

// notCapturedRequest and notCapturedResponse stand in for bodies the console didn't record.
var (
	notCapturedRequest  = []byte("{\"_sish_status\": false, \"_sish_message\": \"request body size exceeds limit for service console\"}")
	notCapturedResponse = []byte("{\"_sish_status\": false, \"_sish_message\": \"response body size exceeds limit for service console\"}")
)

// readRequestBody prepares the request body of c for the console. It returns
// the body when it can be read before forwarding. A body of unknown length is
// recorded as the tunnel reads it instead, and recordRequestBody adds it to
// the console data once the request is done.
func readRequestBody(c *gin.Context) ([]byte, error) {
	limit := viper.GetInt64("service-console-max-content-length")

	switch {
	case limit == -1 || (limit > -1 && c.Request.ContentLength > -1 && c.Request.ContentLength < limit):
		reqBody, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, err
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(reqBody))

		return reqBody, nil
	case limit > -1 && c.Request.ContentLength == -1:
		capture := &consoleCapture{ReadCloser: c.Request.Body, limit: limit, notCaptured: notCapturedRequest}
		c.Request.Body = capture
		c.Set("requestCapture", capture)

		return nil, nil
	}

	return notCapturedRequest, nil
}

// recordRequestBody adds a request body recorded by readRequestBody to data.
// The tunnel can still be reading the body after the response arrives, so
// this waits until the request is logged.
func recordRequestBody(keys map[any]any, data map[string]any) {
	if capture, ok := keys["requestCapture"].(*consoleCapture); ok {
		data["requestBody"] = base64.StdEncoding.EncodeToString(capture.recorded())
	}
}

// consoleCapture records up to limit bytes of a body for the console as it is
// read, so a body of unknown length doesn't have to be held back first.
type consoleCapture struct {
	io.ReadCloser

	encoding    string
	limit       int64
	notCaptured []byte

	// onClose, if set, is passed the recorded body when the body is closed.
	onClose func(body []byte)

	mu   sync.Mutex
	buf  bytes.Buffer
	over bool
	once sync.Once
}

func (b *consoleCapture) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)

	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.over {
		if int64(b.buf.Len()+n) >= b.limit {
			b.over = true
			b.buf = bytes.Buffer{}
		} else {
			b.buf.Write(p[:n])
		}
	}

	return n, err
}

func (b *consoleCapture) Close() error {
	if b.onClose != nil {
		b.once.Do(func() { b.onClose(b.recorded()) })
	}

	return b.ReadCloser.Close()
}

// recorded returns the body read so far without its Content-Encoding, or
// notCaptured if it reached the limit.
func (b *consoleCapture) recorded() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.over {
		return b.notCaptured
	}

	return decodeConsoleBody(b.buf.Bytes(), b.encoding, b.limit)
}

// decodeConsoleBody returns body with its Content-Encoding removed so the
// console can show it. A body that can't be decoded is returned as-is, and
// one that decodes past limit is replaced by notCapturedResponse.
func decodeConsoleBody(body []byte, encoding string, limit int64) []byte {
	// A 304 can carry a Content-Encoding with no body.
	if len(body) == 0 {
		return body
	}

	var reader io.Reader
	var err error

	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		// Deflate should be zlib wrapped, but some servers send it raw.
		reader, err = zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			reader, err = flate.NewReader(bytes.NewReader(body)), nil
		}
	case "br":
		reader = brotli.NewReader(bytes.NewReader(body))
	case "zstd":
		var decoder *zstd.Decoder
		decoder, err = zstd.NewReader(bytes.NewReader(body), zstd.WithDecoderConcurrency(1))
		if err == nil {
			defer decoder.Close()
			reader = decoder
		}
	default:
		return body
	}

	if err != nil {
		slog.Error(
			"error decoding console body",
			"encoding", encoding,
			"err", err,
		)
		return body
	}

	if limit > -1 {
		reader = io.LimitReader(reader, limit)
	}

	decoded, err := io.ReadAll(reader)
	if err != nil {
		slog.Error(
			"error decoding console body",
			"encoding", encoding,
			"err", err,
		)
		return body
	}

	if limit > -1 && int64(len(decoded)) >= limit {
		return notCapturedResponse
	}

	return decoded
}

func consoleEnabled() bool {
	return viper.GetBool("admin-console") || viper.GetBool("service-console")
}

// requestData returns the request fields the console shows for c.
func requestData(c *gin.Context, hostname string, reqBody []byte) map[string]any {
	startTime := c.GetTime("startTime")

	requestHeaders := c.Request.Header.Clone()
	requestHeaders.Add("Host", hostname)

	return map[string]any{
		"startTime":          startTime,
		"startTimePretty":    startTime.Format(viper.GetString("time-format")),
		"requestIP":          c.ClientIP(),
		"requestMethod":      c.Request.Method,
		"requestUrl":         c.Request.URL,
		"originalRequestURI": c.GetString("originalURI"),
		"requestHeaders":     requestHeaders,
		"requestBody":        base64.StdEncoding.EncodeToString(reqBody),
	}
}
