package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/forward"
	oxyutils "github.com/vulcand/oxy/v2/utils"
)

// RoundTripper returns the specific handler for unix connections. This
// will allow us to use our created sockets cleanly.
func RoundTripper() *http.Transport {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		realAddr, err := base64.StdEncoding.DecodeString(strings.Split(addr, ":")[0])
		if err != nil {
			log.Println("Unable to parse socket:", err)
		}

		var d net.Dialer

		return d.DialContext(ctx, "unix", string(realAddr))
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: !viper.GetBool("verify-ssl"),
	}

	return &http.Transport{
		DialContext:     dialer,
		TLSClientConfig: tlsConfig,
	}
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
		log.Printf("Error reading response body from %s: %s", b.host, err)
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
	fwd.ErrorLog = log.New(io.Discard, "", 0)

	fwd.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		// Once an upgrade has hijacked the connection there is no status left
		// to send.
		if gw, ok := w.(gin.ResponseWriter); ok && gw.Written() {
			log.Printf("Error switching protocols for %s: %s", publicHost(req), err)
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
				log.Println("Error loading proxy info from request", err)
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
			var readErr error
			var resBody []byte

			if viper.GetInt64("service-console-max-content-length") == -1 || (viper.GetInt64("service-console-max-content-length") > -1 && response.ContentLength > -1 && response.ContentLength < viper.GetInt64("service-console-max-content-length")) {
				resBody, readErr = io.ReadAll(response.Body)
			}

			if resBody != nil {
				response.Body = io.NopCloser(bytes.NewBuffer(resBody))

				// A 304 can carry Content-Encoding: gzip with no body. Keep the raw bytes if decoding fails.
				if readErr == nil && response.Header.Get("Content-Encoding") == "gzip" && len(resBody) > 0 {
					gzReader, err := gzip.NewReader(bytes.NewBuffer(resBody))
					if err != nil {
						log.Println("Error reading gzip data:", err)
					} else if decodedBody, err := io.ReadAll(gzReader); err != nil {
						log.Println("Error reading gzip data:", err)
					} else {
						resBody = decodedBody
					}
				}
			} else {
				resBody = []byte("{\"_sish_status\": false, \"_sish_message\": \"response body size exceeds limit for service console\"}")
			}

			data := requestData(c, hostname, reqBody)
			data["responseHeaders"] = response.Header
			data["responseBody"] = base64.StdEncoding.EncodeToString(resBody)

			c.Set("broadcastRoute", currentListener.HTTPUrl.String())
			c.Set("broadcastData", data)

			// A cut-off body is still recorded, and the error makes the
			// forwarder send a 502 in place of the partial response.
			return readErr
		}

		return nil
	}
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
