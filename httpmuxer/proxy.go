package httpmuxer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
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

// NewForwarder returns the reverse proxy used for each HTTP host. It dials
// the tunnel sockets through RoundTripper and streams responses with the same
// flush interval oxy v1 used.
func NewForwarder() *httputil.ReverseProxy {
	fwd := forward.New(true)
	fwd.Transport = RoundTripper()
	fwd.FlushInterval = 100 * time.Millisecond

	// All requests to a host share this proxy, so the modifier for each one
	// travels in its context rather than in ModifyResponse.
	fwd.ModifyResponse = func(response *http.Response) error {
		if response.Request == nil {
			return nil
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
// We don't actually modify any requests, but we do want to record the request
// so we can send it to the web console.
func ResponseModifier(state *utils.State, hostname string, reqBody []byte, c *gin.Context, currentListener *utils.HTTPHolder) func(*http.Response) error {
	return func(response *http.Response) error {
		// The body of a 101 is the upgraded connection to the tunnel. Reading it
		// would block until the connection closes, so leave upgrades unrecorded.
		if response.StatusCode == http.StatusSwitchingProtocols {
			return nil
		}

		if viper.GetBool("admin-console") || viper.GetBool("service-console") {
			var err error
			var resBody []byte

			if viper.GetInt64("service-console-max-content-length") == -1 || (viper.GetInt64("service-console-max-content-length") > -1 && response.ContentLength > -1 && response.ContentLength < viper.GetInt64("service-console-max-content-length")) {
				resBody, err = io.ReadAll(response.Body)
				if err != nil {
					log.Println("Error reading response body:", err)
				}
			}

			if resBody != nil {
				response.Body = io.NopCloser(bytes.NewBuffer(resBody))

				// A 304 can carry Content-Encoding: gzip with no body. Keep the raw bytes if decoding fails.
				if response.Header.Get("Content-Encoding") == "gzip" && len(resBody) > 0 {
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

			startTime := c.GetTime("startTime")

			requestHeaders := c.Request.Header.Clone()
			requestHeaders.Add("Host", hostname)

			data := map[string]any{
				"startTime":          startTime,
				"startTimePretty":    startTime.Format(viper.GetString("time-format")),
				"requestIP":          c.ClientIP(),
				"requestMethod":      c.Request.Method,
				"requestUrl":         c.Request.URL,
				"originalRequestURI": c.GetString("originalURI"),
				"requestHeaders":     requestHeaders,
				"requestBody":        base64.StdEncoding.EncodeToString(reqBody),
				"responseHeaders":    response.Header,
				"responseBody":       base64.StdEncoding.EncodeToString(resBody),
			}

			if response.Request != nil {
				hostLocation, err := base64.StdEncoding.DecodeString(response.Request.URL.Host)
				if err != nil {
					log.Println("Error loading proxy info from request", err)
				}

				c.Set("proxySocket", string(hostLocation))
			}

			c.Set("broadcastRoute", currentListener.HTTPUrl.String())
			c.Set("broadcastData", data)
		}

		return nil
	}
}
