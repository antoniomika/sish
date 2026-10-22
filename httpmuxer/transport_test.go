package httpmuxer

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

// startTLSTunnelBackend serves HTTPS on a unix socket and returns the socket
// path and a function that lists the server names clients sent, in order.
func startTLSTunnelBackend(t *testing.T) (string, func() []string) {
	t.Helper()

	var sock string

	// Retry until the encoding has no "/" or "+", as startTunnelBackend does.
	for {
		f, err := os.CreateTemp("", "127.0.0.1_54321_443")
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

	var mu sync.Mutex
	var names []string

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.ServerName)
	}))
	server.Listener = listener
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			defer mu.Unlock()

			names = append(names, hello.ServerName)

			return nil, nil
		},
	}
	server.StartTLS()

	t.Cleanup(func() {
		server.Close()
		_ = os.Remove(sock)
	})

	return sock, func() []string {
		mu.Lock()
		defer mu.Unlock()

		return append([]string(nil), names...)
	}
}

func TestRoundTripperSendsHostAsServerName(t *testing.T) {
	viper.Set("verify-ssl", false)
	t.Cleanup(func() { viper.Set("verify-ssl", nil) })

	sock, handshakes := startTLSTunnelBackend(t)
	transport := RoundTripper()

	for _, host := range []string{"a.example.com", "a.example.com:443", "b.example.com", "[::1]:443"} {
		req, err := http.NewRequest(http.MethodGet, "https://"+base64.StdEncoding.EncodeToString([]byte(sock))+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host

		res, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %s", host, err)
		}

		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		// Go sends no server name for an IP address.
		want := tlsServerName(host)
		if net.ParseIP(want) != nil {
			want = ""
		}

		if string(body) != want {
			t.Errorf("%s: backend saw server name %q, want %q", host, body, want)
		}
	}

	// The second a.example.com request reuses the first connection.
	got := fmt.Sprint(handshakes())
	if want := fmt.Sprint([]string{"a.example.com", "b.example.com", ""}); got != want {
		t.Errorf("handshakes %s, want %s", got, want)
	}
}

func TestRoundTripperBoundsTransports(t *testing.T) {
	transport := RoundTripper().(*tunnelTransport)

	for i := range maxTLSTransports + 10 {
		transport.forName(fmt.Sprintf("host%d.example.com", i))
	}

	if len(transport.byName) != maxTLSTransports {
		t.Errorf("kept %d transports, want %d", len(transport.byName), maxTLSTransports)
	}
}
