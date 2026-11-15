package httpmuxer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func setViper(t *testing.T, values map[string]any) {
	t.Helper()

	for key, value := range values {
		prev := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, prev) })
	}
}

// Forwarded headers only name the visitor when they come from a trusted proxy.
func TestSetTrustedProxies(t *testing.T) {
	cases := []struct {
		trusted, remote, want string
	}{
		{"", "192.0.2.1:1234", "192.0.2.1"},
		{"10.0.0.0/8", "192.0.2.1:1234", "192.0.2.1"},
		{"10.0.0.0/8", "10.1.2.3:1234", "203.0.113.9"},
	}

	for _, c := range cases {
		setViper(t, map[string]any{"http-trusted-proxies": c.trusted})

		r := gin.New()
		trustedProxy, err := setTrustedProxies(r)
		if err != nil {
			t.Fatal(err)
		}

		var got string
		r.GET("/", func(g *gin.Context) { got = g.ClientIP() })

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		r.ServeHTTP(httptest.NewRecorder(), req)

		if got != c.want {
			t.Errorf("trusting %q from %s: client IP %s", c.trusted, c.remote, got)
		}

		if trusted := trustedProxy(c.remote); trusted != (c.want != "192.0.2.1") {
			t.Errorf("trusting %q: %s trusted is %t", c.trusted, c.remote, trusted)
		}
	}

	setViper(t, map[string]any{"http-trusted-proxies": "not-an-ip"})
	if _, err := setTrustedProxies(gin.New()); err == nil {
		t.Error("an invalid proxy was accepted")
	}
}

// forwardHeaders are forwarding headers apps trust from a proxy.
var forwardHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server", "X-Forwarded-Ssl", "X-Forwarded-Prefix", "X-Real-IP"}

// Backends only see forwarding headers that a trusted proxy sent.
func TestDropForwardHeaders(t *testing.T) {
	setViper(t, map[string]any{"http-trusted-proxies": "10.0.0.0/8"})

	trustedProxy, err := setTrustedProxies(gin.New())
	if err != nil {
		t.Fatal(err)
	}

	for remote, kept := range map[string]bool{"192.0.2.1:1234": false, "10.1.2.3:1234": true, "[::ffff:10.1.2.3]:1234": true} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		for _, header := range forwardHeaders {
			req.Header.Set(header, "spoofed")
		}
		req.Header.Set("X-Other", "kept")

		dropForwardHeaders(req, trustedProxy)

		for _, header := range forwardHeaders {
			if got := req.Header.Get(header) != ""; got != kept {
				t.Errorf("from %s: %s kept is %t", remote, header, got)
			}
		}

		if req.Header.Get("X-Other") != "kept" {
			t.Errorf("from %s: an unrelated header was removed", remote)
		}
	}
}

func TestOnDemandAllowed(t *testing.T) {
	setViper(t, map[string]any{
		"https-ondemand-certificate":           true,
		"https-ondemand-certificate-wildcards": false,
		"domain":                               "example.com",
	})

	state := utils.NewState()
	for _, raw := range []string{"http://app.example.com", "http://*.wild.example.com"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		state.HTTPListeners.Store(raw, &utils.HTTPHolder{HTTPUrl: u, SSHConnections: syncmap.New[string, *utils.SSHConnection]()})
	}

	for name, want := range map[string]bool{"example.com": true, "app.example.com": true, "x.wild.example.com": false, "other.example.com": false} {
		if got := onDemandAllowed(state, name) == nil; got != want {
			t.Errorf("onDemandAllowed(%s) = %t", name, got)
		}
	}

	setViper(t, map[string]any{"https-ondemand-certificate-wildcards": true})
	if onDemandAllowed(state, "x.wild.example.com") != nil {
		t.Error("a wildcard name was refused with wildcards allowed")
	}
}
