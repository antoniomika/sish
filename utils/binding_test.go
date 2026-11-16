package utils

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/antoniomika/syncmap"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/v2/roundrobin"
	"golang.org/x/crypto/ssh"
)

func setViper(t *testing.T, values map[string]any) {
	t.Helper()

	for key, value := range values {
		prev := viper.Get(key)
		viper.Set(key, value)
		t.Cleanup(func() { viper.Set(key, prev) })
	}
}

func newTestSSHConnection() *SSHConnection {
	return &SSHConnection{
		Listeners: syncmap.New[string, net.Listener](),
		Messages:  make(chan string, 100),
		Close:     make(chan bool),
	}
}

func storeHTTPHolder(t *testing.T, state *State, raw string) *HTTPHolder {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	lb, err := roundrobin.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	pH := &HTTPHolder{HTTPUrl: u, SSHConnections: syncmap.New[string, *SSHConnection](), Balancer: lb}
	state.HTTPListeners.Store(u.String(), pH)

	return pH
}

func storeHTTPSSNIHolder(state *State, names ...string) *TCPHolder {
	tH := &TCPHolder{
		Balancers:      syncmap.New[string, *roundrobin.RoundRobin](),
		SSHConnections: syncmap.New[string, *SSHConnection](),
		SNIProxy:       true,
		HTTPS:          true,
	}

	tH.Balancers.Store("", nil)
	for _, name := range names {
		tH.Balancers.Store(name, nil)
	}

	state.TCPListeners.Store("https", tH)

	return tH
}

func namedBindingConfig(t *testing.T) {
	setViper(t, map[string]any{
		"domain":                        "example.com",
		"bind-random-subdomains":        false,
		"bind-random-subdomains-length": 8,
		"bind-http-auth":                true,
		"bind-http-path":                true,
		"http-load-balancer":            false,
		"sni-load-balancer":             false,
		"verify-dns":                    false,
	})
}

func TestMatchHTTPHolderPrefersLongestPath(t *testing.T) {
	state := NewState()
	root := storeHTTPHolder(t, state, "http://app.example.com")
	foo := storeHTTPHolder(t, state, "http://app.example.com/foo")
	wildcard := storeHTTPHolder(t, state, "http://*.example.com/foo/bar")

	cases := []struct {
		host, path string
		want       *HTTPHolder
	}{
		{"app.example.com", "/foo/bar", foo},
		{"app.example.com", "/foo", foo},
		{"app.example.com", "/other", root},
		{"other.example.com", "/foo/bar/baz", wildcard},
		{"other.example.com", "/foo", nil},
	}

	for range 20 {
		for _, c := range cases {
			if got, authNeeded := MatchHTTPHolder(state.HTTPListeners, c.host, c.path, "", ""); got != c.want || authNeeded {
				t.Fatalf("%s%s routed to %v, authNeeded %t", c.host, c.path, got, authNeeded)
			}
		}
	}
}

func TestMatchHTTPHolderPicksByCredentials(t *testing.T) {
	state := NewState()
	alice := storeHTTPHolder(t, state, "http://alice:a@app.example.com")
	bob := storeHTTPHolder(t, state, "http://bob:b@app.example.com")
	public := storeHTTPHolder(t, state, "http://app.example.com/public")

	cases := []struct {
		path, user, pass string
		want             *HTTPHolder
		authNeeded       bool
	}{
		{"/", "alice", "a", alice, false},
		{"/", "bob", "b", bob, false},
		{"/", "bob", "a", nil, true},
		{"/", "", "", nil, true},
		// Path comes first, so credentials for the root don't reach it from a more specific path.
		{"/public/x", "alice", "a", public, false},
	}

	for range 20 {
		for _, c := range cases {
			got, authNeeded := MatchHTTPHolder(state.HTTPListeners, "app.example.com", c.path, c.user, c.pass)
			if authNeeded != c.authNeeded || (c.want != nil && got != c.want) || got == nil {
				t.Fatalf("%s as %s:%s routed to %v, authNeeded %t", c.path, c.user, c.pass, got, authNeeded)
			}
		}
	}
}

func TestGetOpenHostCredentialedBindingsShareAPath(t *testing.T) {
	namedBindingConfig(t)

	cases := []struct {
		bound, requested string
		shared           bool
	}{
		{"http://user:pass@app.example.com", "x:y@app", true},
		{"http://user:pass@app.example.com", "user:pass@app", false},
		{"http://user:pass@app.example.com", "app", false},
		{"http://user:pass@app.example.com", "x:y@app/sub", false},
		{"http://app.example.com", "x:y@app", false},
		{"http://app.example.com/foo", "x:y@app/foo", false},
	}

	for _, c := range cases {
		state := NewState()
		storeHTTPHolder(t, state, c.bound)

		hostURL, pH := GetOpenHost(c.requested, state, newTestSSHConnection())
		if shared := hostURL.Host == "app.example.com"; shared != c.shared || pH != nil {
			t.Errorf("%s over %s was given %s", c.requested, c.bound, hostURL.Host)
		}
	}
}

func TestGetOpenHostJoinsOnlyWithMatchingCredentials(t *testing.T) {
	namedBindingConfig(t)
	setViper(t, map[string]any{"http-load-balancer": true})

	state := NewState()
	bound := storeHTTPHolder(t, state, "http://user:pass@app.example.com")

	if _, pH := GetOpenHost("user:pass@app", state, newTestSSHConnection()); pH != bound {
		t.Error("matching credentials didn't join the balancer")
	}

	if _, pH := GetOpenHost("user:other@app", state, newTestSSHConnection()); pH != nil {
		t.Error("other credentials joined the balancer")
	}
}

func TestGetOpenHostSkipsHTTPSSNINames(t *testing.T) {
	namedBindingConfig(t)

	state := NewState()
	storeHTTPSSNIHolder(state, "app.example.com", "*.wild.example.com")

	for _, requested := range []string{"app", "x.wild"} {
		hostURL, _ := GetOpenHost(requested, state, newTestSSHConnection())
		if !strings.HasSuffix(hostURL.Host, ".example.com") || strings.HasPrefix(hostURL.Host, requested+".") {
			t.Errorf("%s was given %s, which is bound for SNI", requested, hostURL.Host)
		}
	}

	if hostURL, _ := GetOpenHost("free", state, newTestSSHConnection()); hostURL.Host != "free.example.com" {
		t.Errorf("free was given %s", hostURL.Host)
	}
}

func TestGetOpenSNIHostSkipsHTTPHosts(t *testing.T) {
	namedBindingConfig(t)
	setViper(t, map[string]any{"bind-root-domain": true})

	state := NewState()
	storeHTTPHolder(t, state, "http://app.example.com/path")
	https := storeHTTPSSNIHolder(state)

	// An empty name asks for the root domain.
	for _, requested := range []string{"app", ""} {
		host, err := GetOpenSNIHost(requested, state, newTestSSHConnection(), https)
		if err != nil {
			t.Fatal(err)
		}

		if host == "app.example.com" || host == "example.com" {
			t.Errorf("%q was given %s", requested, host)
		}
	}

	if host, _ := GetOpenSNIHost("free", state, newTestSSHConnection(), https); host != "free.example.com" {
		t.Errorf("free was given %s", host)
	}

	// SNI names on other ports don't reach sish's HTTPS listener.
	other := &TCPHolder{Balancers: syncmap.New[string, *roundrobin.RoundRobin](), SNIProxy: true}
	if host, _ := GetOpenSNIHost("app", state, newTestSSHConnection(), other); host != "app.example.com" {
		t.Errorf("app on another port was given %s", host)
	}
}

// The first SNI binding keeps every name its wildcard covers.
func TestSNINameTakenByOverlap(t *testing.T) {
	namedBindingConfig(t)

	state := NewState()
	tH := &TCPHolder{Balancers: syncmap.New[string, *roundrobin.RoundRobin](), SNIProxy: true}
	tH.Balancers.Store("*.apps.example.com", nil)
	tH.Balancers.Store("db.example.com", nil)

	for name, want := range map[string]bool{
		"login.apps.example.com":  true,
		"*.deep.apps.example.com": true,
		"*.example.com":           true,
		"db.example.com":          true,
		"other.example.com":       false,
	} {
		if got := SNINameTaken(state, tH, name, newTestSSHConnection()); got != want {
			t.Errorf("%s taken is %t", name, got)
		}
	}

	// Load balancing shares the same name and nothing that only overlaps it.
	setViper(t, map[string]any{"sni-load-balancer": true})
	if SNINameTaken(state, tH, "db.example.com", newTestSSHConnection()) {
		t.Error("db.example.com wasn't shared with load balancing")
	}
	if !SNINameTaken(state, tH, "login.apps.example.com", newTestSSHConnection()) {
		t.Error("login.apps.example.com was shared with load balancing")
	}
}

func TestParsePortRanges(t *testing.T) {
	ranges, err := parsePortRanges("0, 1024-2048,3000-3000")
	if err != nil {
		t.Fatal(err)
	}

	if want := []portRange{{0, 0}, {1024, 2048}, {3000, 3000}}; len(ranges) != len(want) || ranges[1] != want[1] || ranges[2] != want[2] {
		t.Errorf("got %v", ranges)
	}

	for _, bad := range []string{"", "2048-1024", "70000", "1-70000", "a-b"} {
		if _, err := parsePortRanges(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}

	if _, err := CheckPort(2048, "1024-2048"); err != nil {
		t.Error("the top of a range was refused")
	}
}

func TestGetRandomPortInRangeSinglePortAndFull(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	port := ln.Addr().(*net.TCPAddr).Port
	portRange := strconv.Itoa(port) + "-" + strconv.Itoa(port)

	if _, err := GetRandomPortInRange("127.0.0.1", portRange); err == nil {
		t.Error("a full range returned a port")
	}

	_ = ln.Close()

	got, err := GetRandomPortInRange("127.0.0.1", portRange)
	if err != nil || int(got) != port {
		t.Errorf("got %d, %v", got, err)
	}
}

func TestRandomString(t *testing.T) {
	a, b := RandomString(20), RandomString(20)
	if len(a) != 20 || a == b {
		t.Errorf("got %q and %q", a, b)
	}

	for _, r := range a {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", r) {
			t.Errorf("unexpected character %q", r)
		}
	}
}

func TestIsLocalhost(t *testing.T) {
	for addr, want := range map[string]bool{"localhost": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true, "10.0.0.1": false, "": false, "0.0.0.0": false} {
		if IsLocalhost(addr) != want {
			t.Errorf("IsLocalhost(%q) != %t", addr, want)
		}
	}
}

func TestUpstreamTrusted(t *testing.T) {
	prev := trustedUpstreams
	t.Cleanup(func() { trustedUpstreams = prev })

	trustedUpstreams = nil
	if !upstreamTrusted(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}) {
		t.Error("an empty list didn't trust everyone")
	}

	for _, upstream := range []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"} {
		prefix, err := ParsePrefix(upstream)
		if err != nil {
			t.Fatal(err)
		}
		trustedUpstreams = append(trustedUpstreams, prefix)
	}

	for ip, want := range map[string]bool{"10.1.2.3": true, "192.0.2.7": true, "192.0.2.8": false, "2001:db8::1": true, "::ffff:10.0.0.1": true, "8.8.8.8": false} {
		if got := upstreamTrusted(&net.TCPAddr{IP: net.ParseIP(ip), Port: 1}); got != want {
			t.Errorf("upstreamTrusted(%s) = %t", ip, got)
		}
	}
}

func TestTokenMatches(t *testing.T) {
	if TokenMatches("", "") || TokenMatches("a", "") || TokenMatches("ab", "a") || !TokenMatches("abc", "abc") {
		t.Error("unexpected result")
	}
}

func TestListenerPortSkipsOtherNetworks(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "l.sock")

	l, err := Listen("unix://" + sock + ",tcp://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	if ListenerPort(l) == 0 {
		t.Error("no tcp port found")
	}

	u, err := Listen("unix://" + sock + "2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()

	if ListenerPort(u) != 0 {
		t.Error("a unix listener has a port")
	}
}

// A wildcard that covers every random name fails the binding instead of looping.
func TestRandomNamesStopAtWildcard(t *testing.T) {
	namedBindingConfig(t)
	setViper(t, map[string]any{"bind-random-subdomains": true})

	done := make(chan struct{})
	go func() {
		defer close(done)

		state := NewState()
		storeHTTPHolder(t, state, "http://*.example.com")
		if _, err := GetOpenSNIHost("app", state, newTestSSHConnection(), storeHTTPSSNIHolder(state)); err == nil {
			t.Error("an SNI name was found under an HTTP wildcard")
		}

		state = NewState()
		storeHTTPSSNIHolder(state, "*.example.com")
		if hostURL, _ := GetOpenHost("app", state, newTestSSHConnection()); hostURL != nil {
			t.Errorf("%s was found under an SNI wildcard", hostURL.Host)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("binding never gave up")
	}
}

func TestHTTPBindingTaken(t *testing.T) {
	state := NewState()
	storeHTTPHolder(t, state, "http://user:pass@app.example.com")
	storeHTTPSSNIHolder(state, "tls.example.com")

	for raw, want := range map[string]bool{
		"http://user:pass@app.example.com": true,
		"http://x:y@app.example.com":       false,
		"http://app.example.com":           true,
		"http://other.example.com":         false,
		"http://tls.example.com":           true,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}

		if got := HTTPBindingTaken(state, u, newTestSSHConnection()); got != want {
			t.Errorf("HTTPBindingTaken(%s) = %t", raw, got)
		}
	}
}

// An SNI forward listens on the session's tcp-address, never on the hostname it asked for.
func TestGetOpenPortSNIUsesSessionAddress(t *testing.T) {
	setViper(t, map[string]any{
		"bind-random-ports":     true,
		"port-bind-range":       "",
		"localhost-as-all":      false,
		"force-tcp-address":     false,
		"tcp-address":           "",
		"tcp-load-balancer":     false,
		"sni-load-balancer":     false,
		"force-requested-ports": false,
	})

	sshConn := newTestSSHConnection()
	sshConn.TCPAddress = "127.0.0.2"

	for _, requested := range []string{"unix:///tmp/sish-test.sock", "app,tcp://0.0.0.0", "app"} {
		listenAddr, _, _, err := GetOpenPort(requested, 443, NewState(), sshConn, true)
		if err != nil || listenAddr != "127.0.0.2:0" {
			t.Errorf("%s: listening on %q, %v", requested, listenAddr, err)
		}
	}

	sshConn.TCPAddress = "unix:///tmp/sish-test.sock"
	if _, _, _, err := GetOpenPort("app", 443, NewState(), sshConn, true); err == nil {
		t.Error("a unix tcp address was accepted")
	}
}

func TestRedactRoute(t *testing.T) {
	for route, want := range map[string]string{
		"http://user:secret@app.example.com/path": "http://user:xxxxx@app.example.com/path",
		"http://app.example.com":                  "http://app.example.com",
	} {
		if got := RedactRoute(route); got != want {
			t.Errorf("RedactRoute(%q) = %q", route, got)
		}
	}
}

// An auth endpoint that redirects a rejection to a page answering 200 still rejects.
func TestAuthRequestsDontFollowRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	setViper(t, map[string]any{
		"authentication-key-request-timeout":      time.Second,
		"authentication-password-request-timeout": time.Second,
	})

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	if ok, _ := checkAuthenticationKeyRequest(srv.URL+"/auth", []byte("ssh-ed25519 AAAA"), addr, "user"); ok {
		t.Error("key request followed the redirect")
	}

	if ok, _ := checkAuthenticationPasswordRequest(srv.URL+"/auth", []byte("pw"), addr, "user"); ok {
		t.Error("password request followed the redirect")
	}
}

func TestAcquireAuthRequestIsBounded(t *testing.T) {
	var releases []func()
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
	})

	for range maxAuthRequests {
		release, err := acquireAuthRequest(time.Second)
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}

	if _, err := acquireAuthRequest(50 * time.Millisecond); err == nil {
		t.Fatal("a request ran past the limit")
	}

	releases[0]()
	releases = releases[1:]

	release, err := acquireAuthRequest(50 * time.Millisecond)
	if err != nil {
		t.Fatal("a freed slot wasn't reused")
	}
	releases = append(releases, release)
}

// Removing a holder leaves the registry alone once another holder owns the address.
func TestRemoveTCPHolder(t *testing.T) {
	newHolder := func() *TCPHolder {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.Close() })

		return &TCPHolder{Listener: l}
	}

	state := NewState()
	mine, other := newHolder(), newHolder()

	state.TCPListeners.Store("addr", mine)
	state.Listeners.Store("addr", mine.Listener)
	RemoveTCPHolder(state, "addr", mine)

	if _, ok := state.TCPListeners.Load("addr"); ok {
		t.Error("the holder is still registered")
	}
	if _, err := mine.Listener.Accept(); err == nil {
		t.Error("the listener is still open")
	}

	state.TCPListeners.Store("addr", other)
	state.Listeners.Store("addr", other.Listener)
	RemoveTCPHolder(state, "addr", mine)

	if registered, _ := state.TCPListeners.Load("addr"); registered != other {
		t.Error("another holder's registration was removed")
	}
}

// Characters that would end the host, path or credentials in a URL don't make it into a binding.
func TestGetOpenHostRejectsURLBreakingNames(t *testing.T) {
	namedBindingConfig(t)

	for _, requested := range []string{"evil.com?", "evil.com#", `evil.com\`, "evil com", "evil.com:443"} {
		hostURL, _ := GetOpenHost(requested, NewState(), newTestSSHConnection())
		if hostURL != nil && !strings.HasSuffix(hostURL.Host, ".example.com") {
			t.Errorf("%q was given %s", requested, hostURL.Host)
		}
		if hostURL != nil && strings.HasPrefix(hostURL.Host, "evil") {
			t.Errorf("%q kept its name: %s", requested, hostURL.Host)
		}
	}

	for _, requested := range []string{"app/x#", "app/x?y", `app/x\y`, "evil.com:443/x@app", "u/x:p@app", "u:p#@app"} {
		if hostURL, _ := GetOpenHost(requested, NewState(), newTestSSHConnection()); hostURL != nil {
			t.Errorf("%q was bound as %s", requested, hostURL.String())
		}
	}

	if hostURL, _ := GetOpenHost("user:p4ss@app/api/v1", NewState(), newTestSSHConnection()); hostURL == nil || hostURL.Host != "app.example.com" {
		t.Errorf("a valid binding was refused: %v", hostURL)
	}
}

func ownedTestSSHConnection(fingerprint string) *SSHConnection {
	conn := newTestSSHConnection()
	conn.SSHConn = &ssh.ServerConn{Permissions: &ssh.Permissions{Extensions: map[string]string{"pubKeyFingerprint": fingerprint}}}
	return conn
}

func TestSameOwner(t *testing.T) {
	if !SameOwner(ownedTestSSHConnection("SHA256:a"), ownedTestSSHConnection("SHA256:a")) {
		t.Error("connections with the same key didn't match")
	}
	if SameOwner(ownedTestSSHConnection("SHA256:a"), ownedTestSSHConnection("SHA256:b")) {
		t.Error("connections with different keys matched")
	}
	if SameOwner(ownedTestSSHConnection(""), ownedTestSSHConnection("")) {
		t.Error("connections without a key matched")
	}
	if SameOwner(newTestSSHConnection(), newTestSSHConnection()) {
		t.Error("connections without an SSH conn matched")
	}
}

// One user can serve raw TLS on 443 and plain HTTP on 80 for the same name.
// Another user still can't take either side.
func TestSNIAndHTTPShareOwnName(t *testing.T) {
	namedBindingConfig(t)

	owner := ownedTestSSHConnection("SHA256:owner")
	other := ownedTestSSHConnection("SHA256:other")
	const name = "*.apps.example.com"

	newSNI := func(t *testing.T, state *State) *TCPHolder {
		tH := storeHTTPSSNIHolder(state)
		lb, err := roundrobin.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := lb.UpsertServer(&url.URL{Host: base64.StdEncoding.EncodeToString([]byte("sni-listener"))}); err != nil {
			t.Fatal(err)
		}
		tH.Balancers.Store(name, lb)
		tH.SSHConnections.Store("sni-listener", owner)
		return tH
	}

	t.Run("HTTP after SNI", func(t *testing.T) {
		state := NewState()
		newSNI(t, state)
		u := &url.URL{Scheme: "http", Host: name}

		if HTTPBindingTaken(state, u, owner) {
			t.Error("owner can't add HTTP for its SNI name")
		}
		if !HTTPBindingTaken(state, u, other) {
			t.Error("another user can add HTTP for the owner's SNI name")
		}
	})

	t.Run("SNI after HTTP", func(t *testing.T) {
		state := NewState()
		pH := storeHTTPHolder(t, state, "http://"+name)
		pH.SSHConnections.Store("http-listener", owner)
		tH := storeHTTPSSNIHolder(state)

		if SNINameTaken(state, tH, name, owner) {
			t.Error("owner can't add SNI for its HTTP name")
		}
		if !SNINameTaken(state, tH, name, other) {
			t.Error("another user can add SNI for the owner's HTTP name")
		}
		if !SNINameTaken(state, tH, "example.com", owner) {
			t.Error("owner can take the root domain for SNI")
		}
	})

	t.Run("SNI name served by another user", func(t *testing.T) {
		state := NewState()
		tH := newSNI(t, state)
		tH.SSHConnections.Store("sni-listener", other)

		if !HTTPBindingTaken(state, &url.URL{Scheme: "http", Host: name}, owner) {
			t.Error("owner can add HTTP for a name another user serves")
		}
	})
}
