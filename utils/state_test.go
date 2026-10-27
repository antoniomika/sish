package utils

import (
	"net"
	"net/url"
	"testing"

	"github.com/antoniomika/syncmap"
)

func TestHTTPHolderTunnelIdOmitsPassword(t *testing.T) {
	cases := map[string]string{
		"http://dev.example.com/api":          "dev.example.com/api",
		"http://user:secret@dev.example.com/": "user@dev.example.com/",
		"https://dev.example.com:8443":        "dev.example.com",
	}

	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}

		if got := (&HTTPHolder{HTTPUrl: u}).TunnelId(); got != want {
			t.Errorf("TunnelId(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestListenerOwner(t *testing.T) {
	conns := syncmap.New[string, *SSHConnection]()

	for _, name := range []string{"a", "b"} {
		conn := &SSHConnection{Listeners: syncmap.New[string, net.Listener]()}
		conn.Listeners.Store("/tmp/"+name+".sock", nil)
		conns.Store(name, conn)
	}

	b, _ := conns.Load("b")
	if got := ListenerOwner(conns, "/tmp/b.sock"); got != b {
		t.Errorf("ListenerOwner returned %p, want %p", got, b)
	}

	if got := ListenerOwner(conns, "/tmp/missing.sock"); got != nil {
		t.Errorf("ListenerOwner returned %p for an unknown listener", got)
	}

	if got := (*SSHConnection)(nil).User(); got != "" {
		t.Errorf("nil connection User() = %q", got)
	}
}
