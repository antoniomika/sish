package sshmuxer

import (
	"net"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/vulcand/oxy/v2/roundrobin"
)

func newTestHTTPHolder(t *testing.T, raw string) *utils.HTTPHolder {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	lb, err := roundrobin.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &utils.HTTPHolder{HTTPUrl: u, SSHConnections: syncmap.New[string, *utils.SSHConnection](), Balancer: lb}
}

func newTestListenerHolder(t *testing.T) *utils.ListenerHolder {
	t.Helper()

	l, err := net.Listen("unix", filepath.Join(t.TempDir(), "l.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	return &utils.ListenerHolder{Listener: l}
}

func TestRegisterHTTPBackend(t *testing.T) {
	state := utils.NewState()
	bound := newTestHTTPHolder(t, "http://app.example.com")
	state.HTTPListeners.Store(bound.HTTPUrl.String(), bound)

	// A new holder for a host that was bound meanwhile.
	if _, _, err := registerHTTPBackend(state, newTestHTTPHolder(t, "http://app.example.com"), true, newTestListenerHolder(t), &utils.SSHConnection{}); err == nil {
		t.Error("a second holder was registered for a bound host")
	}

	// Joining a holder that was removed meanwhile.
	removed := newTestHTTPHolder(t, "http://gone.example.com")
	if _, _, err := registerHTTPBackend(state, removed, false, newTestListenerHolder(t), &utils.SSHConnection{}); err == nil {
		t.Error("a backend joined a removed holder")
	}

	if _, _, err := registerHTTPBackend(state, bound, false, newTestListenerHolder(t), &utils.SSHConnection{}); err != nil {
		t.Fatal(err)
	}
	if len(bound.Balancer.Servers()) != 1 {
		t.Error("the backend wasn't added to the balancer")
	}

	fresh := newTestHTTPHolder(t, "http://new.example.com")
	if _, _, err := registerHTTPBackend(state, fresh, true, newTestListenerHolder(t), &utils.SSHConnection{}); err != nil {
		t.Fatal(err)
	}
	if registered, _ := state.HTTPListeners.Load(fresh.HTTPUrl.String()); registered != fresh {
		t.Error("the new holder wasn't registered")
	}
}
