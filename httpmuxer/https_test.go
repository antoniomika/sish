package httpmuxer

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/antoniomika/syncmap"
	"github.com/jpillora/ipfilter"
	"github.com/vulcand/oxy/v2/roundrobin"
)

func newTestProxyListener(t *testing.T, helloTimeout time.Duration) (*proxyListener, string) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	state := utils.NewState()
	state.IPFilter = ipfilter.NewNoDB(ipfilter.Options{})

	pL := &proxyListener{
		Listener: l,
		Holder: &utils.TCPHolder{
			SSHConnections: syncmap.New[string, *utils.SSHConnection](),
			Balancers:      syncmap.New[string, *roundrobin.RoundRobin](),
			SNIProxy:       true,
			HTTPS:          true,
		},
		State:        state,
		HelloTimeout: helloTimeout,
	}
	t.Cleanup(func() { _ = pL.Close() })

	return pL, l.Addr().String()
}

func acceptWithin(t *testing.T, pL *proxyListener, d time.Duration) net.Conn {
	t.Helper()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := pL.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	case <-time.After(d):
		t.Fatal("accept didn't return")
		return nil
	}
}

// A client that never sends a TLS hello doesn't hold up the clients after it.
func TestProxyListenerIdleClientDoesNotBlock(t *testing.T) {
	pL, addr := newTestProxyListener(t, 0)

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()

	active, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = active.Close() }()

	if _, err := active.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	conn := acceptWithin(t, pL, 2*time.Second)

	// The peeked bytes are still there for the server.
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
		t.Errorf("read %q, %v", got, err)
	}
}

// A client that never sends a TLS hello is handed on once the read header timeout passes.
func TestProxyListenerHelloTimeout(t *testing.T) {
	pL, addr := newTestProxyListener(t, 100*time.Millisecond)

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idle.Close() }()

	acceptWithin(t, pL, 2*time.Second)
}

// Closing the listener ends a pending Accept.
func TestProxyListenerClose(t *testing.T) {
	pL, _ := newTestProxyListener(t, 0)

	done := make(chan error, 1)
	go func() {
		_, err := pL.Accept()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	_ = pL.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("accept returned no error after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("accept didn't return after close")
	}
}

// failingListener fails its first Accept calls the way a full file descriptor table does.
type failingListener struct {
	net.Listener
	failures int
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.failures > 0 {
		l.failures--
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: errors.New("too many open files")}
	}

	return l.Listener.Accept()
}

// An accept error that passes doesn't stop the listener.
func TestProxyListenerSurvivesAcceptErrors(t *testing.T) {
	pL, addr := newTestProxyListener(t, 0)
	pL.Listener = &failingListener{Listener: pL.Listener, failures: 3}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	acceptWithin(t, pL, 5*time.Second)
}
