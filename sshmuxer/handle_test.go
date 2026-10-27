package sshmuxer

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/antoniomika/sish/utils"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// TestMain configures the server once for every test. The connections a test
// starts outlive it and keep reading this config, so a test that changed it
// would race with them.
func TestMain(m *testing.M) {
	// captureLog swaps handlers, so start from a real one rather than slog's
	// default, which routes through the log package.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	dir, err := os.MkdirTemp("", "sish_keys")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	viper.Set("private-keys-directory", dir)
	viper.Set("authentication", false)
	viper.Set("domain", "localhost")
	viper.Set("bind-random-subdomains", false)
	viper.Set("cleanup-unauthed", false)
	viper.Set("ping-client", false)
	viper.Set("idle-connection", false)
	viper.Set("welcome-message", "welcome")

	utils.Setup()

	code := m.Run()

	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// syncBuffer is a goroutine-safe buffer for capturing log output written
// concurrently by the server goroutines under test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the default logger's output to a buffer until the test ends.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()

	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	return buf
}

// dropConnAfterForwardRequest connects to addr, requests an HTTP remote
// forward for the given subdomain without waiting for the reply, and then
// yanks the TCP connection. The drop happens inside the server's 1s Exec
// fallback window (see handleRemoteForward), so the server ends up building
// the forward after the connection is already gone - the condition that a
// flaky network triggers in the wild.
func dropConnAfterForwardRequest(t *testing.T, addr, subdomain string) {
	t.Helper()

	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientConfig)
	if err != nil {
		_ = netConn.Close()
		t.Fatalf("ssh handshake: %v", err)
	}

	go ssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no channels")
		}
	}()

	// Fire the forward request but never wait for its reply.
	go func() {
		_, _, _ = conn.SendRequest("tcpip-forward", true,
			ssh.Marshal(&channelForwardMsg{Addr: subdomain, Rport: 80}))
	}()

	// Give the request a moment to reach the server, then drop the connection.
	time.Sleep(30 * time.Millisecond)
	_ = netConn.Close()
}

func countHTTPListeners(state *utils.State) int {
	count := 0
	state.HTTPListeners.Range(func(_ string, _ *utils.HTTPHolder) bool {
		count++
		return true
	})
	return count
}

// TestForwardingCleanupOnDroppedConn verifies that connections dropped right
// after requesting a forward do not leave behind HTTP forwarding routes. A
// leaked route keeps its subdomain permanently reserved (and is a data race on
// the deferred cleanup handler, which -race flags), so a clean run must end
// with zero HTTP listeners registered.
func TestForwardingCleanupOnDroppedConn(t *testing.T) {
	// Silence the per-connection logging this test deliberately generates.
	captureLog(t)

	sshConfig := utils.GetSSHConfig()
	state := utils.NewState()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, state, sshConfig)
		}
	}()

	addr := listener.Addr().String()

	// Each unique subdomain registers an independent HTTP route, so any leak
	// is observable. Repeat enough to reliably lose the cleanup race.
	const numConns = 40
	for i := 0; i < numConns; i++ {
		dropConnAfterForwardRequest(t, addr, fmt.Sprintf("tun%d", i))
	}

	// Every dropped connection builds its forward ~1s later (the Exec
	// fallback) and should immediately tear it down again because the
	// connection is gone. Wait past that window, then require the route table
	// to drain to zero.
	time.Sleep(2500 * time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := countHTTPListeners(state)
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d HTTP forwarding route(s) leaked: connections dropped before forwarding completed left their subdomains permanently reserved", remaining)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestForwardedTCPIPPayloadHasValidOrigin verifies that forwarded-tcpip
// channels carry a syntactically valid RFC 4254 originator address and port.
// sish used to copy the requested bind address into OriginAddr; for hostname
// binds (localhost, HTTP subdomains) that produced a non-IP value which
// strict clients such as golang.org/x/crypto/ssh reject outright, breaking
// every connection the forward was supposed to deliver.
func TestForwardedTCPIPPayloadHasValidOrigin(t *testing.T) {
	captureLog(t)

	sshConfig := utils.GetSSHConfig()
	state := utils.NewState()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, state, sshConfig)
		}
	}()

	addr := listener.Addr().String()

	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = netConn.Close() }()

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = netConn.Close()
		t.Fatalf("ssh handshake: %v", err)
	}

	go ssh.DiscardRequests(reqs)

	forwarded := make(chan ssh.NewChannel, 1)
	go func() {
		for nc := range chans {
			if nc.ChannelType() == "forwarded-tcpip" {
				forwarded <- nc
				continue
			}
			_ = nc.Reject(ssh.Prohibited, "unexpected channel")
		}
	}()

	// A hostname bind exercises the broken path: the originator address must
	// still be an IP address, not the requested hostname.
	reply := &channelForwardReply{}
	ok, payload, err := conn.SendRequest("tcpip-forward", true,
		ssh.Marshal(&channelForwardMsg{Addr: "localhost", Rport: 0}))
	if err != nil || !ok {
		t.Fatalf("forward request not accepted: ok=%v err=%v", ok, err)
	}
	if err := ssh.Unmarshal(payload, reply); err != nil || reply.Rport == 0 {
		t.Fatalf("no forwarded port assigned: reply=%+v err=%v", reply, err)
	}

	visitor, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", reply.Rport))
	if err != nil {
		t.Fatalf("dial forwarded port: %v", err)
	}
	defer func() { _ = visitor.Close() }()

	var nc ssh.NewChannel
	select {
	case nc = <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for forwarded-tcpip channel")
	}

	resp := &forwardedTCPPayload{}
	if err := ssh.Unmarshal(nc.ExtraData(), resp); err != nil {
		t.Fatalf("unmarshaling forwarded-tcpip payload: %v", err)
	}

	if parsed, err := netip.ParseAddr(resp.OriginAddr); err != nil {
		t.Fatalf("OriginAddr %q is not an IP address (RFC 4254 requires one): %v", resp.OriginAddr, err)
	} else if parsed.IsUnspecified() {
		t.Fatalf("OriginAddr %q is the unspecified address, not a real originator", resp.OriginAddr)
	}
	if resp.OriginPort == 0 || resp.OriginPort > 65535 {
		t.Fatalf("OriginPort %d out of range", resp.OriginPort)
	}

	_ = nc.Reject(ssh.Prohibited, "payload verified")
}

// TestForwardingStoppedIsLogged verifies that tearing down an established
// forward emits a "forwarding stopped" log line, mirroring the
// "forwarding started" log.
func TestForwardingStoppedIsLogged(t *testing.T) {
	logBuf := captureLog(t)

	sshConfig := utils.GetSSHConfig()
	state := utils.NewState()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, state, sshConfig)
		}
	}()

	addr := listener.Addr().String()

	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = netConn.Close()
		t.Fatalf("ssh handshake: %v", err)
	}

	go ssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, "no channels")
		}
	}()

	// Request the forward and wait for the reply: once it returns the server
	// has established the forward ("forwarding started" is logged).
	ok, _, err := conn.SendRequest("tcpip-forward", true,
		ssh.Marshal(&channelForwardMsg{Addr: "stoptest", Rport: 80}))
	if err != nil || !ok {
		t.Fatalf("forward request not accepted: ok=%v err=%v", ok, err)
	}

	// Tear the forward down by closing the connection.
	_ = netConn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logBuf.String(), "forwarding stopped") {
		if time.Now().After(deadline) {
			t.Fatalf("expected a \"forwarding stopped\" log after the connection closed; got:\n%s", logBuf.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}
