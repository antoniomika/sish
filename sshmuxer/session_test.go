package sshmuxer

import (
	"net"
	"testing"

	"github.com/antoniomika/sish/utils"
	"golang.org/x/crypto/ssh"
)

func startTestServer(t *testing.T) string {
	t.Helper()

	sshConfig := utils.GetSSHConfig()
	state := utils.NewState()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, state, sshConfig)
		}
	}()

	return listener.Addr().String()
}

func dialTestServer(t *testing.T, addr string) *ssh.Client {
	t.Helper()

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// A connection gets one session. Opening another, as a client multiplexing
// over a shared connection does, is rejected and leaves the first one working.
func TestSecondSessionRejected(t *testing.T) {
	addr := startTestServer(t)
	client := dialTestServer(t, addr)

	first, err := client.NewSession()
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	if err := first.Shell(); err != nil {
		t.Fatalf("first shell: %v", err)
	}

	if _, err := client.NewSession(); err == nil {
		t.Fatal("expected the second session to be rejected")
	}

	out, err := dialTestServer(t, addr).NewSession()
	if err != nil {
		t.Fatalf("server stopped accepting sessions: %v", err)
	}
	_ = out.Close()
}

// Sending both shell and exec on one session doesn't take the server down.
func TestShellThenExec(t *testing.T) {
	addr := startTestServer(t)
	client := dialTestServer(t, addr)

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := session.SendRequest("shell", true, nil); err != nil {
		t.Fatalf("shell: %v", err)
	}
	_, _ = session.SendRequest("exec", false, ssh.Marshal(struct{ Command string }{"auto-close=true"}))
	_, _ = session.SendRequest("shell", false, nil)

	out, err := dialTestServer(t, addr).NewSession()
	if err != nil {
		t.Fatalf("server stopped accepting sessions: %v", err)
	}
	_ = out.Close()
}
