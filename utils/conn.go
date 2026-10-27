package utils

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/antoniomika/syncmap"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// SSHConnection handles state for a SSHConnection. It wraps an ssh.ServerConn
// and allows us to pass other state around the application.
type SSHConnection struct {
	SSHConn                *ssh.ServerConn
	Listeners              *syncmap.Map[string, net.Listener]
	Closed                 *sync.Once
	Close                  chan bool
	Exec                   chan bool
	Messages               chan string
	ProxyProto             byte
	HostHeader             string
	StripPath              bool
	SNIProxy               bool
	TCPAddress             string
	TCPAlias               bool
	LocalForward           bool
	TCPAliasesAllowedUsers []string
	AutoClose              bool
	ForceHTTPS             bool
	Session                chan bool
	CleanupHandler         bool
	SetupLock              *sync.Mutex
	Deadline               *time.Time
	ConnectedAt            time.Time
	sessionOnce            sync.Once
	execOnce               sync.Once
}

// OpenSession closes Session to mark the connection's session as open. A
// connection carries one session, so it returns false if one is already open.
func (s *SSHConnection) OpenSession() bool {
	opened := false
	s.sessionOnce.Do(func() {
		close(s.Session)
		opened = true
	})
	return opened
}

// ExecReceived closes Exec once the client has sent its shell or exec request.
func (s *SSHConnection) ExecReceived() {
	s.execOnce.Do(func() {
		close(s.Exec)
	})
}

// SendMessage sends a console message to the connection. If block is true, it
// will block until the message is sent. If it is false, it will try to send the
// message 5 times, waiting 100ms each time.
func (s *SSHConnection) SendMessage(message string, block bool) {
	if block {
		s.Messages <- message
		return
	}

	for i := 0; i < 5; {
		select {
		case <-s.Close:
			return
		case s.Messages <- message:
			return
		default:
			time.Sleep(100 * time.Millisecond)
			i++
		}
	}
}

// ListenerCount returns the number of current active listeners on this connection.
func (s *SSHConnection) ListenerCount() int {
	if s.LocalForward {
		return -1
	}

	count := 0

	s.Listeners.Range(func(key string, value net.Listener) bool {
		count++
		return true
	})

	return count
}

// CleanUp closes all allocated resources for a SSH session and cleans them up.
func (s *SSHConnection) CleanUp(state *State) {
	s.Closed.Do(func() {
		close(s.Close)

		err := s.SSHConn.Close()
		if err != nil {
			slog.Error(
				"error closing SSH connection",
				"error", err,
			)
		}

		state.SSHConnections.Delete(s.SSHConn.RemoteAddr().String())
		s.Logger().Info("closed SSH connection")
	})
}

// User returns the name the client authenticated as, or "" for a nil connection.
func (s *SSHConnection) User() string {
	if s == nil {
		return ""
	}

	return s.SSHConn.User()
}

// Logger returns the default logger with the connection's remote address and user.
func (s *SSHConnection) Logger() *slog.Logger {
	return slog.With(
		"remoteAddr", s.SSHConn.RemoteAddr().String(),
		"user", s.User(),
	)
}

// TeeConn represents a simple net.Conn interface for SNI Processing.
type TeeConn struct {
	Conn     net.Conn
	Buffer   *bufio.Reader
	Unbuffer bool
}

// Read implements a reader ontop of the TeeReader.
func (conn *TeeConn) Read(p []byte) (int, error) {
	if conn.Unbuffer && conn.Buffer.Buffered() > 0 {
		return conn.Buffer.Read(p)
	}
	return conn.Conn.Read(p)
}

// Write is a shim function to fit net.Conn.
func (conn *TeeConn) Write(p []byte) (int, error) {
	return conn.Conn.Write(p)
}

// Close is a shim function to fit net.Conn.
func (conn *TeeConn) Close() error {
	return conn.Conn.Close()
}

// LocalAddr is a shim function to fit net.Conn.
func (conn *TeeConn) LocalAddr() net.Addr { return conn.Conn.LocalAddr() }

// RemoteAddr is a shim function to fit net.Conn.
func (conn *TeeConn) RemoteAddr() net.Addr { return conn.Conn.RemoteAddr() }

// SetDeadline is a shim function to fit net.Conn.
func (conn *TeeConn) SetDeadline(t time.Time) error { return conn.Conn.SetDeadline(t) }

// SetReadDeadline is a shim function to fit net.Conn.
func (conn *TeeConn) SetReadDeadline(t time.Time) error { return conn.Conn.SetReadDeadline(t) }

// SetWriteDeadline is a shim function to fit net.Conn.
func (conn *TeeConn) SetWriteDeadline(t time.Time) error { return conn.Conn.SetWriteDeadline(t) }

func NewTeeConn(conn net.Conn) *TeeConn {
	teeConn := &TeeConn{
		Conn:   conn,
		Buffer: bufio.NewReaderSize(conn, 65535),
	}

	return teeConn
}

// PeekTLSHello peeks the TLS Connection Hello to proxy based on SNI.
func PeekTLSHello(conn net.Conn) (*tls.ClientHelloInfo, *TeeConn, error) {
	var tlsHello *tls.ClientHelloInfo

	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			tlsHello = hello
			return nil, nil
		},
	}

	teeConn := NewTeeConn(conn)

	header, err := teeConn.Buffer.Peek(5)
	if err != nil {
		return tlsHello, teeConn, err
	}

	if header[0] != 0x16 {
		return tlsHello, teeConn, err
	}

	helloBytes, err := teeConn.Buffer.Peek(len(header) + (int(header[3])<<8 | int(header[4])))
	if err != nil {
		return tlsHello, teeConn, err
	}

	err = tls.Server(bufConn{reader: bytes.NewReader(helloBytes)}, tlsConfig).Handshake()

	teeConn.Unbuffer = true

	return tlsHello, teeConn, err
}

type bufConn struct {
	reader io.Reader
	net.Conn
}

func (b bufConn) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (bufConn) Write(p []byte) (int, error)  { return 0, io.EOF }

// IdleTimeoutConn handles the connection with a context deadline.
// code adapted from https://qiita.com/kwi/items/b38d6273624ad3f6ae79
type IdleTimeoutConn struct {
	Conn net.Conn
}

// Read is needed to implement the reader part.
func (i IdleTimeoutConn) Read(buf []byte) (int, error) {
	err := i.Conn.SetDeadline(time.Now().Add(viper.GetDuration("idle-connection-timeout")))
	if err != nil {
		return 0, err
	}

	return i.Conn.Read(buf)
}

// Write is needed to implement the writer part.
func (i IdleTimeoutConn) Write(buf []byte) (int, error) {
	err := i.Conn.SetDeadline(time.Now().Add(viper.GetDuration("idle-connection-timeout")))
	if err != nil {
		return 0, err
	}

	return i.Conn.Write(buf)
}

// CopyBoth copies betwen a reader and writer and will cleanup each.
func CopyBoth(writer net.Conn, reader io.ReadWriteCloser) {
	closeBoth := func() {
		err := reader.Close()
		if err != nil {
			slog.Error(
				"error closing reader",
				"error", err,
			)
		}

		err = writer.Close()
		if err != nil {
			slog.Error(
				"error closing writer",
				"error", err,
			)
		}
	}

	var tcon io.ReadWriter

	if viper.GetBool("idle-connection") {
		tcon = IdleTimeoutConn{
			Conn: writer,
		}
	} else {
		tcon = writer
	}

	copyToReader := func() {
		_, err := io.Copy(reader, tcon)
		if err != nil {
			slog.Debug(
				"error copying to reader",
				"error", err,
			)
		}

		closeBoth()
	}

	copyToWriter := func() {
		_, err := io.Copy(tcon, reader)
		if err != nil {
			slog.Debug(
				"error copying to writer",
				"error", err,
			)
		}

		closeBoth()
	}

	go copyToReader()
	copyToWriter()
}
