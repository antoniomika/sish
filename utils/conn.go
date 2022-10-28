package utils

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
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
	SSHConn        *ssh.ServerConn
	Listeners      *syncmap.Map[string, net.Listener]
	Closed         *sync.Once
	Close          chan bool
	Exec           chan bool
	Messages       chan string
	ProxyProto     byte
	HostHeader     string
	StripPath      bool
	SNIProxy       bool
	TCPAddress     string
	TCPAlias       bool
	LocalForward   bool
	AutoClose      bool
	ForceHttps     bool
	Session        chan bool
	CleanupHandler bool
	SetupLock      *sync.Mutex
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
		s.SSHConn.Close()
		state.SSHConnections.Delete(s.SSHConn.RemoteAddr().String())
		log.Println("Closed SSH connection for:", s.SSHConn.RemoteAddr().String(), "user:", s.SSHConn.User())
	})
}

// TeeConn represents a simple net.Conn interface for SNI Processing.
type TeeConn struct {
	Conn      net.Conn
	Reader    io.Reader
	Buffer    *bytes.Buffer
	FirstRead bool
	Flushed   bool
}

// Read implements a reader ontop of the TeeReader.
func (conn *TeeConn) Read(p []byte) (int, error) {
	if !conn.FirstRead {
		conn.FirstRead = true
		return conn.Reader.Read(p)
	}

	if conn.FirstRead && !conn.Flushed {
		conn.Flushed = true
		copy(p[0:conn.Buffer.Len()], conn.Buffer.Bytes())
		return conn.Buffer.Len(), nil
	}

	return conn.Conn.Read(p)
}

// Write is a shim function to fit net.Conn.
func (conn *TeeConn) Write(p []byte) (int, error) {
	if !conn.Flushed {
		return 0, io.ErrClosedPipe
	}

	return conn.Conn.Write(p)
}

// Close is a shim function to fit net.Conn.
func (conn *TeeConn) Close() error {
	if !conn.Flushed {
		return nil
	}

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

// GetBuffer returns the tee'd buffer.
func (conn *TeeConn) GetBuffer() *bytes.Buffer { return conn.Buffer }

func NewTeeConn(conn net.Conn) *TeeConn {
	teeConn := &TeeConn{
		Conn:    conn,
		Buffer:  bytes.NewBuffer([]byte{}),
		Flushed: false,
	}

	teeConn.Reader = io.TeeReader(conn, teeConn.Buffer)

	return teeConn
}

// PeekTLSHello peeks the TLS Connection Hello to proxy based on SNI.
func PeekTLSHello(conn net.Conn) (*tls.ClientHelloInfo, *bytes.Buffer, *TeeConn, error) {
	var tlsHello *tls.ClientHelloInfo

	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			tlsHello = hello
			return nil, nil
		},
	}

	teeConn := NewTeeConn(conn)

	err := tls.Server(teeConn, tlsConfig).Handshake()

	return tlsHello, teeConn.GetBuffer(), teeConn, err
}

// IdleTimeoutConn handles the connection with a context deadline.
// code adapted from https://qiita.com/kwi/items/b38d6273624ad3f6ae79
type IdleTimeoutConn struct {
	Conn net.Conn
}

// Read is needed to implement the reader part.
func (i IdleTimeoutConn) Read(buf []byte) (int, error) {
	err := i.Conn.SetReadDeadline(time.Now().Add(viper.GetDuration("idle-connection-timeout")))
	if err != nil {
		return 0, err
	}

	return i.Conn.Read(buf)
}

// Write is needed to implement the writer part.
func (i IdleTimeoutConn) Write(buf []byte) (int, error) {
	err := i.Conn.SetWriteDeadline(time.Now().Add(viper.GetDuration("idle-connection-timeout")))
	if err != nil {
		return 0, err
	}

	return i.Conn.Write(buf)
}

// CopyBoth copies betwen a reader and writer and will cleanup each.
func CopyBoth(writer net.Conn, reader io.ReadWriteCloser) {
	closeBoth := func() {
		reader.Close()
		writer.Close()
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
		if err != nil && viper.GetBool("debug") {
			log.Println("Error copying to reader:", err)
		}

		closeBoth()
	}

	copyToWriter := func() {
		_, err := io.Copy(tcon, reader)
		if err != nil && viper.GetBool("debug") {
			log.Println("Error copying to writer:", err)
		}

		closeBoth()
	}

	go copyToReader()
	copyToWriter()
}
