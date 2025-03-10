package utils

import (
	"bufio"
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
