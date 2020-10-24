package utils

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// SSHConnection handles state for a SSHConnection. It wraps an ssh.ServerConn
// and allows us to pass other state around the application.
// Listeners is a map[string]net.Listener.
type SSHConnection struct {
	SSHConn        *ssh.ServerConn
	Listeners      *sync.Map
	Closed         *sync.Once
	Close          chan bool
	Messages       chan string
	ProxyProto     byte
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

// CleanUp closes all allocated resources for a SSH session and cleans them up.
func (s *SSHConnection) CleanUp(state *State) {
	s.Closed.Do(func() {
		close(s.Close)
		s.SSHConn.Close()
		state.SSHConnections.Delete(s.SSHConn.RemoteAddr().String())
		log.Println("Closed SSH connection for:", s.SSHConn.RemoteAddr().String(), "user:", s.SSHConn.User())
	})
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
