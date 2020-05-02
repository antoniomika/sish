package utils

import (
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHConnection handles state for a SSHConnection
type SSHConnection struct {
	SSHConn        *ssh.ServerConn
	Listeners      *sync.Map
	Close          chan bool
	Messages       chan string
	ProxyProto     byte
	Session        chan bool
	CleanupHandler bool
}

// SendMessage sends a console message to the connection
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

// CleanUp closes all allocated resources and cleans them up
func (s *SSHConnection) CleanUp(state *State) {
	close(s.Close)
	s.SSHConn.Close()
	state.SSHConnections.Delete(s.SSHConn.RemoteAddr())
	log.Println("Closed SSH connection for:", s.SSHConn.RemoteAddr(), "user:", s.SSHConn.User())
}
