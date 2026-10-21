package wsinspect

import (
	"io"
	"net/http"
	"sync"
)

// Direction names the side of the connection that sent a message.
type Direction string

const (
	FromClient Direction = "client"
	FromServer Direction = "server"
)

// Handler receives what Conn sees. Message and Error are called from the
// connection's copy goroutines, so they must not block.
type Handler struct {
	Message func(Direction, Message)
	Error   func(Direction, error)
	Close   func()
}

// Conn wraps the backend side of an upgraded connection. Reads carry the
// server's frames and writes carry the client's. Bytes pass through unchanged.
type Conn struct {
	backend io.ReadWriteCloser
	handler Handler

	client, server                 *parser
	clientReported, serverReported bool

	closeOnce sync.Once
}

// NewConn wraps backend, keeping up to limit bytes of each message (all of it if limit is negative).
// header is the handshake response, which says whether messages are compressed.
func NewConn(backend io.ReadWriteCloser, header http.Header, limit int, handler Handler) *Conn {
	var clientInflater, serverInflater *inflater
	if deflate, clientTakeover, serverTakeover := Extensions(header); deflate {
		clientInflater = newInflater(clientTakeover)
		serverInflater = newInflater(serverTakeover)
	}

	return &Conn{
		backend: backend,
		handler: handler,
		client:  newParser(limit, clientInflater),
		server:  newParser(limit, serverInflater),
	}
}

func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.backend.Read(b)
	if n > 0 {
		c.feed(FromServer, c.server, &c.serverReported, b[:n])
	}

	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.backend.Write(b)
	if n > 0 {
		c.feed(FromClient, c.client, &c.clientReported, b[:n])
	}

	return n, err
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.handler.Close != nil {
			c.handler.Close()
		}
	})

	return c.backend.Close()
}

// feed is only called from one goroutine per direction, so each parser has a single user.
func (c *Conn) feed(dir Direction, p *parser, reported *bool, b []byte) {
	if *reported {
		return
	}

	for _, msg := range p.Feed(b) {
		if c.handler.Message != nil {
			c.handler.Message(dir, msg)
		}
	}

	if err := p.Err(); err != nil {
		*reported = true
		if c.handler.Error != nil {
			c.handler.Error(dir, err)
		}
	}
}
