package wsinspect

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// frame builds one raw frame. A non-nil mask masks the payload the way a client must.
func frame(fin bool, opcode byte, rsv1 bool, mask []byte, payload []byte) []byte {
	b0 := opcode
	if fin {
		b0 |= 0x80
	}
	if rsv1 {
		b0 |= 0x40
	}

	out := []byte{b0}

	var b1 byte
	if mask != nil {
		b1 = 0x80
	}

	switch n := len(payload); {
	case n <= 125:
		out = append(out, b1|byte(n))
	case n <= 0xffff:
		out = append(out, b1|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, b1|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}

	if mask != nil {
		out = append(out, mask...)
		for i, c := range payload {
			out = append(out, c^mask[i%4])
		}
		return out
	}

	return append(out, payload...)
}

var testMask = []byte{0x12, 0x34, 0x56, 0x78}

func feedAll(p *parser, data []byte, chunk int) []Message {
	var out []Message
	for len(data) > 0 {
		n := min(chunk, len(data))
		out = append(out, p.Feed(data[:n])...)
		data = data[n:]
	}
	return out
}

func TestParserSplitReads(t *testing.T) {
	data := append(frame(true, OpText, false, testMask, []byte("hello")), frame(true, OpBinary, false, testMask, []byte{1, 2, 3})...)

	for _, chunk := range []int{1, 2, 3, 7, len(data)} {
		msgs := feedAll(newParser(-1, nil), data, chunk)
		if len(msgs) != 2 {
			t.Fatalf("chunk %d: got %d messages, want 2", chunk, len(msgs))
		}
		if msgs[0].Opcode != OpText || string(msgs[0].Payload) != "hello" {
			t.Errorf("chunk %d: first message = %v %q", chunk, msgs[0].Opcode, msgs[0].Payload)
		}
		if msgs[1].Opcode != OpBinary || !bytes.Equal(msgs[1].Payload, []byte{1, 2, 3}) {
			t.Errorf("chunk %d: second message = %v %v", chunk, msgs[1].Opcode, msgs[1].Payload)
		}
	}
}

func TestParserLengthForms(t *testing.T) {
	for _, size := range []int{0, 125, 126, 65535, 65536, 70000} {
		payload := bytes.Repeat([]byte{'x'}, size)
		for _, mask := range [][]byte{nil, testMask} {
			msgs := feedAll(newParser(-1, nil), frame(true, OpBinary, false, mask, payload), 4096)
			if len(msgs) != 1 || msgs[0].Size != int64(size) || !bytes.Equal(msgs[0].Payload, payload) {
				t.Errorf("size %d masked=%v: got %d messages", size, mask != nil, len(msgs))
			}
		}
	}
}

func TestParserFragmentedWithPing(t *testing.T) {
	var data []byte
	data = append(data, frame(false, OpText, false, testMask, []byte("hel"))...)
	data = append(data, frame(true, OpPing, false, testMask, []byte("are you there"))...)
	data = append(data, frame(false, OpContinuation, false, testMask, []byte("lo, "))...)
	data = append(data, frame(true, OpContinuation, false, testMask, []byte("world"))...)

	msgs := feedAll(newParser(-1, nil), data, 5)
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Opcode != OpPing || string(msgs[0].Payload) != "are you there" {
		t.Errorf("first message = %v %q, want the ping", msgs[0].Opcode, msgs[0].Payload)
	}
	if msgs[1].Opcode != OpText || string(msgs[1].Payload) != "hello, world" {
		t.Errorf("second message = %v %q, want the joined text", msgs[1].Opcode, msgs[1].Payload)
	}
}

func TestParserClose(t *testing.T) {
	payload := binary.BigEndian.AppendUint16(nil, 1001)
	payload = append(payload, "going away"...)

	msgs := newParser(-1, nil).Feed(frame(true, OpClose, false, nil, payload))
	if len(msgs) != 1 || msgs[0].CloseCode != 1001 || msgs[0].CloseReason != "going away" {
		t.Fatalf("got %+v", msgs)
	}
}

func TestParserTruncates(t *testing.T) {
	payload := []byte(strings.Repeat("abcdef", 10))

	msgs := feedAll(newParser(8, nil), frame(true, OpText, false, testMask, payload), 3)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if string(msgs[0].Payload) != "abcdefab" || msgs[0].Size != int64(len(payload)) || !msgs[0].Truncated {
		t.Errorf("got payload %q size %d truncated %v", msgs[0].Payload, msgs[0].Size, msgs[0].Truncated)
	}
}

// compressor produces permessage-deflate payloads. With takeover it keeps one
// stream across messages, so later messages refer back to earlier ones.
type compressor struct {
	takeover bool
	buf      bytes.Buffer
	w        *flate.Writer
}

func (c *compressor) compress(t *testing.T, msg []byte) []byte {
	t.Helper()

	if c.w == nil || !c.takeover {
		c.buf.Reset()
		w, err := flate.NewWriter(&c.buf, flate.BestCompression)
		if err != nil {
			t.Fatal(err)
		}
		c.w = w
	}

	start := c.buf.Len()
	if _, err := c.w.Write(msg); err != nil {
		t.Fatal(err)
	}
	if err := c.w.Flush(); err != nil {
		t.Fatal(err)
	}

	out := append([]byte(nil), c.buf.Bytes()[start:]...)
	return bytes.TrimSuffix(out, deflateTail)
}

func TestParserDeflateContextTakeover(t *testing.T) {
	c := &compressor{takeover: true}
	first := []byte(strings.Repeat(`{"event":"price","symbol":"SISH","value":42}`, 20))
	second := []byte(`{"event":"price","symbol":"SISH","value":43}`)

	var data []byte
	data = append(data, frame(true, OpText, true, nil, c.compress(t, first))...)
	data = append(data, frame(true, OpText, true, nil, c.compress(t, second))...)

	msgs := feedAll(newParser(-1, newInflater(true)), data, 9)
	if len(msgs) != 2 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if !bytes.Equal(msgs[0].Payload, first) || !bytes.Equal(msgs[1].Payload, second) {
		t.Errorf("decoded %q and %q", msgs[0].Payload, msgs[1].Payload)
	}
	if !msgs[0].Compressed || msgs[0].Size != int64(len(first)) {
		t.Errorf("first message compressed=%v size=%d", msgs[0].Compressed, msgs[0].Size)
	}
}

func TestParserDeflateFragmented(t *testing.T) {
	c := &compressor{}
	msg := []byte(strings.Repeat("sish tunnels to localhost. ", 40))
	compressed := c.compress(t, msg)
	half := len(compressed) / 2

	var data []byte
	data = append(data, frame(false, OpText, true, testMask, compressed[:half])...)
	data = append(data, frame(true, OpContinuation, false, testMask, compressed[half:])...)

	msgs := feedAll(newParser(16, newInflater(false)), data, 11)
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	if string(msgs[0].Payload) != string(msg[:16]) || msgs[0].Size != int64(len(msg)) || !msgs[0].Truncated {
		t.Errorf("got %q size %d truncated %v", msgs[0].Payload, msgs[0].Size, msgs[0].Truncated)
	}
}

func TestParserStopsOnProtocolError(t *testing.T) {
	p := newParser(-1, nil)
	msgs := p.Feed(append(frame(true, OpText, true, nil, []byte("x")), frame(true, OpText, false, nil, []byte("y"))...))
	if len(msgs) != 0 || p.Err() == nil {
		t.Fatalf("expected an error for a compressed frame without the extension, got %v %v", msgs, p.Err())
	}

	p = newParser(-1, nil)
	p.Feed(frame(true, OpContinuation, false, nil, []byte("x")))
	if p.Err() == nil {
		t.Error("expected an error for a continuation frame with no message")
	}

	p = newParser(-1, nil)
	p.Feed(frame(false, OpPing, false, nil, []byte("x")))
	if p.Err() == nil {
		t.Error("expected an error for a fragmented ping")
	}
}

func TestExtensions(t *testing.T) {
	for value, want := range map[string][3]bool{
		"":                       {false, false, false},
		"x-webkit-deflate-frame": {false, false, false},
		"permessage-deflate":     {true, true, true},
		"permessage-deflate; client_max_window_bits=10; server_no_context_takeover": {true, true, false},
		"foo, permessage-deflate;client_no_context_takeover":                        {true, false, true},
	} {
		h := http.Header{}
		if value != "" {
			h.Set("Sec-WebSocket-Extensions", value)
		}

		deflate, client, server := Extensions(h)
		if got := [3]bool{deflate, client, server}; got != want {
			t.Errorf("%q: got %v, want %v", value, got, want)
		}
	}
}

// fakeBackend serves the server's bytes on Read and records the client's bytes from Write.
type fakeBackend struct {
	fromServer *bytes.Reader
	toServer   bytes.Buffer
	closed     int
}

func (f *fakeBackend) Read(b []byte) (int, error)  { return f.fromServer.Read(b) }
func (f *fakeBackend) Write(b []byte) (int, error) { return f.toServer.Write(b) }
func (f *fakeBackend) Close() error                { f.closed++; return nil }

func TestConnPassesBytesThrough(t *testing.T) {
	serverBytes := frame(true, OpText, false, nil, []byte("from server"))
	clientBytes := frame(true, OpText, false, testMask, []byte("from client"))
	backend := &fakeBackend{fromServer: bytes.NewReader(serverBytes)}

	var mu sync.Mutex
	var got []string
	closes := 0
	conn := NewConn(backend, http.Header{}, -1, Handler{
		Message: func(dir Direction, m Message) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, string(dir)+": "+string(m.Payload))
		},
		Close: func() { closes++ },
	})

	read, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(clientBytes); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = conn.Close()

	if !bytes.Equal(read, serverBytes) || !bytes.Equal(backend.toServer.Bytes(), clientBytes) {
		t.Error("bytes were changed on the way through")
	}
	if strings.Join(got, "|") != "server: from server|client: from client" {
		t.Errorf("got messages %q", got)
	}
	if closes != 1 || backend.closed != 2 {
		t.Errorf("close hook ran %d times and backend closed %d times", closes, backend.closed)
	}
}
