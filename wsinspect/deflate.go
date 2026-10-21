package wsinspect

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"net/http"
	"strings"
)

// maxWindow is the largest LZ77 window permessage-deflate allows.
const maxWindow = 32 << 10

// maxInflated bounds how much one message may decompress to.
const maxInflated = 64 << 20

// deflateTail is removed from the end of each compressed message by the sender (RFC 7692 section 7.2.1).
var deflateTail = []byte{0x00, 0x00, 0xff, 0xff}

// inflater decompresses permessage-deflate messages from one side of a connection.
type inflater struct {
	// takeover means the sender keeps its window between messages, so each message is decoded with the previous output as the dictionary.
	takeover bool
	window   []byte
	broken   bool
}

// Extensions reports whether permessage-deflate was accepted in the handshake response,
// and whether each side keeps its compression window between messages.
func Extensions(header http.Header) (deflate, clientTakeover, serverTakeover bool) {
	for _, value := range header.Values("Sec-WebSocket-Extensions") {
		for _, ext := range strings.Split(value, ",") {
			params := strings.Split(ext, ";")
			if strings.TrimSpace(params[0]) != "permessage-deflate" {
				continue
			}

			clientTakeover, serverTakeover = true, true
			for _, param := range params[1:] {
				switch strings.TrimSpace(strings.SplitN(param, "=", 2)[0]) {
				case "client_no_context_takeover":
					clientTakeover = false
				case "server_no_context_takeover":
					serverTakeover = false
				}
			}

			return true, clientTakeover, serverTakeover
		}
	}

	return false, false, false
}

func newInflater(takeover bool) *inflater {
	return &inflater{takeover: takeover}
}

// inflate decompresses one message. It returns up to limit bytes of output (all of it if limit is negative) and the full output size.
func (f *inflater) inflate(payload []byte, limit int) ([]byte, int64, error) {
	if f.broken {
		return nil, 0, errors.New("earlier message couldn't be decoded")
	}

	src := io.MultiReader(bytes.NewReader(payload), bytes.NewReader(deflateTail))

	var r io.ReadCloser
	if f.takeover && len(f.window) > 0 {
		r = flate.NewReaderDict(src, f.window)
	} else {
		r = flate.NewReader(src)
	}
	defer func() { _ = r.Close() }()

	out := &inflateOutput{limit: limit, track: f.takeover}
	if f.takeover {
		out.window = append([]byte(nil), f.window...)
	}

	_, err := io.Copy(out, io.LimitReader(r, maxInflated+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		f.fail()
		return nil, 0, err
	}

	// The sender flushes without ending the stream, so running out of input after the last block is expected.
	if out.size > maxInflated {
		f.fail()
		return nil, 0, errors.New("message decompresses to more than the inspection limit")
	}

	if f.takeover {
		f.window = out.window
	}

	return out.kept, out.size, nil
}

// fail stops decoding when the sender's window can no longer be tracked.
func (f *inflater) fail() {
	if f.takeover {
		f.broken = true
	}
}

// inflateOutput keeps the first limit bytes of output and the last window of it.
type inflateOutput struct {
	limit  int
	kept   []byte
	size   int64
	track  bool
	window []byte
}

func (o *inflateOutput) Write(b []byte) (int, error) {
	o.size += int64(len(b))

	if o.limit < 0 || len(o.kept) < o.limit {
		keep := b
		if o.limit >= 0 && len(o.kept)+len(keep) > o.limit {
			keep = keep[:o.limit-len(o.kept)]
		}
		o.kept = append(o.kept, keep...)
	}

	if !o.track {
		return len(b), nil
	}

	o.window = append(o.window, b...)
	if len(o.window) > maxWindow {
		o.window = append(o.window[:0], o.window[len(o.window)-maxWindow:]...)
	}

	return len(b), nil
}
