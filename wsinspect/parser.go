// Package wsinspect reads the WebSocket messages passing through a proxied
// connection without changing them, so they can be shown in the service console.
package wsinspect

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Opcodes from RFC 6455 section 5.2.
const (
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xa
)

// maxCompressedMessage bounds how much of one compressed message is buffered for decoding.
const maxCompressedMessage = 8 << 20

// Message is a complete WebSocket message seen on one side of the connection.
type Message struct {
	Opcode byte
	// Payload holds up to the parser's limit of the unmasked, decompressed payload.
	Payload []byte
	// Size is the full payload size after decompression.
	Size       int64
	Truncated  bool
	Compressed bool
	// Undecoded is set when a compressed message couldn't be decompressed. Payload is then empty.
	Undecoded   bool
	CloseCode   int
	CloseReason string
}

// OpcodeName returns the lowercase name of a message opcode.
func OpcodeName(op byte) string {
	switch op {
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	default:
		return fmt.Sprintf("0x%x", op)
	}
}

// parser turns the bytes sent by one side of a WebSocket connection into messages.
// Bytes are pushed in as they pass through, so parsing never blocks the connection.
type parser struct {
	limit    int
	inflater *inflater

	header    [14]byte
	headerLen int

	inFrame   bool
	remaining uint64
	opcode    byte
	fin       bool
	masked    bool
	mask      [4]byte
	maskPos   int

	control []byte

	inMessage  bool
	msgOpcode  byte
	compressed bool
	payload    []byte
	size       int64
	truncated  bool
	overflow   bool

	err error
}

// newParser returns a parser that keeps up to limit bytes of each message's payload.
// A negative limit keeps everything. inflater is nil unless permessage-deflate was negotiated.
func newParser(limit int, inflater *inflater) *parser {
	return &parser{limit: limit, inflater: inflater}
}

// Err returns the protocol error that stopped the parser, if any.
func (p *parser) Err() error {
	return p.err
}

// Feed parses the next bytes from the connection and returns any messages they complete.
// After a protocol error it ignores further input; Err reports why.
func (p *parser) Feed(b []byte) []Message {
	var out []Message

	for len(b) > 0 && p.err == nil {
		if !p.inFrame {
			b = p.readHeader(b)
			if p.err != nil || !p.inFrame {
				break
			}

			if p.remaining == 0 {
				out = p.endFrame(out)
			}

			continue
		}

		n := uint64(len(b))
		if n > p.remaining {
			n = p.remaining
		}

		chunk := b[:n]
		b = b[n:]
		p.remaining -= n

		p.consume(chunk)

		if p.remaining == 0 {
			out = p.endFrame(out)
		}
	}

	return out
}

// readHeader accumulates a frame header and returns the bytes after it.
func (p *parser) readHeader(b []byte) []byte {
	need := 2
	if p.headerLen >= 2 {
		need = headerSize(p.header[0], p.header[1])
	}

	for p.headerLen < need && len(b) > 0 {
		p.header[p.headerLen] = b[0]
		p.headerLen++
		b = b[1:]

		if p.headerLen == 2 {
			need = headerSize(p.header[0], p.header[1])
		}
	}

	if p.headerLen < need {
		return b
	}

	h := p.header[:p.headerLen]
	p.headerLen = 0

	p.fin = h[0]&0x80 != 0
	rsv1 := h[0]&0x40 != 0
	p.opcode = h[0] & 0x0f
	p.masked = h[1]&0x80 != 0
	p.maskPos = 0

	length := uint64(h[1] & 0x7f)
	pos := 2
	switch length {
	case 126:
		length = uint64(binary.BigEndian.Uint16(h[2:4]))
		pos = 4
	case 127:
		length = binary.BigEndian.Uint64(h[2:10])
		pos = 10
	}

	if p.masked {
		copy(p.mask[:], h[pos:pos+4])
	}

	if h[0]&0x30 != 0 || (rsv1 && p.inflater == nil) {
		p.err = errors.New("frame uses reserved bits that weren't negotiated")
		return b
	}

	control := p.opcode&0x8 != 0
	switch {
	case control && (!p.fin || length > 125):
		p.err = errors.New("control frame is fragmented or longer than 125 bytes")
		return b
	case control && rsv1:
		p.err = errors.New("control frame is compressed")
		return b
	case control:
		if p.opcode != OpClose && p.opcode != OpPing && p.opcode != OpPong {
			p.err = fmt.Errorf("unknown control opcode 0x%x", p.opcode)
			return b
		}
		p.control = p.control[:0]
	case p.opcode == OpContinuation:
		if !p.inMessage {
			p.err = errors.New("continuation frame without a message to continue")
			return b
		}
	case p.opcode == OpText || p.opcode == OpBinary:
		if p.inMessage {
			p.err = errors.New("new message started before the previous one finished")
			return b
		}
		p.startMessage(p.opcode, rsv1)
	default:
		p.err = fmt.Errorf("unknown data opcode 0x%x", p.opcode)
		return b
	}

	p.inFrame = true
	p.remaining = length

	return b
}

// headerSize returns the full header length given its first two bytes.
func headerSize(b0, b1 byte) int {
	size := 2
	switch b1 & 0x7f {
	case 126:
		size += 2
	case 127:
		size += 8
	}

	if b1&0x80 != 0 {
		size += 4
	}

	return size
}

func (p *parser) startMessage(opcode byte, compressed bool) {
	p.inMessage = true
	p.msgOpcode = opcode
	p.compressed = compressed
	p.payload = p.payload[:0]
	p.size = 0
	p.truncated = false
	p.overflow = false
}

// consume unmasks a chunk of frame payload and keeps what's needed of it.
func (p *parser) consume(chunk []byte) {
	if p.opcode&0x8 != 0 {
		p.control = p.appendUnmasked(p.control, chunk)
		return
	}

	if p.compressed {
		// Compressed payloads are kept whole because decoding needs all of it.
		if len(p.payload)+len(chunk) > maxCompressedMessage {
			p.overflow = true
			p.advanceMask(len(chunk))
			return
		}

		p.payload = p.appendUnmasked(p.payload, chunk)
		return
	}

	p.size += int64(len(chunk))

	keep := len(chunk)
	if p.limit >= 0 && len(p.payload)+keep > p.limit {
		keep = p.limit - len(p.payload)
		p.truncated = true
	}

	p.payload = p.appendUnmasked(p.payload, chunk[:keep])
	p.advanceMask(len(chunk) - keep)
}

func (p *parser) appendUnmasked(dst, chunk []byte) []byte {
	start := len(dst)
	dst = append(dst, chunk...)

	if p.masked {
		for i := start; i < len(dst); i++ {
			dst[i] ^= p.mask[p.maskPos&3]
			p.maskPos++
		}
	}

	return dst
}

func (p *parser) advanceMask(n int) {
	p.maskPos += n
}

// endFrame finishes the current frame and emits a message if one is complete.
func (p *parser) endFrame(out []Message) []Message {
	p.inFrame = false

	if p.opcode&0x8 != 0 {
		msg := Message{Opcode: p.opcode, Payload: append([]byte(nil), p.control...), Size: int64(len(p.control))}
		if p.opcode == OpClose && len(p.control) >= 2 {
			msg.CloseCode = int(binary.BigEndian.Uint16(p.control[:2]))
			msg.CloseReason = string(p.control[2:])
		}

		return append(out, msg)
	}

	if !p.fin {
		return out
	}

	p.inMessage = false

	msg := Message{Opcode: p.msgOpcode, Compressed: p.compressed}
	if p.compressed {
		var decoded []byte
		var size int64
		var err error

		if p.overflow {
			p.inflater.fail()
			err = errors.New("compressed message is too large to decode")
		} else {
			decoded, size, err = p.inflater.inflate(p.payload, p.limit)
		}

		if err != nil {
			msg.Undecoded = true
			msg.Size = int64(len(p.payload))
		} else {
			msg.Payload = decoded
			msg.Size = size
			msg.Truncated = p.limit >= 0 && size > int64(p.limit)
		}
	} else {
		msg.Payload = append([]byte(nil), p.payload...)
		msg.Size = p.size
		msg.Truncated = p.truncated
	}

	if cap(p.payload) > 1<<20 {
		p.payload = nil
	}

	return append(out, msg)
}
