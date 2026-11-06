package transport

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// maxRecordLen is the largest TLS record body we accept: 2^14 plaintext plus
// the allowance TLS 1.3 / 1.2 give for expansion (RFC 8446 section 5.2).
const maxRecordLen = 16384 + 2048

// RecordConn sits directly on the socket, below a (u)TLS layer, and hands the
// TLS layer exactly one TLS record per Read. Because it never returns bytes
// from beyond the current record, the TLS layer cannot buffer past a record
// boundary, which is what lets XTLS Vision switch to "direct copy": after the
// inner connection's last padded frame the caller calls Detach, and every
// later Read comes straight from the socket instead of being parsed as records.
//
// Writes pass through untouched. Read must be called by one goroutine at a
// time (as with any net.Conn used by a single reader); Detach may be called
// from that same goroutine or any other.
type RecordConn struct {
	net.Conn

	detached atomic.Bool
	pending  []byte // the rest of the record currently being handed out
	hdr      [5]byte
}

// NewRecordConn wraps c.
func NewRecordConn(c net.Conn) *RecordConn { return &RecordConn{Conn: c} }

// NetConn returns the wrapped connection.
func (c *RecordConn) NetConn() net.Conn { return c.Conn }

// Detach stops record framing: later reads go straight to the socket. Bytes
// of the current record that were already read are still returned first.
func (c *RecordConn) Detach() { c.detached.Store(true) }

// Detached reports whether Detach has been called.
func (c *RecordConn) Detached() bool { return c.detached.Load() }

func (c *RecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		return c.drain(p), nil
	}
	if c.detached.Load() {
		return c.Conn.Read(p)
	}
	if _, err := io.ReadFull(c.Conn, c.hdr[:]); err != nil {
		return 0, err
	}
	// type 20..24 (ccs, alert, handshake, application data, heartbeat), version 3.x
	if t := c.hdr[0]; t < 20 || t > 24 || c.hdr[1] != 3 {
		return 0, errors.New("transport: record conn: not a TLS record")
	}
	n := int(c.hdr[3])<<8 | int(c.hdr[4])
	if n > maxRecordLen {
		return 0, errors.New("transport: record conn: oversized TLS record")
	}
	rec := make([]byte, 5+n)
	copy(rec, c.hdr[:])
	if _, err := io.ReadFull(c.Conn, rec[5:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	c.pending = rec
	return c.drain(p), nil
}

func (c *RecordConn) drain(p []byte) int {
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n
}
