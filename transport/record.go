package transport

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
)

// RecordDialer wraps every conn it dials in a RecordConn. Put it directly
// below the TLS / REALITY layer when XTLS Vision is used.
type RecordDialer struct{ Inner Dialer }

func (d *RecordDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return NewRecordConn(c), nil
}

// RecordConn sits between the socket and a TLS layer. Reads return at most the
// rest of the current TLS record, so the TLS layer never pulls bytes from the
// socket that belong to the next record. XTLS Vision relies on this: when the
// server announces "direct copy", everything after the current record is raw
// inner-TLS traffic that must be read from the socket, not from the TLS layer.
// Detach switches the conn to plain pass-through reads.
type RecordConn struct {
	net.Conn
	mu       sync.Mutex
	buf      []byte // socket bytes not yet handed out
	cur      int    // bytes of the current record still to hand out (0 = at a boundary)
	detached bool
}

func NewRecordConn(c net.Conn) *RecordConn { return &RecordConn{Conn: c} }

func (c *RecordConn) fill() error {
	tmp := make([]byte, 16<<10)
	n, err := c.Conn.Read(tmp)
	c.buf = append(c.buf, tmp[:n]...)
	if n > 0 {
		return nil
	}
	return err
}

func (c *RecordConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.detached {
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		return c.Conn.Read(p)
	}
	if c.cur == 0 { // record boundary: learn the next record's length from its header
		for len(c.buf) < 5 {
			if err := c.fill(); err != nil {
				return 0, err
			}
		}
		c.cur = 5 + int(binary.BigEndian.Uint16(c.buf[3:5]))
	}
	for len(c.buf) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := len(p)
	if n > c.cur {
		n = c.cur
	}
	if n > len(c.buf) {
		n = len(c.buf)
	}
	copy(p, c.buf[:n])
	c.buf = c.buf[n:]
	c.cur -= n
	return n, nil
}

// Detach stops record framing. Later reads return the buffered bytes first,
// then whatever the socket delivers.
func (c *RecordConn) Detach() {
	c.mu.Lock()
	c.detached = true
	c.mu.Unlock()
}
