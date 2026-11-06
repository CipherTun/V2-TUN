package proxy

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"io.surprise.vpn/transport"
)

// XTLS Vision (VLESS flow "xtls-rprx-vision"), client side.
//
// While the inner connection is still in its TLS handshake, every write is
// wrapped in a padded frame, which hides the handshake's record sizes:
//
//	[16 byte user UUID, first frame only] cmd(1) contentLen(2) paddingLen(2) content padding
//
// cmd is 0 = more padded frames follow, 1 = padding ends here, 2 = the sender
// switches to "direct copy" (raw inner-TLS records on the socket, outside the
// outer TLS layer). This client never sends cmd 2 (it ends padding with cmd 1
// and keeps using the outer TLS layer for uploads), but it does follow the
// server's cmd 2: it detaches the RecordConn below the TLS layer and reads the
// rest of the downlink straight from the socket. That needs no access to TLS
// internals, because RecordConn never lets the TLS layer read past a record.
//
// Layout and padding sizes follow Xray-core (proxy/proxy.go: XtlsPadding,
// XtlsUnpadding, XtlsFilterTls). It has not been tested against a live server.

const (
	visionFlow  = "xtls-rprx-vision"
	visionBlock = 8192 - 21 // largest content bytes per frame
)

type netConner interface{ NetConn() net.Conn }

// findRecordConn walks down through (u)TLS conns to the RecordConn below.
func findRecordConn(c net.Conn) *transport.RecordConn {
	for i := 0; i < 4 && c != nil; i++ {
		if rc, ok := c.(*transport.RecordConn); ok {
			return rc
		}
		nc, ok := c.(netConner)
		if !ok {
			return nil
		}
		c = nc.NetConn()
	}
	return nil
}

type visionConn struct {
	net.Conn // the VLESS conn (strips the response header, then plain reads/writes)
	uuid     []byte
	rc       *transport.RecordConn

	// read side: one reader at a time
	rtmp    []byte
	rpad    bool // still inside the padded phase
	rdirect bool // server switched to direct copy: read the socket
	rinit   bool // first-frame UUID check pending
	rhold   []byte
	hdrLeft int
	cmd     byte
	content int
	padding int
	rout    []byte
	rerr    error

	// write side
	wmu     sync.Mutex
	wpad    bool
	wuuid   bool
	wfilter int

	// set by the reader, used by the writer
	isTLS atomic.Bool
	tls12 atomic.Bool
}

func newVisionConn(c net.Conn, uuid []byte, rc *transport.RecordConn) *visionConn {
	return &visionConn{Conn: c, uuid: append([]byte(nil), uuid...), rc: rc, rtmp: make([]byte, 16<<10),
		rpad: true, rinit: true, wpad: true, wuuid: true, wfilter: 8}
}

func (c *visionConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(c.rout) > 0 {
			n := copy(p, c.rout)
			c.rout = c.rout[n:]
			return n, nil
		}
		if c.rerr != nil {
			return 0, c.rerr
		}
		if c.rdirect {
			return c.rc.Read(p)
		}
		if !c.rpad {
			return c.Conn.Read(p)
		}
		n, err := c.Conn.Read(c.rtmp)
		if n > 0 {
			c.unpad(c.rtmp[:n])
		}
		if err != nil && len(c.rout) == 0 {
			return 0, err
		}
	}
}

// observe notes a TLS ServerHello in the unpadded downlink: from then on the
// writer knows the inner connection is TLS 1.2+ and keeps padding until the
// first application-data record.
func (c *visionConn) observe(b []byte) {
	if len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x03 && b[5] == 0x02 {
		c.tls12.Store(true)
		c.isTLS.Store(true)
	}
}

// unpad feeds raw downlink bytes through the frame state machine.
func (c *visionConn) unpad(b []byte) {
	if c.rinit {
		c.rhold = append(c.rhold, b...)
		if len(c.rhold) < 21 {
			return
		}
		b = c.rhold
		c.rhold = nil
		c.rinit = false
		if !bytes.Equal(b[:16], c.uuid) { // not Vision framed: pass everything through
			c.rpad = false
			c.rout = append(c.rout, b...)
			return
		}
		b = b[16:]
		c.hdrLeft = 5
	}
	for len(b) > 0 {
		switch {
		case c.hdrLeft > 0:
			d := b[0]
			b = b[1:]
			switch c.hdrLeft {
			case 5:
				c.cmd = d
			case 4:
				c.content = int(d) << 8
			case 3:
				c.content |= int(d)
			case 2:
				c.padding = int(d) << 8
			case 1:
				c.padding |= int(d)
			}
			c.hdrLeft--
		case c.content > 0:
			n := min(c.content, len(b))
			c.observe(b[:n])
			c.rout = append(c.rout, b[:n]...)
			b = b[n:]
			c.content -= n
		case c.padding > 0:
			n := min(c.padding, len(b))
			b = b[n:]
			c.padding -= n
		}
		if c.hdrLeft == 0 && c.content == 0 && c.padding == 0 { // frame complete
			if c.cmd == 0 {
				c.hdrLeft = 5
				continue
			}
			c.rpad = false
			if c.cmd == 2 {
				if c.rc == nil {
					c.rerr = errors.New("vision: server switched to direct copy, but this transport cannot follow it (needs TLS or REALITY over plain TCP)")
					return
				}
				c.rdirect = true
				c.rc.Detach()
			}
			c.rout = append(c.rout, b...) // bytes after the last frame are plain data
			return
		}
	}
}

func (c *visionConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.wpad {
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), visionBlock)
		if err := c.writeFrame(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
		if !c.wpad && len(p) > 0 { // padding ended: the rest goes out plain
			m, err := c.Conn.Write(p)
			return total + m, err
		}
	}
	return total, nil
}

func (c *visionConn) writeFrame(chunk []byte) error {
	if c.wfilter > 0 {
		c.wfilter--
		if len(chunk) >= 6 && chunk[0] == 0x16 && chunk[1] == 0x03 && chunk[5] == 0x01 { // inner ClientHello
			c.isTLS.Store(true)
		}
	}
	cmd := byte(0)
	switch {
	case c.isTLS.Load() && len(chunk) >= 6 && chunk[0] == 0x17 && chunk[1] == 0x03 && chunk[2] == 0x03:
		cmd = 1 // inner TLS application data: the handshake is over
	case !c.tls12.Load() && c.wfilter <= 1:
		cmd = 1 // not TLS (as far as we can tell): stop padding after a few packets
	}
	if cmd != 0 {
		c.wpad = false
	}
	padLen := 0
	if len(chunk) < 900 && c.isTLS.Load() {
		padLen = int(randInt(500)) + 900 - len(chunk)
	} else {
		padLen = int(randInt(256))
	}
	if room := 8192 - 21 - len(chunk); padLen > room {
		padLen = room
	}
	if padLen < 0 {
		padLen = 0
	}
	f := make([]byte, 0, 21+len(chunk)+padLen)
	if c.wuuid {
		f = append(f, c.uuid...)
		c.wuuid = false
	}
	f = append(f, cmd, byte(len(chunk)>>8), byte(len(chunk)), byte(padLen>>8), byte(padLen))
	f = append(f, chunk...)
	f = append(f, randBytes(padLen)...)
	_, err := c.Conn.Write(f)
	return err
}
