package transport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// WebSocket upgrades Inner to WebSocket (or raw HTTPUpgrade when Upgrade is true).
type WebSocket struct {
	Inner   Dialer
	Host    string
	Path    string
	Headers map[string]string
	Upgrade bool // true => httpupgrade (no framing after handshake)
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func (d *WebSocket) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host := d.Host
	if host == "" {
		host, _, _ = net.SplitHostPort(addr)
	}
	path := d.Path
	if path == "" {
		path = "/"
	}
	kb := make([]byte, 16)
	rand.Read(kb)
	key := base64.StdEncoding.EncodeToString(kb)
	proto := "websocket"
	if d.Upgrade {
		proto = "websocket"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n",
		path, host, proto, key)
	for k, v := range d.Headers {
		req += k + ": " + v + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		c.Close()
		return nil, fmt.Errorf("websocket: upgrade failed (%v, %v)", resp, err)
	}
	if !d.Upgrade {
		sum := sha1.Sum([]byte(key + wsGUID))
		if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
			c.Close()
			return nil, errors.New("websocket: bad accept key")
		}
		return &wsConn{Conn: c, br: br}, nil
	}
	return &bufConn{Conn: c, br: br}, nil
}

type bufConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.br.Read(p) }

type wsConn struct {
	net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
	rbuf []byte
}

func (c *wsConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, err
		}
		op := h[0] & 0x0f
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(c.br, e[:]); err != nil {
				return 0, err
			}
			n = uint64(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(c.br, e[:]); err != nil {
				return 0, err
			}
			n = binary.BigEndian.Uint64(e[:])
		}
		var mask [4]byte
		masked := h[1]&0x80 != 0
		if masked {
			if _, err := io.ReadFull(c.br, mask[:]); err != nil {
				return 0, err
			}
		}
		if n > 1<<24 {
			return 0, errors.New("websocket: frame too large")
		}
		pl := make([]byte, n)
		if _, err := io.ReadFull(c.br, pl); err != nil {
			return 0, err
		}
		if masked {
			for i := range pl {
				pl[i] ^= mask[i%4]
			}
		}
		switch op {
		case 0, 1, 2:
			c.rbuf = pl
		case 8:
			return 0, io.EOF
		case 9:
			c.writeFrame(0xA, pl)
		}
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

func (c *wsConn) writeFrame(op byte, p []byte) error {
	hdr := []byte{0x80 | op}
	switch l := len(p); {
	case l < 126:
		hdr = append(hdr, 0x80|byte(l))
	case l < 65536:
		hdr = append(hdr, 0x80|126, byte(l>>8), byte(l))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(l))
	}
	var mask [4]byte
	rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	out := make([]byte, len(hdr)+len(p))
	copy(out, hdr)
	for i, b := range p {
		out[len(hdr)+i] = b ^ mask[i%4]
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.Conn.Write(out)
	return err
}

func (c *wsConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 32768 {
			n = 32768
		}
		if err := c.writeFrame(2, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
