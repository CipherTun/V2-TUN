package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"io.surprise.vpn/transport"
)

// VLESS supports plaintext (no TLS in the chain) as well as TLS.
type VLESS struct {
	Server string
	Dialer transport.Dialer
	UUID   string
}

func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return u, fmt.Errorf("bad uuid")
	}
	for i := 0; i < 16; i++ {
		var b byte
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b); err != nil {
			return u, err
		}
		u[i] = b
	}
	return u, nil
}

func (v *VLESS) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return v.dial(ctx, target, 1)
}

func (v *VLESS) dial(ctx context.Context, target string, cmd byte) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	if h, _, _ := net.SplitHostPort(target); h == "v1.mux.cool" {
		cmd = 3
	}
	id, err := parseUUID(v.UUID)
	if err != nil {
		return nil, err
	}
	c, err := v.Dialer.DialContext(ctx, "tcp", v.Server)
	if err != nil {
		return nil, err
	}
	hdr := []byte{0}           // version
	hdr = append(hdr, id[:]...) // user id
	hdr = append(hdr, 0, cmd) // addons len 0; cmd 1 tcp, 2 udp
	if cmd != 3 {
		hdr = append(hdr, a.vless()...)
	}
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	return &vlessConn{Conn: c}, nil
}

// vlessConn strips the response header (version + addons) on first read.
type vlessConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *vlessConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		h := make([]byte, 2)
		if _, c.err = io.ReadFull(c.Conn, h); c.err != nil {
			return
		}
		if h[1] > 0 {
			_, c.err = io.CopyN(io.Discard, c.Conn, int64(h[1]))
		}
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}
