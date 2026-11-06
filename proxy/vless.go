package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"io.surprise.vpn/transport"
)

// VLESS supports plaintext (no TLS in the chain) as well as TLS.
// Flow "xtls-rprx-vision" enables XTLS Vision for TCP; it needs a TLS or
// REALITY layer over plain TCP with a transport.RecordDialer directly below it.
type VLESS struct {
	Server string
	Dialer transport.Dialer
	UUID   string
	Flow   string
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
	vision := cmd == 1 && strings.HasPrefix(strings.ToLower(v.Flow), visionFlow)
	c, err := v.Dialer.DialContext(ctx, "tcp", v.Server)
	if err != nil {
		return nil, err
	}
	var rc *transport.RecordConn
	var addons []byte
	if vision {
		if rc = findRecordConn(c); rc == nil {
			c.Close()
			return nil, errors.New("vless: flow xtls-rprx-vision needs TLS or REALITY over plain TCP")
		}
		addons = append([]byte{0x0a, byte(len(v.Flow))}, v.Flow...) // protobuf: field 1 = flow
	}
	hdr := []byte{0}            // version
	hdr = append(hdr, id[:]...) // user id
	hdr = append(hdr, byte(len(addons)))
	hdr = append(hdr, addons...)
	hdr = append(hdr, cmd) // 1 tcp, 2 udp, 3 mux
	if cmd != 3 {
		hdr = append(hdr, a.vless()...)
	}
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	vc := &vlessConn{Conn: c}
	if vision {
		return newVisionConn(vc, id[:], rc), nil
	}
	return vc, nil
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
