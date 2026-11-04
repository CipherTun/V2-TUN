package transport

import (
	"context"
	"math/rand"
	"net"
	"time"
)

// Fragment splits the first TLS ClientHello into small TCP segments with
// short pauses, which defeats SNI-based DPI. Sits directly above TCP.
type Fragment struct {
	Inner            Dialer
	LenMin, LenMax   int // bytes per fragment
	IntMin, IntMax   int // ms between fragments
}

func (d *Fragment) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &fragConn{Conn: c, f: d}, nil
}

type fragConn struct {
	net.Conn
	f    *Fragment
	done bool
}

func between(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rand.Intn(hi-lo+1)
}

func (c *fragConn) Write(p []byte) (int, error) {
	if c.done || len(p) < 6 || p[0] != 0x16 || p[1] != 0x03 {
		return c.Conn.Write(p)
	}
	c.done = true
	total := 0
	for len(p) > 0 {
		n := between(c.f.LenMin, c.f.LenMax)
		if n < 1 {
			n = 1
		}
		if n > len(p) {
			n = len(p)
		}
		w, err := c.Conn.Write(p[:n])
		total += w
		if err != nil {
			return total, err
		}
		p = p[n:]
		if len(p) > 0 {
			time.Sleep(time.Duration(between(c.f.IntMin, c.f.IntMax)) * time.Millisecond)
		}
	}
	return total, nil
}
