package transport

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// dnsRetryPrimary is how long the resolver stays on a fallback server before it
// tries the first one again.
const dnsRetryPrimary = 30 * time.Second

// NewResolver returns a resolver that asks server over protected sockets, so
// hostname lookups never loop back into the VPN.
//
// server is "1.1.1.1:53", or a list of resolvers separated by commas or
// spaces. The first is used until it fails to answer, then the next one, and
// the first is tried again after 30 seconds. An entry is "host:port" for plain
// DNS (port 53 when left out) or "tls://host[:port]" for DNS over TLS (port
// 853 by default), for example "1.1.1.1:53,tls://dns.google,8.8.4.4".
func NewResolver(server string) *net.Resolver {
	list := parseDNSServers(server)
	if len(list) == 0 {
		return nil
	}
	if len(list) == 1 && !list[0].tls {
		addr := list[0].addr
		return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second, Control: controlFn}
			return d.DialContext(ctx, network, addr)
		}}
	}
	p := &dnsPool{servers: list}
	return &net.Resolver{PreferGo: true, Dial: p.dial}
}

type dnsServer struct {
	addr string // host:port
	name string // TLS server name (DNS over TLS only)
	tls  bool
}

// parseDNSServers reads the server list; entries it cannot use are skipped.
func parseDNSServers(s string) []dnsServer {
	var out []dnsServer
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		useTLS := false
		if rest, ok := strings.CutPrefix(f, "tls://"); ok {
			f, useTLS = rest, true
		}
		if f == "" {
			continue
		}
		host, port, err := net.SplitHostPort(f)
		if err != nil { // no port
			host, port = strings.Trim(f, "[]"), "53"
			if useTLS {
				port = "853"
			}
		}
		if host == "" {
			continue
		}
		srv := dnsServer{addr: net.JoinHostPort(host, port), tls: useTLS}
		if useTLS {
			srv.name = host
		}
		out = append(out, srv)
	}
	return out
}

// dnsPool keeps the resolvers in order and moves on to the next one when the
// current one answers nothing.
type dnsPool struct {
	servers  []dnsServer
	mu       sync.Mutex
	cur      int
	switched time.Time
}

func (p *dnsPool) pick() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur != 0 && time.Since(p.switched) > dnsRetryPrimary {
		p.cur = 0
	}
	return p.cur
}

func (p *dnsPool) fail(idx int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cur == idx && len(p.servers) > 1 {
		p.cur = (idx + 1) % len(p.servers)
		p.switched = time.Now()
	}
}

func (p *dnsPool) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	idx := p.pick()
	s := p.servers[idx]
	d := net.Dialer{Timeout: 5 * time.Second, Control: controlFn}
	var c net.Conn
	var err error
	if s.tls {
		c, err = dialDoT(ctx, &d, s)
	} else {
		c, err = d.DialContext(ctx, network, s.addr)
	}
	if err != nil {
		p.fail(idx)
		return nil, err
	}
	// The Go resolver frames a query for UDP when the conn is a net.PacketConn
	// and for a stream otherwise, so a UDP conn must stay one.
	if u, ok := c.(*net.UDPConn); ok {
		return &dnsPacketConn{UDPConn: u, pool: p, idx: idx}, nil
	}
	return &dnsStreamConn{Conn: c, pool: p, idx: idx}, nil
}

// dialDoT opens a TLS connection to a DNS over TLS server. The conn is a
// stream, so the Go resolver uses TCP framing on it whatever network it asked for.
func dialDoT(ctx context.Context, d *net.Dialer, s dnsServer) (net.Conn, error) {
	raw, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: s.name})
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// dnsStreamConn and dnsPacketConn tell the pool whether a server answered: a
// conn closed without a single byte read counts as a failure of that server.
type dnsStreamConn struct {
	net.Conn
	pool *dnsPool
	idx  int
	got  atomic.Bool
}

func (c *dnsStreamConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.got.Store(true)
	}
	return n, err
}

func (c *dnsStreamConn) Close() error {
	if !c.got.Load() {
		c.pool.fail(c.idx)
	}
	return c.Conn.Close()
}

type dnsPacketConn struct {
	*net.UDPConn
	pool *dnsPool
	idx  int
	got  atomic.Bool
}

func (c *dnsPacketConn) Read(b []byte) (int, error) {
	n, err := c.UDPConn.Read(b)
	if n > 0 {
		c.got.Store(true)
	}
	return n, err
}

func (c *dnsPacketConn) Close() error {
	if !c.got.Load() {
		c.pool.fail(c.idx)
	}
	return c.UDPConn.Close()
}
