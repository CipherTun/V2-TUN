package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DNS over HTTPS for the resolver pool ("https://host[:port][/path]" in the
// resolver list). It goes over port 443, which is open on networks that block
// or redirect plain DNS (port 53) and DNS over TLS (port 853), so it is the
// entry that still works when the others time out. The Go resolver cannot speak
// DoH itself; dohConn is a stream conn that takes the length-prefixed query it
// writes, POSTs it (RFC 8484) and hands the answer back with its length
// prefix, which is how the resolver talks to a DNS-over-TCP server.

// dohTimeout bounds one query, including the TLS connection it may open.
const dohTimeout = 5 * time.Second

// dohMaxAnswer is the longest DoH answer taken (a DNS message is 64 KB at most).
const dohMaxAnswer = 64 << 10

// dohBootstrap holds addresses for well-known DoH host names. Reaching these
// needs no lookup, and a lookup here would go to the very resolver that is
// being set up. Other host names are dialed normally; an IP literal in the
// entry ("https://1.1.1.1/dns-query") always works.
var dohBootstrap = map[string][]string{
	"dns.google":         {"8.8.8.8", "8.8.4.4"},
	"cloudflare-dns.com": {"1.1.1.1", "1.0.0.1"},
	"dns.quad9.net":      {"9.9.9.9", "149.112.112.112"},
}

// dohEndpoint is one DNS-over-HTTPS server.
type dohEndpoint struct {
	url string
	hc  *http.Client
}

func newDoHEndpoint(u *url.URL) *dohEndpoint {
	tr := &http.Transport{
		DialContext:         dohDial,
		TLSHandshakeTimeout: dohTimeout,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &dohEndpoint{url: u.String(), hc: &http.Client{Transport: tr}}
}

// dohDial opens the TCP connection to a DoH server on a protected socket, so it
// never loops into the VPN.
func dohDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: dohTimeout, Control: controlFn}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if ips, ok := dohBootstrap[strings.ToLower(host)]; ok {
			var last error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		}
	}
	return d.DialContext(ctx, network, addr)
}

// query POSTs one DNS message and returns the answer message.
func (e *dohEndpoint) query(ctx context.Context, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := e.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: %s answered %s", req.URL.Host, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(b) < 12 || len(b) > dohMaxAnswer {
		return nil, errors.New("doh: the answer is not a DNS message")
	}
	return b, nil
}

type dohResult struct {
	data []byte // the answer with its 2-byte length prefix
	err  error
}

// dohConn adapts a DoH endpoint to the stream conn the Go resolver expects.
// It carries one query at a time per conn, like the resolver uses it.
type dohConn struct {
	ep   *dohEndpoint
	pool *dnsPool
	idx  int

	ctx    context.Context
	cancel context.CancelFunc
	res    chan dohResult
	got    atomic.Bool

	mu      sync.Mutex
	pending []byte // bytes written, until a whole query is there
	buf     []byte // the answer not read yet
	rd      time.Time
}

func newDoHConn(ep *dohEndpoint, pool *dnsPool, idx int) *dohConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &dohConn{ep: ep, pool: pool, idx: idx, ctx: ctx, cancel: cancel, res: make(chan dohResult, 4)}
}

// Write takes the length-prefixed query(ies) of the DNS-over-TCP framing.
func (c *dohConn) Write(b []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	c.pending = append(c.pending, b...)
	var queries [][]byte
	for len(c.pending) >= 2 {
		n := int(c.pending[0])<<8 | int(c.pending[1])
		if len(c.pending) < 2+n {
			break
		}
		queries = append(queries, append([]byte(nil), c.pending[2:2+n]...))
		c.pending = c.pending[2+n:]
	}
	c.mu.Unlock()
	for _, q := range queries {
		go c.exchange(q)
	}
	return len(b), nil
}

func (c *dohConn) exchange(q []byte) {
	ans, err := c.ep.query(c.ctx, q)
	var r dohResult
	if err != nil {
		if c.pool != nil {
			c.pool.fail(c.idx)
		}
		r.err = err
	} else {
		framed := make([]byte, 2+len(ans))
		framed[0], framed[1] = byte(len(ans)>>8), byte(len(ans))
		copy(framed[2:], ans)
		c.got.Store(true)
		r.data = framed
	}
	select {
	case c.res <- r:
	case <-c.ctx.Done():
	}
}

func (c *dohConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.buf) > 0 {
		n := copy(b, c.buf)
		c.buf = c.buf[n:]
		c.mu.Unlock()
		return n, nil
	}
	rd := c.rd
	c.mu.Unlock()
	var expire <-chan time.Time
	if !rd.IsZero() {
		t := time.NewTimer(time.Until(rd))
		defer t.Stop()
		expire = t.C
	}
	select {
	case r := <-c.res:
		if r.err != nil {
			return 0, r.err
		}
		n := copy(b, r.data)
		c.mu.Lock()
		c.buf = append(c.buf[:0], r.data[n:]...)
		c.mu.Unlock()
		return n, nil
	case <-expire:
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	}
}

func (c *dohConn) Close() error {
	c.cancel()
	if !c.got.Load() && c.pool != nil {
		c.pool.fail(c.idx)
	}
	return nil
}

func (c *dohConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *dohConn) SetWriteDeadline(time.Time) error { return nil }
func (c *dohConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *dohConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *dohConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rd = t
	c.mu.Unlock()
	return nil
}
