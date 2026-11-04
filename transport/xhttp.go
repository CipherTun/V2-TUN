package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// XHTTP is Xray's SplitHTTP/XHTTP transport over HTTP/2.
//   stream-one: one streaming POST carries both directions.
//   packet-up : a long-lived GET downloads; uploads are sequenced POSTs
//               (path/<session>/<seq>), batched for throughput. Default for "auto".
// Padding is sent as an x_padding query parameter. Server-side details vary by
// Xray version; verify against your server and adjust here if needed.
type XHTTP struct {
	Inner   Dialer
	TLS     bool
	Host    string
	Path    string
	Mode    string
	Headers map[string]string
}

func padding() string {
	b := make([]byte, 1)
	rand.Read(b)
	n := 100 + int(b[0])*3 // 100..865 chars
	const set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	rb := make([]byte, n)
	rand.Read(rb)
	for i := range out {
		out[i] = set[int(rb[i])%len(set)]
	}
	return string(out)
}

func sessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (d *XHTTP) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := d.Inner.DialContext(ctx, network, addr)
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
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	switch strings.ToLower(d.Mode) {
	case "stream-one":
		return openH2(ctx, raw, d.TLS, host, path+"?x_padding="+padding(), d.Headers)
	case "", "auto", "packet-up":
	default:
		raw.Close()
		return nil, fmt.Errorf("xhttp: mode %q not implemented", d.Mode)
	}
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	c := &xhttpConn{raw: raw, cc: cc, host: host, base: path + sessionID(), hdr: d.Headers,
		ready: make(chan struct{}), wch: make(chan []byte, 32), closed: make(chan struct{})}
	if d.TLS {
		c.scheme = "https"
	} else {
		c.scheme = "http"
	}
	go c.download(context.WithoutCancel(ctx))
	go c.uploader(context.WithoutCancel(ctx))
	return c, nil
}

type xhttpConn struct {
	raw    net.Conn
	cc     *http2.ClientConn
	scheme string
	host   string
	base   string
	hdr    map[string]string

	ready chan struct{}
	resp  *http.Response
	rerr  error

	wch    chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	werr   error
	seq    uint64
}

func (c *xhttpConn) newReq(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := &url.URL{Scheme: c.scheme, Host: c.host, Path: path, RawQuery: "x_padding=" + padding()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (c *xhttpConn) download(ctx context.Context) {
	defer close(c.ready)
	req, err := c.newReq(ctx, "GET", c.base, nil)
	if err != nil {
		c.rerr = err
		return
	}
	resp, err := c.cc.RoundTrip(req)
	if err != nil {
		c.rerr = err
		return
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		c.rerr = fmt.Errorf("xhttp: download status %d", resp.StatusCode)
		return
	}
	c.resp = resp
}

func (c *xhttpConn) uploader(ctx context.Context) {
	for {
		var batch []byte
		select {
		case batch = <-c.wch:
		case <-c.closed:
			return
		}
	drain:
		for len(batch) < 1_000_000 {
			select {
			case more := <-c.wch:
				batch = append(batch, more...)
			default:
				break drain
			}
		}
		req, err := c.newReq(ctx, "POST", fmt.Sprintf("%s/%d", c.base, c.seq), bytes.NewReader(batch))
		if err == nil {
			c.seq++
			var resp *http.Response
			if resp, err = c.cc.RoundTrip(req); err == nil {
				if resp.StatusCode != 200 {
					err = fmt.Errorf("xhttp: upload status %d", resp.StatusCode)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		if err != nil {
			c.mu.Lock()
			c.werr = err
			c.mu.Unlock()
			return
		}
	}
}

func (c *xhttpConn) Read(p []byte) (int, error) {
	<-c.ready
	if c.rerr != nil {
		return 0, c.rerr
	}
	return c.resp.Body.Read(p)
}

func (c *xhttpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	err := c.werr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	select {
	case c.wch <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.closed:
		return 0, errors.New("xhttp: closed")
	}
}

func (c *xhttpConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		go func() {
			<-c.ready
			if c.resp != nil {
				c.resp.Body.Close()
			}
			c.raw.Close()
		}()
	})
	return nil
}

func (c *xhttpConn) LocalAddr() net.Addr              { return c.raw.LocalAddr() }
func (c *xhttpConn) RemoteAddr() net.Addr             { return c.raw.RemoteAddr() }
func (c *xhttpConn) SetDeadline(time.Time) error      { return nil }
func (c *xhttpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xhttpConn) SetWriteDeadline(time.Time) error { return nil }
