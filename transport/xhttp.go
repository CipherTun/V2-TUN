package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// XHTTP is Xray's XHTTP (SplitHTTP) transport. The wire behaviour follows the
// Xray-core client in transport/internet/splithttp:
//
//	stream-one  one POST to <path> carries both directions (no session id)
//	stream-up   POST <path>/<session> streams uploads, GET <path>/<session> downloads
//	packet-up   GET <path>/<session> downloads, POST <path>/<session>/<seq> uploads
//	            (batched up to ScMaxEachPostBytes, >= ScMinPostsIntervalMs apart)
//	auto        packet-up
//
// Session id and seq go in the path; padding goes in the Referer query as
// x_padding (Xray's default, non-obfuscated placement). HTTP/2 is used over TLS
// unless the ALPN list is exactly "http/1.1" (then HTTP/1.1, one connection per
// request, like Xray); without TLS it is HTTP/1.1. HTTP/3 is not supported.
type XHTTP struct {
	Inner   Dialer // TCP (+TLS) layers; the HTTP stack opens as many connections as it needs
	Server  string // "host:port" of the XHTTP server (the URL host may be a CDN name); defaults to the dial address
	TLS     bool
	SNI     string
	ALPN    []string
	Host    string
	Path    string // may carry a "?query"
	Mode    string
	Headers map[string]string

	XPaddingBytes        [2]int // default 100..1000
	ScMaxEachPostBytes   int    // default 1_000_000
	ScMinPostsIntervalMs int    // default 30

	once    sync.Once
	client  *http.Client
	initErr error
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

// setup runs once. The default server address is set here, inside the Once,
// because concurrent dials would otherwise write d.Server at the same time.
func (d *XHTTP) setup(addr string) error {
	d.once.Do(func() {
		if d.Server == "" {
			d.Server = addr
		}
		h2 := true
		switch {
		case !d.TLS:
			h2 = false
		case len(d.ALPN) == 1 && d.ALPN[0] == "http/1.1":
			h2 = false
		case len(d.ALPN) == 1 && d.ALPN[0] == "h3":
			d.initErr = errors.New("xhttp: HTTP/3 is not supported")
			return
		}
		dial := func(ctx context.Context) (net.Conn, error) {
			return d.Inner.DialContext(ctx, "tcp", d.Server)
		}
		var rt http.RoundTripper
		if h2 {
			rt = &http2.Transport{
				DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return dial(ctx)
				},
				IdleConnTimeout: 90 * time.Second,
				ReadIdleTimeout: 45 * time.Second, // Chrome's H2 keep-alive period
			}
		} else {
			rt = &http.Transport{
				DialContext:        func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
				DialTLSContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
				IdleConnTimeout:    90 * time.Second,
				DisableKeepAlives:  true, // one connection per request, like Xray's HTTP/1.1 path
				DisableCompression: true,
			}
		}
		d.client = &http.Client{Transport: rt}
	})
	return d.initErr
}

func (d *XHTTP) baseURL() *url.URL {
	u := &url.URL{Scheme: "http"}
	if d.TLS {
		u.Scheme = "https"
	}
	u.Host = d.Host
	if u.Host == "" {
		u.Host = d.SNI
	}
	if u.Host == "" {
		u.Host, _, _ = net.SplitHostPort(d.Server)
	}
	path, query, _ := strings.Cut(d.Path, "?")
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") { // session id and seq live in the path
		path += "/"
	}
	u.Path, u.RawQuery = path, query
	return u
}

func (d *XHTTP) header() http.Header {
	h := http.Header{}
	for k, v := range d.Headers {
		h.Add(k, v)
	}
	if h.Get("User-Agent") == "" {
		h.Set("User-Agent", chromeUA)
	}
	if h.Get("Accept") == "" {
		h.Set("Accept", "*/*")
	}
	if h.Get("Accept-Language") == "" {
		h.Set("Accept-Language", "en-US,en;q=0.9")
	}
	return h
}

func randBetween(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}

// applyPadding puts "x_padding=XXXX..." in the Referer query, Xray's default placement.
func (d *XHTTP) applyPadding(req *http.Request) {
	lo, hi := d.XPaddingBytes[0], d.XPaddingBytes[1]
	if hi == 0 {
		lo, hi = 100, 1000
	}
	ref := *req.URL
	ref.RawQuery = "x_padding=" + strings.Repeat("X", randBetween(lo, hi))
	req.Header.Set("Referer", ref.String())
}

func appendPath(p, v string) string {
	if strings.HasSuffix(p, "/") {
		return p + v
	}
	return p + "/" + v
}

func (d *XHTTP) newRequest(ctx context.Context, method string, base *url.URL, session, seq string, body io.Reader) (*http.Request, error) {
	u := *base
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Header = d.header()
	d.applyPadding(req) // computed from the URL before session/seq are appended
	if session != "" {
		req.URL.Path = appendPath(req.URL.Path, session)
	}
	if seq != "" {
		req.URL.Path = appendPath(req.URL.Path, seq)
	}
	return req, nil
}

func sessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type xAddr string

func (a xAddr) Network() string { return "tcp" }
func (a xAddr) String() string  { return string(a) }

func (d *XHTTP) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := d.setup(addr); err != nil {
		return nil, err
	}
	base := d.baseURL()
	mode := strings.ToLower(d.Mode)
	switch mode {
	case "", "auto":
		mode = "packet-up"
	case "packet-up", "stream-up", "stream-one":
	default:
		return nil, fmt.Errorf("xhttp: unknown mode %q", d.Mode)
	}
	session := ""
	if mode != "stream-one" {
		session = sessionID()
	}

	// The session outlives the dial context but must be cancellable on Close.
	cctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	c := &xhttpConn{d: d, base: base, session: session, cancel: cancel, ctx: cctx,
		ready: make(chan struct{}), remote: xAddr(d.Server)}

	switch mode {
	case "stream-one":
		pr, pw := io.Pipe()
		c.w, c.closeW = pw, pw
		if err := c.openDownload(pr); err != nil {
			cancel()
			return nil, err
		}
	case "stream-up":
		pr, pw := io.Pipe()
		c.w, c.closeW = pw, pw
		if err := c.openDownload(nil); err != nil {
			cancel()
			return nil, err
		}
		go c.streamUpload(pr)
	default: // packet-up
		if err := c.openDownload(nil); err != nil {
			cancel()
			return nil, err
		}
		c.batch = make(chan []byte, 64)
		c.w = packetWriter{c}
		go c.packetUploader()
	}
	return c, nil
}

type xhttpConn struct {
	d       *XHTTP
	base    *url.URL
	session string
	ctx     context.Context
	cancel  context.CancelFunc
	remote  net.Addr

	ready chan struct{} // closed once the download response (or its failure) is known
	body  io.ReadCloser
	rerr  error

	w      io.Writer
	closeW io.Closer
	batch  chan []byte

	mu   sync.Mutex
	werr error
	once sync.Once
}

// openDownload starts the GET (or, for stream-one, the bidirectional POST) and
// returns once a connection exists, so dial failures surface immediately.
func (c *xhttpConn) openDownload(body io.Reader) error {
	method := "GET"
	if body != nil {
		method = "POST"
	}
	gotConn := make(chan struct{})
	var gotOnce sync.Once
	ctx := httptrace.WithClientTrace(c.ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { gotOnce.Do(func() { close(gotConn) }) },
	})
	req, err := c.d.newRequest(ctx, method, c.base, c.session, "", body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/grpc")
	}
	failed := make(chan error, 1)
	go func() {
		defer close(c.ready)
		resp, err := c.d.client.Do(req)
		if err != nil {
			c.rerr = err
			failed <- err
			return
		}
		if resp.StatusCode != 200 {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			c.rerr = fmt.Errorf("xhttp: server answered %s", resp.Status)
			failed <- c.rerr
			return
		}
		c.body = resp.Body
	}()
	select {
	case <-gotConn:
		return nil
	case err := <-failed:
		return err
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

func (c *xhttpConn) setErr(err error) {
	c.mu.Lock()
	if c.werr == nil {
		c.werr = err
	}
	c.mu.Unlock()
	c.Close()
}

func (c *xhttpConn) streamUpload(pr io.Reader) {
	req, err := c.d.newRequest(c.ctx, "POST", c.base, c.session, "", pr)
	if err != nil {
		c.setErr(err)
		return
	}
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := c.d.client.Do(req)
	if err != nil {
		c.setErr(err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

type packetWriter struct{ c *xhttpConn }

func (w packetWriter) Write(p []byte) (int, error) {
	c := w.c
	c.mu.Lock()
	err := c.werr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	select {
	case c.batch <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (c *xhttpConn) packetUploader() {
	maxBody := c.d.ScMaxEachPostBytes
	if maxBody <= 0 {
		maxBody = 1_000_000
	}
	minGap := c.d.ScMinPostsIntervalMs
	if minGap == 0 {
		minGap = 30
	}
	var seq int64
	var last time.Time
	for {
		var data []byte
		select {
		case data = <-c.batch:
		case <-c.ctx.Done():
			return
		}
	drain:
		for len(data) < maxBody { // batch writes that queued up meanwhile
			select {
			case more := <-c.batch:
				data = append(data, more...)
			default:
				break drain
			}
		}
		for len(data) > 0 {
			n := min(len(data), maxBody)
			chunk := data[:n]
			data = data[n:]
			if wait := time.Duration(minGap)*time.Millisecond - time.Since(last); wait > 0 {
				select {
				case <-time.After(wait):
				case <-c.ctx.Done():
					return
				}
			}
			last = time.Now()
			wrote := make(chan struct{})
			var wroteOnce sync.Once
			markWrote := func() { wroteOnce.Do(func() { close(wrote) }) }
			ctx := httptrace.WithClientTrace(c.ctx, &httptrace.ClientTrace{
				WroteRequest: func(httptrace.WroteRequestInfo) { markWrote() },
			})
			s := strconv.FormatInt(seq, 10)
			seq++
			go func() {
				defer markWrote()
				if err := c.post(ctx, s, chunk); err != nil {
					c.setErr(err)
				}
			}()
			select { // keep sequence numbers in wire order, like Xray
			case <-wrote:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

func (c *xhttpConn) post(ctx context.Context, seq string, data []byte) error {
	req, err := c.d.newRequest(ctx, "POST", c.base, c.session, seq, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))
	resp, err := c.d.client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("xhttp: upload answered %s", resp.Status)
	}
	return nil
}

func (c *xhttpConn) Read(p []byte) (int, error) {
	select {
	case <-c.ready:
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	}
	if c.rerr != nil {
		return 0, c.rerr
	}
	return c.body.Read(p)
}

func (c *xhttpConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *xhttpConn) Close() error {
	c.once.Do(func() {
		if c.closeW != nil {
			c.closeW.Close()
		}
		c.cancel()
		go func() {
			<-c.ready
			if c.body != nil {
				c.body.Close()
			}
		}()
	})
	return nil
}

func (c *xhttpConn) LocalAddr() net.Addr              { return xAddr("0.0.0.0:0") }
func (c *xhttpConn) RemoteAddr() net.Addr             { return c.remote }
func (c *xhttpConn) SetDeadline(time.Time) error      { return nil }
func (c *xhttpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xhttpConn) SetWriteDeadline(time.Time) error { return nil }
