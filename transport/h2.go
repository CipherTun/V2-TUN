package transport

import (
	"bufio"
	"context"
	"encoding/binary"
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

// h2Stream is a net.Conn over one streaming HTTP/2 POST.
type h2Stream struct {
	raw   net.Conn
	wr    *io.PipeWriter
	ready chan struct{}
	resp  *http.Response
	err   error
	once  sync.Once
}

func (s *h2Stream) Read(p []byte) (int, error) {
	<-s.ready
	if s.err != nil {
		return 0, s.err
	}
	return s.resp.Body.Read(p)
}
func (s *h2Stream) Write(p []byte) (int, error) { return s.wr.Write(p) }
func (s *h2Stream) Close() error {
	s.once.Do(func() {
		s.wr.Close()
		go func() {
			<-s.ready
			if s.resp != nil {
				s.resp.Body.Close()
			}
			s.raw.Close()
		}()
	})
	return nil
}
func (s *h2Stream) LocalAddr() net.Addr              { return s.raw.LocalAddr() }
func (s *h2Stream) RemoteAddr() net.Addr             { return s.raw.RemoteAddr() }
func (s *h2Stream) SetDeadline(time.Time) error      { return nil }
func (s *h2Stream) SetReadDeadline(time.Time) error  { return nil }
func (s *h2Stream) SetWriteDeadline(time.Time) error { return nil }

// openH2 starts the POST asynchronously (servers like grpc-go may send headers lazily).
func openH2(ctx context.Context, raw net.Conn, tlsOn bool, host, path string, hdr map[string]string) (*h2Stream, error) {
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}
	pr, pw := io.Pipe()
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	u := &url.URL{Scheme: scheme, Host: host, Path: path}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path, u.RawQuery = path[:i], path[i+1:]
	}
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), "POST", u.String(), pr)
	if err != nil {
		raw.Close()
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s := &h2Stream{raw: raw, wr: pw, ready: make(chan struct{})}
	go func() {
		defer close(s.ready)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			s.err = err
			return
		}
		if resp.StatusCode != 200 {
			s.err = fmt.Errorf("h2: status %d", resp.StatusCode)
			resp.Body.Close()
			return
		}
		s.resp = resp
	}()
	return s, nil
}

// H2 is the plain V2Ray "http" transport: a bidirectional stream over HTTP/2.
// Inner must yield a TLS conn with ALPN h2 (or cleartext h2c when TLS is false).
type H2 struct {
	Inner   Dialer
	TLS     bool
	Host    string
	Path    string
	Headers map[string]string
}

func (d *H2) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
	return openH2(ctx, raw, d.TLS, host, path, d.Headers)
}

// GRPC is the "gun" transport (V2Ray/Xray gRPC): length-prefixed Hunk messages
// over HTTP/2, implemented without the gRPC library.
type GRPC struct {
	Inner   Dialer
	TLS     bool
	Host    string
	Service string // default "GunService"
}

func (d *GRPC) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host := d.Host
	if host == "" {
		host, _, _ = net.SplitHostPort(addr)
	}
	svc := d.Service
	if svc == "" {
		svc = "GunService"
	}
	s, err := openH2(ctx, raw, d.TLS, host, "/"+svc+"/Tun", map[string]string{
		"Content-Type": "application/grpc", "Te": "trailers", "User-Agent": "grpc-go/1.58.1"})
	if err != nil {
		return nil, err
	}
	return &gunConn{Conn: s, br: bufio.NewReader(s)}, nil
}

type gunConn struct {
	net.Conn
	br   *bufio.Reader
	rbuf []byte
}

func (c *gunConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 16384 {
			n = 16384
		}
		msg := append([]byte{0x0a}, binary.AppendUvarint(nil, uint64(n))...)
		msg = append(msg, p[:n]...)
		frame := append([]byte{0}, binary.BigEndian.AppendUint32(nil, uint32(len(msg)))...)
		frame = append(frame, msg...)
		if _, err := c.Conn.Write(frame); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *gunConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		var h [5]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[1:])
		if n > 1<<24 {
			return 0, errors.New("grpc: message too large")
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c.br, msg); err != nil {
			return 0, err
		}
		if len(msg) == 0 {
			continue
		}
		if msg[0] != 0x0a {
			return 0, errors.New("grpc: unexpected hunk")
		}
		l, k := binary.Uvarint(msg[1:])
		if k <= 0 || uint64(len(msg)) < 1+uint64(k)+l {
			return 0, errors.New("grpc: bad hunk")
		}
		c.rbuf = msg[1+k : 1+uint64(k)+l]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}
