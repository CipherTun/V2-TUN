// Package transport holds composable dial layers (TCP, TLS, payload, WS, h2, gRPC, QUIC).
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"io.surprise.vpn/payload"
)

// Dialer opens a connection to addr ("host:port").
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// TCP is the base layer.
type TCP struct {
	Timeout  time.Duration
	Resolver *net.Resolver // nil => system resolver
}

func (d *TCP) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second, Control: controlFn, Resolver: d.Resolver}
	return nd.DialContext(ctx, network, addr)
}

// TLS wraps Inner with TLS. AllowInsecure skips verification (the thing Xray removed).
// Fingerprint (chrome|firefox|safari|ios|android|edge|random) uses uTLS to mimic a browser.
type TLS struct {
	Inner         Dialer
	ServerName    string // SNI; empty => host of addr
	ALPN          []string
	AllowInsecure bool
	MinVersion    uint16
	Fingerprint   string
}

var fingerprints = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"edge":    utls.HelloEdge_Auto,
	"random":  utls.HelloRandomized,
}

// KnownFingerprint reports whether name is a supported uTLS fingerprint.
func KnownFingerprint(name string) bool {
	_, ok := fingerprints[strings.ToLower(name)]
	return ok
}

func (d *TLS) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	sni := d.ServerName
	if sni == "" {
		sni = host
	}
	if id, ok := fingerprints[strings.ToLower(d.Fingerprint)]; ok {
		uc := utls.UClient(c, &utls.Config{ServerName: sni, InsecureSkipVerify: d.AllowInsecure,
			NextProtos: d.ALPN}, id)
		if err := uc.BuildHandshakeState(); err != nil {
			c.Close()
			return nil, err
		}
		if len(d.ALPN) > 0 { // force our ALPN into the browser preset
			hasH2 := false
			for _, p := range d.ALPN {
				hasH2 = hasH2 || p == "h2"
			}
			kept := uc.Extensions[:0]
			for _, ext := range uc.Extensions {
				switch e := ext.(type) {
				case *utls.ALPNExtension:
					e.AlpnProtocols = d.ALPN
				case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
					if !hasH2 { // ALPS only makes sense when h2 is offered
						continue
					}
				}
				kept = append(kept, ext)
			}
			uc.Extensions = kept
		}
		if err := uc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("utls handshake: %w", err)
		}
		return uc, nil
	}
	tc := tls.Client(c, &tls.Config{
		ServerName:         sni,
		NextProtos:         d.ALPN,
		InsecureSkipVerify: d.AllowInsecure,
		MinVersion:         d.MinVersion,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, nil
}

// Payload sends an HTTP-Injector style payload right after connecting.
// See package payload for the tag list.
//
// With ExpectResponse the HTTP replies to the payload's request lines are read
// and dropped before the protocol starts. That is what a "websocket upgrade"
// payload for SSH needs: the server answers "101 Switching Protocols" and
// then speaks raw SSH (no WebSocket framing), so the reply must not reach the
// SSH client.
type Payload struct {
	Inner          Dialer
	Template       *payload.Template
	Host           string // value for [host]; empty => host of addr
	Method         string
	UserAgent      string
	SNI            string            // value for [sni]
	Vars           map[string]string // values for [var=name]
	ExpectResponse bool              // read and validate the HTTP replies before continuing
	ExpectCodes    []int             // accepted status codes; empty => 101 and any 2xx; 0 accepts any
	Responses      int               // replies to read; 0 => one per HTTP request line in the payload (1 to 4)
}

func codeOK(code int, allowed []int) bool {
	if len(allowed) == 0 {
		return code == 101 || (code >= 200 && code < 300)
	}
	for _, a := range allowed {
		if a == code || a == 0 {
			return true
		}
	}
	return false
}

var requestLine = regexp.MustCompile(`(?m)^[A-Za-z]+ \S+ HTTP/1\.[01]\r?$`)

// countRequests counts the HTTP request lines in the rendered payload, so a
// payload that holds two requests (CONNECT to a proxy, then an Upgrade
// request through it) waits for both replies.
func countRequests(segs []payload.Segment) int {
	var all []byte
	for _, s := range segs {
		all = append(all, s.Data...)
	}
	n := len(requestLine.FindAll(all, -1))
	if n < 1 {
		n = 1
	}
	if n > 4 {
		n = 4
	}
	return n
}

func (d *Payload) readReplies(c net.Conn, segs []payload.Segment) error {
	n := d.Responses
	if n <= 0 {
		n = countRequests(segs)
	}
	for i := 0; i < n; i++ {
		code, err := payload.ReadHTTPHeaders(c)
		if err != nil {
			return fmt.Errorf("payload: waiting for reply %d of %d: %w", i+1, n, err)
		}
		if !codeOK(code, d.ExpectCodes) {
			return fmt.Errorf("payload: reply %d of %d has status %d", i+1, n, code)
		}
	}
	return nil
}

func (d *Payload) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	ip := h
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
		ip = ra.IP.String() // [ip] / [ip_port]: the address we actually connected to
	}
	if d.Host != "" {
		h = d.Host
	}
	segs := d.Template.Render(payload.Context{Host: h, Port: port, IP: ip, SNI: d.SNI, Method: d.Method,
		UserAgent: d.UserAgent, Vars: d.Vars})
	if err := payload.SendContext(ctx, c, segs); err != nil {
		c.Close()
		return nil, err
	}
	if d.ExpectResponse {
		// A server that never answers must not hang the dial: stop at ctx or
		// after 30 seconds, whichever comes first.
		stop := context.AfterFunc(ctx, func() { c.Close() })
		limit := time.AfterFunc(30*time.Second, func() { c.Close() })
		err := d.readReplies(c, segs)
		limit.Stop()
		if !stop() && err == nil {
			err = ctx.Err()
		}
		if err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}
