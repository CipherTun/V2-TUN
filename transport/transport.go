// Package transport holds composable dial layers (TCP, TLS, payload, WS, h2, gRPC, QUIC).
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
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
// PinSHA256 pins certificates: the handshake only succeeds when the SHA-256 of
// at least one certificate (DER) the server sends matches. The pin is checked
// in addition to normal verification, and also when AllowInsecure is set, so a
// self-signed server can be trusted by pin alone. Empty means no pinning.
// VerifyName verifies the certificate against that DNS name instead of the
// SNI (for servers that present a name other than the one sent as SNI, such
// as a fronting setup). The chain is still checked against the system roots;
// AllowInsecure turns the check off, as it does for the normal verification.
type TLS struct {
	Inner         Dialer
	ServerName    string // SNI; empty => host of addr
	ALPN          []string
	AllowInsecure bool
	MinVersion    uint16
	Fingerprint   string
	PinSHA256     []string // hex, ":" separators allowed
	VerifyName    string   // verify the certificate for this name instead of the SNI
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

// NormalizePin lower-cases a certificate pin and drops ":" separators and
// spaces. It reports false unless the result is 64 hex characters (SHA-256).
func NormalizePin(p string) (string, bool) {
	p = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(p), ":", ""), " ", ""))
	if len(p) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(p); err != nil {
		return "", false
	}
	return p, true
}

// pinVerifier returns a VerifyPeerCertificate hook for the pins, or nil.
func pinVerifier(pins []string) func([][]byte, [][]*x509.Certificate) error {
	want := map[string]bool{}
	for _, p := range pins {
		if n, ok := NormalizePin(p); ok {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		for _, c := range raw {
			sum := sha256.Sum256(c)
			if want[hex.EncodeToString(sum[:])] {
				return nil
			}
		}
		return errors.New("tls: no certificate in the server's chain matches the pinned SHA-256")
	}
}

// nameVerifier returns a VerifyPeerCertificate hook that checks the server's
// chain against the system roots for name (not the SNI), then runs next (the
// pin check) when it is not nil. It is used together with
// InsecureSkipVerify, which only switches off the built-in check.
func nameVerifier(name string, next func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, chains [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("tls: the server sent no certificate")
		}
		certs := make([]*x509.Certificate, 0, len(raw))
		for _, r := range raw {
			c, err := x509.ParseCertificate(r)
			if err != nil {
				return fmt.Errorf("tls: bad server certificate: %w", err)
			}
			certs = append(certs, c)
		}
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: inter}); err != nil {
			return fmt.Errorf("tls: the certificate does not verify for %q: %w", name, err)
		}
		if next != nil {
			return next(raw, chains)
		}
		return nil
	}
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
	pin := pinVerifier(d.PinSHA256)
	skip := d.AllowInsecure
	if d.VerifyName != "" && !d.AllowInsecure {
		// The built-in check would use the SNI, so it is replaced by one that
		// uses VerifyName (and still runs the pin check afterwards).
		skip = true
		pin = nameVerifier(d.VerifyName, pin)
	}
	if id, ok := fingerprints[strings.ToLower(d.Fingerprint)]; ok {
		uc := utls.UClient(c, &utls.Config{ServerName: sni, InsecureSkipVerify: skip,
			NextProtos: d.ALPN, VerifyPeerCertificate: pin}, id)
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
		ServerName:            sni,
		NextProtos:            d.ALPN,
		InsecureSkipVerify:    skip,
		MinVersion:            d.MinVersion,
		VerifyPeerCertificate: pin,
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
// SSH client. Only the status line and headers are read; a body, if a server
// sends one, is not skipped.
//
// Every reply is accepted unless its status is 400 or higher; there is nothing
// to configure, which is how HTTP Custom, HTTP Injector and NetMod behave (a
// 200, a 301 or a made-up "HTTP/1.1 3xx" from a front all let the tunnel
// start, a 4xx or 5xx does not).
type Payload struct {
	Inner          Dialer
	Template       *payload.Template
	Host           string // value for [host]; empty => host of addr
	Method         string
	UserAgent      string
	SNI            string            // value for [sni]
	Vars           map[string]string // values for [var=name]
	ExpectResponse bool              // read and validate the HTTP replies before continuing
	Responses      int               // replies to read; 0 => one per HTTP request line in the payload (1 to 4)

	// ViaProxy says the connection below goes to a remote proxy, not to addr.
	// [ip] and [ip_port] then name the real server (resolved with Resolver)
	// instead of the proxy.
	ViaProxy bool
	Resolver *net.Resolver // nil => system resolver
}

// codeOK accepts every reply below 400: 1xx (101 Switching Protocols), 2xx
// and 3xx. A 4xx or 5xx reply, or a status that is not a status, is refused.
func codeOK(code int) bool { return code >= 100 && code < 400 }

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
		raw, err := payload.ReadHTTPHeaders(c)
		if err != nil {
			return fmt.Errorf("payload: waiting for reply %d of %d: %w", i+1, n, err)
		}
		if !codeOK(raw) {
			return fmt.Errorf("payload: reply %d of %d has status %d", i+1, n, raw)
		}
	}
	return nil
}

// serverIP is the address [ip] stands for: the peer of the connection, or,
// behind a remote proxy (where the peer is the proxy), the real server.
func (d *Payload) serverIP(ctx context.Context, c net.Conn, host string) string {
	if !d.ViaProxy {
		if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
			return ra.IP.String() // the address we actually connected to
		}
		return host
	}
	if net.ParseIP(host) != nil {
		return host
	}
	rs := d.Resolver
	if rs == nil {
		rs = net.DefaultResolver
	}
	cx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := rs.LookupIPAddr(cx, host)
	if err != nil || len(ips) == 0 {
		return host
	}
	pick := ips[0].IP
	for _, a := range ips {
		if a.IP.To4() != nil {
			pick = a.IP
			break
		}
	}
	return pick.String()
}

func (d *Payload) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	server := h // the real target: [host] may be replaced by the bug host below
	ip := d.serverIP(ctx, c, server)
	if d.Host != "" {
		h = d.Host
	}
	segs := d.Template.Render(payload.Context{Host: h, Port: port, Server: server, ServerPort: port, IP: ip,
		SNI: d.SNI, Method: d.Method, UserAgent: d.UserAgent, Vars: d.Vars})
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
