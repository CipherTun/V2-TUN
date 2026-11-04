// Package transport holds composable dial layers (TCP, TLS, payload, WS, h2, gRPC, QUIC).
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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
			for _, ext := range uc.Extensions {
				if a, ok := ext.(*utls.ALPNExtension); ok {
					a.AlpnProtocols = d.ALPN
				}
			}
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
type Payload struct {
	Inner          Dialer
	Template       *payload.Template
	Host           string // value for [host]; empty => host of addr
	Method         string
	UserAgent      string
	ExpectResponse bool // read and validate the HTTP reply (200/101) before continuing
}

func (d *Payload) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	if d.Host != "" {
		h = d.Host
	}
	segs := d.Template.Render(payload.Context{Host: h, Port: port, Method: d.Method, UserAgent: d.UserAgent})
	if err := payload.Send(c, segs); err != nil {
		c.Close()
		return nil, err
	}
	if d.ExpectResponse {
		code, err := payload.ReadHTTPHeaders(c)
		if err != nil || (code != 200 && code != 101) {
			c.Close()
			return nil, fmt.Errorf("payload: server replied %d: %v", code, err)
		}
	}
	return c, nil
}
