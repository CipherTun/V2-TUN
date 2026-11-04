// Package v2tun is a standalone, Xray-free tunnel library.
package v2tun

import (
	"context"
	"errors"
	"strconv"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"io.surprise.vpn/payload"
	"io.surprise.vpn/proxy"
	"io.surprise.vpn/route"
	"io.surprise.vpn/transport"
	"io.surprise.vpn/udpgw"
)

type TLSConfig struct {
	Enabled       bool     `json:"enabled"`
	SNI           string   `json:"sni"`
	ALPN          []string `json:"alpn"`
	AllowInsecure bool     `json:"allowInsecure"`
	Fingerprint   string   `json:"fingerprint"` // chrome|firefox|safari|ios|android|edge|random
}

type PayloadConfig struct {
	Template       string `json:"template"`
	Host           string `json:"host"`
	Method         string `json:"method"`
	UserAgent      string `json:"userAgent"`
	Stage          string `json:"stage"` // "pre-tls" (default) or "post-tls"
	ExpectResponse bool   `json:"expectResponse"`
}

// FragmentConfig splits the TLS ClientHello: Length bytes per piece, Interval ms between.
type FragmentConfig struct {
	Length   [2]int `json:"length"`
	Interval [2]int `json:"interval"`
}

type WSConfig struct {
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// Advanced holds optional knobs the UI does not need to expose.
type Advanced struct {
	SSHCiphers      []string `json:"sshCiphers,omitempty"`
	SSHKeyExchanges []string `json:"sshKex,omitempty"`
	SSHMACs         []string `json:"sshMacs,omitempty"`
	SSHHostKeys     []string `json:"sshHostKeys,omitempty"`
}

type Config struct {
	Protocol   string         `json:"protocol"` // trojan|vless|vmess|shadowsocks|ssh
	Network    string         `json:"network"`  // tcp (default)|ws|httpupgrade|h2|grpc|quic
	GRPCService string        `json:"grpcService"`
	XHTTPMode   string        `json:"xhttpMode"` // auto|packet-up|stream-one
	Fragment    *FragmentConfig `json:"fragment,omitempty"`
	Server     string         `json:"server"`
	Port       int            `json:"port"`
	UUID       string         `json:"uuid"`
	AlterID    int            `json:"alterId"`
	Password   string         `json:"password"`
	Username   string         `json:"username"`
	Method     string         `json:"method"`
	PrivateKey string         `json:"privateKey"`
	TLS        TLSConfig      `json:"tls"`
	WS         WSConfig       `json:"ws"`
	Payload    *PayloadConfig `json:"payload,omitempty"`
	Advanced   Advanced       `json:"advanced"`
	Routing    *route.Config  `json:"routing,omitempty"`
	Mux        *MuxConfig     `json:"mux,omitempty"`
	UDPGW      string         `json:"udpgw"`      // BadVPN udpgw address as seen from the server, e.g. "127.0.0.1:7300"
	DirectDNS  string         `json:"directDns"`  // resolver for hostnames, bypasses the VPN (default 1.1.1.1:53)
	TimeoutSec int            `json:"timeoutSec"`
}

type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency"`
}

// Client dials targets through the configured tunnel.
type Client struct {
	out      proxy.Outbound
	direct   *transport.TCP
	resolver *net.Resolver
	router   *route.Router
	gw       *udpgw.Client
}

var ErrBlocked = errors.New("v2tun: blocked by routing rule")

func New(cfg *Config) (*Client, error) {
	if cfg.Server == "" || cfg.Port == 0 {
		return nil, errors.New("v2tun: server and port required")
	}
	to := time.Duration(cfg.TimeoutSec) * time.Second
	if to == 0 {
		to = 15 * time.Second
	}
	// chain: tcp -> [payload pre] -> tls -> [payload post] -> ws/httpupgrade
	net_ := strings.ToLower(cfg.Network)
	alpn := cfg.TLS.ALPN
	if len(alpn) == 0 {
		switch net_ {
		case "h2", "grpc", "xhttp", "splithttp":
			alpn = []string{"h2"}
		case "ws", "websocket", "httpupgrade":
			alpn = []string{"http/1.1"}
		}
	}
	dns := cfg.DirectDNS
	if dns == "" {
		dns = "1.1.1.1:53"
	}
	res := transport.NewResolver(dns)
	d, err := baseChain(cfg, net_, to, alpn, res)
	if err != nil {
		return nil, err
	}
	switch net_ {
	case "", "tcp":
	case "h2", "http":
		d = &transport.H2{Inner: d, TLS: cfg.TLS.Enabled, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers}
	case "xhttp", "splithttp":
		d = &transport.XHTTP{Inner: d, TLS: cfg.TLS.Enabled, Host: cfg.WS.Host, Path: cfg.WS.Path, Mode: cfg.XHTTPMode, Headers: cfg.WS.Headers}
	case "grpc":
		d = &transport.GRPC{Inner: d, TLS: cfg.TLS.Enabled, Host: cfg.WS.Host, Service: cfg.GRPCService}
	case "quic":
	case "ws", "websocket":
		d = &transport.WebSocket{Inner: d, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers}
	case "httpupgrade":
		d = &transport.WebSocket{Inner: d, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers, Upgrade: true}
	default:
		return nil, fmt.Errorf("v2tun: transport %q not implemented yet", cfg.Network)
	}

	srv := net.JoinHostPort(cfg.Server, fmt.Sprint(cfg.Port))
	c := &Client{direct: &transport.TCP{Timeout: to, Resolver: res}, resolver: res}
	proto := strings.ToLower(cfg.Protocol)
	switch proto {
	case "trojan":
		c.out = &proxy.Trojan{Server: srv, Dialer: d, Password: cfg.Password}
	case "vless":
		c.out = &proxy.VLESS{Server: srv, Dialer: d, UUID: cfg.UUID}
	case "vmess":
		c.out = &proxy.VMess{Server: srv, Dialer: d, UUID: cfg.UUID, AlterID: cfg.AlterID, Security: cfg.Method}
	case "shadowsocks", "ss":
		c.out = &proxy.Shadowsocks{Server: srv, Dialer: d, Method: cfg.Method, Password: cfg.Password}
	case "ssh":
		c.out = &proxy.SSH{Server: srv, Dialer: d, User: cfg.Username,
			Password: cfg.Password, PrivateKey: readKey(cfg.PrivateKey),
			Options: proxy.SSHOptions{Ciphers: cfg.Advanced.SSHCiphers, KeyExchanges: cfg.Advanced.SSHKeyExchanges,
				MACs: cfg.Advanced.SSHMACs, HostKeyAlgos: cfg.Advanced.SSHHostKeys}}
	default:
		return nil, fmt.Errorf("v2tun: unknown protocol %q", cfg.Protocol)
	}
	if cfg.Mux != nil && cfg.Mux.Enabled && proto != "ssh" {
		c.out = &proxy.Mux{Base: c.out, Concurrency: cfg.Mux.Concurrency}
	}
	if cfg.UDPGW != "" {
		gwAddr, out := cfg.UDPGW, c.out
		c.gw = &udpgw.Client{Dial: func(ctx context.Context) (net.Conn, error) {
			return out.DialContext(ctx, "tcp", gwAddr)
		}}
	}
	if cfg.Routing != nil {
		r, err := route.New(cfg.Routing)
		if err != nil {
			return nil, err
		}
		r.Resolve = func(ctx context.Context, host string) ([]net.IP, error) {
			var rs *net.Resolver = res
			if rs == nil {
				rs = net.DefaultResolver
			}
			addrs, err := rs.LookupIPAddr(ctx, host)
			var ips []net.IP
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, err
		}
		c.router = r
	}
	return c, nil
}

// SetRouteList supplies a named list (domains or CIDRs) for "list:NAME" rules.
func (c *Client) SetRouteList(name string, items []string) error {
	if c.router == nil {
		return errors.New("v2tun: no routing configured")
	}
	return c.router.SetList(name, items)
}

func (c *Client) decide(ctx context.Context, network, addr string) (route.Action, error) {
	if c.router == nil {
		return route.Proxy, nil
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	port, _ := strconv.Atoi(p)
	return c.router.Decide(ctx, network, h, port), nil
}

func readKey(s string) []byte {
	if strings.Contains(s, "PRIVATE KEY") {
		return []byte(s)
	}
	if s != "" {
		if b, err := os.ReadFile(s); err == nil {
			return b
		}
	}
	return nil
}

func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	act, err := c.decide(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	switch act {
	case route.Block:
		return nil, ErrBlocked
	case route.Direct:
		conn, err = c.direct.DialContext(ctx, "tcp", addr)
	default:
		conn, err = c.out.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	return countConn{conn}, nil
}

// DialUDP returns a datagram conn (one Write/Read = one datagram) to addr.
// Order: routing rule, native UDP of the protocol, then BadVPN udpgw.
func (c *Client) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	act, err := c.decide(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	switch {
	case act == route.Block:
		return nil, ErrBlocked
	case act == route.Direct:
		conn, err = c.directUDP(ctx, addr)
	default:
		if u, ok := c.out.(proxy.UDPOutbound); ok {
			conn, err = u.DialUDP(ctx, addr)
		} else if c.gw != nil {
			conn, err = c.gw.DialUDP(ctx, addr)
		} else {
			return nil, proxy.ErrNotImplemented
		}
	}
	if err != nil {
		return nil, err
	}
	return countConn{conn}, nil
}

type udpConn struct {
	net.PacketConn
	remote *net.UDPAddr
}

func (u *udpConn) Read(p []byte) (int, error)  { n, _, err := u.ReadFrom(p); return n, err }
func (u *udpConn) Write(p []byte) (int, error) { return u.WriteTo(p, u.remote) }
func (u *udpConn) RemoteAddr() net.Addr        { return u.remote }

func (c *Client) directUDP(ctx context.Context, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(ps)
	ip := net.ParseIP(host)
	if ip == nil {
		rs := c.resolver
		if rs == nil {
			rs = net.DefaultResolver
		}
		ips, err := rs.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("v2tun: resolve %s: %v", host, err)
		}
		ip = ips[0].IP
	}
	pc, err := transport.ListenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return &udpConn{PacketConn: pc, remote: &net.UDPAddr{IP: ip, Port: port}}, nil
}

// baseChain builds tcp -> [payload pre] -> tls -> [payload post] (or QUIC alone).
func baseChain(cfg *Config, net_ string, to time.Duration, alpn []string, res *net.Resolver) (transport.Dialer, error) {
	if net_ == "quic" { // QUIC carries its own TLS; payload and TLS layers don't apply
		return &transport.QUIC{ServerName: cfg.TLS.SNI, ALPN: cfg.TLS.ALPN, AllowInsecure: cfg.TLS.AllowInsecure}, nil
	}
	var d transport.Dialer = &transport.TCP{Timeout: to, Resolver: res}
	if f := cfg.Fragment; f != nil {
		d = &transport.Fragment{Inner: d, LenMin: f.Length[0], LenMax: f.Length[1], IntMin: f.Interval[0], IntMax: f.Interval[1]}
	}
	var pd *transport.Payload
	if p := cfg.Payload; p != nil && p.Template != "" {
		tpl, err := payload.Compile(p.Template)
		if err != nil {
			return nil, err
		}
		pd = &transport.Payload{Template: tpl, Host: p.Host, Method: p.Method,
			UserAgent: p.UserAgent, ExpectResponse: p.ExpectResponse}
	}
	post := pd != nil && cfg.Payload.Stage == "post-tls"
	if pd != nil && !post {
		pd.Inner = d
		d = pd
	}
	if cfg.TLS.Enabled {
		d = &transport.TLS{Inner: d, ServerName: cfg.TLS.SNI, ALPN: alpn,
			AllowInsecure: cfg.TLS.AllowInsecure, Fingerprint: cfg.TLS.Fingerprint}
	}
	if post {
		pd.Inner = d
		d = pd
	}
	return d, nil
}
