// Package v2tun is a standalone, Xray-free tunnel library.
package v2tun

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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

// RealityConfig enables REALITY in place of the TLS layer (TLS.Enabled is then
// ignored). Keys use the same encodings as Xray share links.
type RealityConfig struct {
	PublicKey   string `json:"publicKey"`   // server X25519 public key, base64url (pbk)
	ShortID     string `json:"shortId"`     // 0 to 16 hex characters (sid)
	ServerName  string `json:"serverName"`  // cover site SNI; empty => TLS.SNI, then the server host
	Fingerprint string `json:"fingerprint"` // empty => TLS.Fingerprint, then chrome
}

// HysteriaConfig holds the settings of the hysteria and hysteria2 protocols
// that have no place elsewhere. The server password (hysteria2) or auth string
// (hysteria) is Config.Password; the TLS name and "insecure" flag are
// Config.TLS.SNI and Config.TLS.AllowInsecure (TLS.Enabled is not needed).
type HysteriaConfig struct {
	Obfs      string `json:"obfs,omitempty"`      // hysteria2: Salamander password; hysteria: xplus password
	PinSHA256 string `json:"pinSha256,omitempty"` // hysteria2: hex SHA-256 of the server certificate (replaces CA verification)
	ALPN      string `json:"alpn,omitempty"`      // hysteria: default "hysteria"
	UpMbps    int    `json:"upMbps,omitempty"`    // hysteria: required by the server, default 10; unused by hysteria2
	DownMbps  int    `json:"downMbps,omitempty"`  // hysteria: required, default 50 (the server sends at this rate); hysteria2: advertised receive rate, 0 lets the server decide
}

// PayloadConfig is the HTTP-Injector style payload sent right after the TCP
// connect (or after TLS with Stage "post-tls"). See package payload for tags.
//
// "SSH over WebSocket" needs no TLS: protocol ssh, a payload such as
// "@ssh-ws" (or your own GET ... Upgrade: websocket request) and, if you use
// one, an HTTP proxy in Proxy. Whether TLS is used is up to the config.
type PayloadConfig struct {
	Template  string `json:"template"` // a template or a preset such as "@connect" or "@ssh-ws"
	Host      string `json:"host"`     // value for [host] (and [host_port]); empty => server host
	Method    string `json:"method"`
	UserAgent string `json:"userAgent"`
	Stage     string `json:"stage"` // "pre-tls" (default) or "post-tls"
	// ExpectResponse says whether the server's HTTP reply to the payload is read
	// and dropped before the protocol starts. Unset means automatic: yes when a
	// Proxy is set, or when the payload is an HTTP request on a plain tcp
	// stream (the "101 Switching Protocols" of an SSH-WS server, a proxy's 200).
	ExpectResponse *bool `json:"expectResponse,omitempty"`
	// ExpectResponses is how many replies to read; 0 means one per HTTP request
	// line in the payload (a CONNECT followed by an Upgrade request gives two).
	ExpectResponses int   `json:"expectResponses,omitempty"`
	ExpectCodes     []int `json:"expectCodes,omitempty"` // accepted status codes; empty => 101 and any 2xx; 0 accepts any
	// ResponseMap is the response changer: a status code the server sent ("301",
	// or a class such as "3xx") counts as the code it maps to, so
	// {"301": 200} makes "301 Moved Permanently" work like "200 OK".
	ResponseMap map[string]int    `json:"responseMap,omitempty"`
	Vars        map[string]string `json:"vars,omitempty"` // values for [var=name]
	// Proxy ("host:port") is HTTP-Injector's remote proxy mode: the TCP
	// connection goes to this proxy, the payload names the real server in
	// [host_port]. It needs the pre-tls stage.
	Proxy string `json:"proxy,omitempty"`
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

// XHTTPOptions tunes the XHTTP client; zero values use Xray's defaults.
type XHTTPOptions struct {
	XPaddingBytes        [2]int `json:"xPaddingBytes"`        // default 100..1000
	ScMaxEachPostBytes   int    `json:"scMaxEachPostBytes"`   // default 1000000
	ScMinPostsIntervalMs int    `json:"scMinPostsIntervalMs"` // default 30
}

// Advanced holds optional knobs the UI does not need to expose.
type Advanced struct {
	SSHCiphers      []string `json:"sshCiphers,omitempty"`
	SSHKeyExchanges []string `json:"sshKex,omitempty"`
	SSHMACs         []string `json:"sshMacs,omitempty"`
	SSHHostKeys     []string `json:"sshHostKeys,omitempty"`
	// SSHHostKey pins the SSH server's host key: "SHA256:..." as printed by
	// ssh-keygen -l, or 64 hex characters. Empty accepts any key.
	SSHHostKey string `json:"sshHostKey,omitempty"`
}

type Config struct {
	// Protocol: trojan|vless|vmess|shadowsocks|ssh|socks5|socks4|http|https|
	// hysteria2|hysteria ("socks" is socks5, "socks4a" is socks4, "hy2" is
	// hysteria2, "hy" is hysteria; "https" is an http proxy that needs
	// tls.enabled). The hysteria protocols bring their own QUIC/TLS: payload,
	// reality, fragment and the other transports do not apply to them.
	Protocol     string            `json:"protocol"`
	Network      string            `json:"network"` // tcp (default)|ws|httpupgrade|h2|grpc|quic|xhttp
	GRPCService  string            `json:"grpcService"`
	XHTTPMode    string            `json:"xhttpMode"` // auto|packet-up|stream-up|stream-one
	XHTTP        *XHTTPOptions     `json:"xhttp,omitempty"`
	Fragment     *FragmentConfig   `json:"fragment,omitempty"`
	Server       string            `json:"server"`
	Port         int               `json:"port"`
	UUID         string            `json:"uuid"`
	Flow         string            `json:"flow,omitempty"` // vless only: "xtls-rprx-vision" (see checkFlow)
	AlterID      int               `json:"alterId"`
	Password     string            `json:"password"`
	Username     string            `json:"username"`
	Method       string            `json:"method"`
	PrivateKey   string            `json:"privateKey"`
	ProxyHeaders map[string]string `json:"proxyHeaders,omitempty"` // extra headers for the http/https proxy CONNECT
	TLS          TLSConfig         `json:"tls"`
	Reality      *RealityConfig    `json:"reality,omitempty"`
	Hysteria     *HysteriaConfig   `json:"hysteria,omitempty"`
	WS           WSConfig          `json:"ws"`
	Payload      *PayloadConfig    `json:"payload,omitempty"`
	Advanced     Advanced          `json:"advanced"`
	Routing      *route.Config     `json:"routing,omitempty"`
	Mux          *MuxConfig        `json:"mux,omitempty"`
	UDPGW        string            `json:"udpgw"`     // BadVPN udpgw address as seen from the server, e.g. "127.0.0.1:7300"
	DirectDNS    string            `json:"directDns"` // resolver for hostnames, bypasses the VPN (default 1.1.1.1:53)
	TimeoutSec   int               `json:"timeoutSec"`

	// Backups are complete outbound configs (another server, bug host,
	// payload or protocol) that are tried in order when this one fails; the
	// one that worked last is tried first next time (see proxy.Failover).
	// routing, udpgw and directDns belong to the top-level config only, and
	// backups cannot nest.
	Backups []Config `json:"backups,omitempty"`
	// Fallbacks is the same list as Backups, written as pointers. Both may be
	// set: Backups are tried first, then Fallbacks, with the same rules.
	Fallbacks []*Config `json:"fallbacks,omitempty"`
	// FailoverTimeoutSec limits each outbound's attempt when there are
	// backups or fallbacks (default 12 seconds).
	FailoverTimeoutSec int `json:"failoverTimeoutSec,omitempty"`
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

// checkFlow validates the VLESS flow. The only supported flow is XTLS Vision
// ("xtls-rprx-vision", or its "-udp443" variant, which behaves the same for
// TCP): it runs on plain TCP with TLS or REALITY directly on top, so any other
// transport, no TLS layer, or Mux.Cool cannot carry it. Rejecting these here
// beats a connection that fails later with a server-side protocol error.
func checkFlow(cfg *Config) error {
	f := strings.ToLower(cfg.Flow)
	if f == "" {
		return nil
	}
	if f != "xtls-rprx-vision" && f != "xtls-rprx-vision-udp443" {
		return fmt.Errorf("v2tun: flow %q is not supported (only xtls-rprx-vision)", cfg.Flow)
	}
	if !strings.EqualFold(cfg.Protocol, "vless") {
		return errors.New("v2tun: flow is only valid for vless")
	}
	if n := strings.ToLower(cfg.Network); n != "" && n != "tcp" {
		return fmt.Errorf("v2tun: flow xtls-rprx-vision needs the tcp transport, not %q", cfg.Network)
	}
	if !cfg.TLS.Enabled && cfg.Reality == nil {
		return errors.New("v2tun: flow xtls-rprx-vision needs TLS or REALITY")
	}
	if cfg.Mux != nil && cfg.Mux.Enabled {
		return errors.New("v2tun: flow xtls-rprx-vision cannot be combined with mux")
	}
	return nil
}

// checkFingerprints rejects an unknown uTLS fingerprint name. Without this the
// TLS layer would quietly fall back to Go's own (very recognisable) ClientHello
// and REALITY to chrome, so a typo would go unnoticed.
func checkFingerprints(cfg *Config) error {
	names := []string{cfg.TLS.Fingerprint}
	if cfg.Reality != nil {
		names = append(names, cfg.Reality.Fingerprint)
	}
	for _, fp := range names {
		if fp != "" && !transport.KnownFingerprint(fp) {
			return fmt.Errorf("v2tun: unknown tls fingerprint %q (use chrome, firefox, safari, ios, android, edge or random)", fp)
		}
	}
	return nil
}

// New builds the tunnel client: the outbound described by cfg, then cfg.Backups
// and cfg.Fallbacks behind a proxy.Failover when there are any, plus routing
// and udpgw.
func New(cfg *Config) (*Client, error) {
	dns := cfg.DirectDNS
	if dns == "" {
		dns = "1.1.1.1:53"
	}
	res := transport.NewResolver(dns)
	out, to, err := buildOutbound(cfg, res)
	if err != nil {
		return nil, err
	}
	// Backups first, then Fallbacks: one ordered list with one set of rules.
	var extra []*Config
	for i := range cfg.Backups {
		extra = append(extra, &cfg.Backups[i])
	}
	for i, fb := range cfg.Fallbacks {
		if fb == nil {
			return nil, fmt.Errorf("v2tun: fallback %d is empty", i+1)
		}
		extra = append(extra, fb)
	}
	if len(extra) > 0 {
		outs := []proxy.Outbound{out}
		for i, b := range extra {
			if len(b.Backups) > 0 || len(b.Fallbacks) > 0 {
				return nil, fmt.Errorf("v2tun: backup %d has backups of its own; list every backup in the top-level backups", i+1)
			}
			if b.Routing != nil || b.UDPGW != "" || b.DirectDNS != "" {
				return nil, fmt.Errorf("v2tun: backup %d sets routing, udpgw or directDns; those belong to the top-level config", i+1)
			}
			bo, _, err := buildOutbound(b, res)
			if err != nil {
				return nil, fmt.Errorf("v2tun: backup %d: %w", i+1, err)
			}
			outs = append(outs, bo)
		}
		out = &proxy.Failover{Outs: outs, PerTry: time.Duration(cfg.FailoverTimeoutSec) * time.Second}
	}
	c := &Client{out: out, direct: &transport.TCP{Timeout: to, Resolver: res}, resolver: res}
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

// buildOutbound turns one config into an outbound: the dial chain (transport
// layers) with the protocol on top, wrapped in Mux.Cool when asked. It returns
// the connect timeout it used.
func buildOutbound(cfg *Config, res *net.Resolver) (proxy.Outbound, time.Duration, error) {
	if cfg.Server == "" || cfg.Port == 0 {
		return nil, 0, errors.New("v2tun: server and port required")
	}
	if err := checkFlow(cfg); err != nil {
		return nil, 0, err
	}
	if err := checkFingerprints(cfg); err != nil {
		return nil, 0, err
	}
	to := time.Duration(cfg.TimeoutSec) * time.Second
	if to == 0 {
		to = 15 * time.Second
	}
	// chain: tcp -> [payload pre] -> [record layer, Vision only] -> tls|reality -> [payload post] -> ws/httpupgrade
	net_ := strings.ToLower(cfg.Network)
	proto := strings.ToLower(cfg.Protocol)
	isHysteria := proto == "hysteria" || proto == "hysteria1" || proto == "hy" || proto == "hysteria2" || proto == "hy2"
	if isHysteria && (cfg.Payload != nil || cfg.Reality != nil || cfg.Fragment != nil || (net_ != "" && net_ != "tcp")) {
		return nil, 0, errors.New("v2tun: hysteria brings its own QUIC and TLS; payload, reality, fragment and transports do not apply")
	}
	if cfg.Reality != nil && net_ == "quic" {
		return nil, 0, errors.New("v2tun: reality cannot be combined with the quic transport")
	}
	tlsOn := cfg.TLS.Enabled || cfg.Reality != nil
	alpn := cfg.TLS.ALPN
	if len(alpn) == 0 {
		switch net_ {
		case "h2", "grpc", "xhttp", "splithttp":
			alpn = []string{"h2"}
		case "ws", "websocket", "httpupgrade":
			alpn = []string{"http/1.1"}
		}
	}
	d, err := baseChain(cfg, net_, to, alpn, res)
	if err != nil {
		return nil, 0, err
	}
	srv := net.JoinHostPort(cfg.Server, fmt.Sprint(cfg.Port))
	switch net_ {
	case "", "tcp":
	case "h2", "http":
		d = &transport.H2{Inner: d, TLS: tlsOn, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers}
	case "xhttp", "splithttp":
		x := &transport.XHTTP{Inner: d, Server: srv, TLS: tlsOn, SNI: cfg.TLS.SNI, ALPN: alpn,
			Host: cfg.WS.Host, Path: cfg.WS.Path, Mode: cfg.XHTTPMode, Headers: cfg.WS.Headers}
		if o := cfg.XHTTP; o != nil {
			x.XPaddingBytes, x.ScMaxEachPostBytes, x.ScMinPostsIntervalMs = o.XPaddingBytes, o.ScMaxEachPostBytes, o.ScMinPostsIntervalMs
		}
		d = x
	case "grpc":
		d = &transport.GRPC{Inner: d, TLS: tlsOn, Host: cfg.WS.Host, Service: cfg.GRPCService}
	case "quic":
	case "ws", "websocket":
		d = &transport.WebSocket{Inner: d, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers}
	case "httpupgrade":
		d = &transport.WebSocket{Inner: d, Host: cfg.WS.Host, Path: cfg.WS.Path, Headers: cfg.WS.Headers, Upgrade: true}
	default:
		return nil, 0, fmt.Errorf("v2tun: transport %q not implemented yet", cfg.Network)
	}

	var out proxy.Outbound
	muxable := false
	switch proto {
	case "trojan":
		out, muxable = &proxy.Trojan{Server: srv, Dialer: d, Password: cfg.Password}, true
	case "vless":
		out, muxable = &proxy.VLESS{Server: srv, Dialer: d, UUID: cfg.UUID, Flow: strings.ToLower(cfg.Flow)}, true
	case "vmess":
		out, muxable = &proxy.VMess{Server: srv, Dialer: d, UUID: cfg.UUID, AlterID: cfg.AlterID, Security: cfg.Method}, true
	case "shadowsocks", "ss":
		out, muxable = &proxy.Shadowsocks{Server: srv, Dialer: d, Method: cfg.Method, Password: cfg.Password}, true
	case "ssh":
		if pin := cfg.Advanced.SSHHostKey; pin != "" && !proxy.ValidHostKeyPin(pin) {
			return nil, 0, errors.New(`v2tun: advanced.sshHostKey must be "SHA256:..." (as ssh-keygen -l prints it) or 64 hex characters`)
		}
		out = &proxy.SSH{Server: srv, Dialer: d, User: cfg.Username,
			Password: cfg.Password, PrivateKey: readKey(cfg.PrivateKey),
			HostKeySHA256: cfg.Advanced.SSHHostKey,
			Options: proxy.SSHOptions{Ciphers: cfg.Advanced.SSHCiphers, KeyExchanges: cfg.Advanced.SSHKeyExchanges,
				MACs: cfg.Advanced.SSHMACs, HostKeyAlgos: cfg.Advanced.SSHHostKeys}}
	case "socks", "socks5":
		out = &proxy.SOCKS{Server: srv, Dialer: d, Username: cfg.Username, Password: cfg.Password, Version: 5}
	case "socks4", "socks4a":
		out = &proxy.SOCKS{Server: srv, Dialer: d, Username: cfg.Username, Password: cfg.Password, Version: 4}
	case "http", "https":
		if proto == "https" && !tlsOn {
			return nil, 0, errors.New("v2tun: an https proxy needs tls.enabled")
		}
		out = &proxy.HTTPProxy{Server: srv, Dialer: d, Username: cfg.Username, Password: cfg.Password, Headers: cfg.ProxyHeaders}
	case "hysteria2", "hy2":
		hc := cfg.Hysteria
		if hc == nil {
			hc = &HysteriaConfig{}
		}
		out = &proxy.Hysteria2{Server: srv, Password: cfg.Password, SNI: cfg.TLS.SNI, AllowInsecure: cfg.TLS.AllowInsecure,
			PinSHA256: hc.PinSHA256, Obfs: hc.Obfs, DownMbps: hc.DownMbps, Resolver: res}
	case "hysteria", "hysteria1", "hy":
		hc := cfg.Hysteria
		if hc == nil {
			hc = &HysteriaConfig{}
		}
		out = &proxy.Hysteria1{Server: srv, Auth: cfg.Password, SNI: cfg.TLS.SNI, AllowInsecure: cfg.TLS.AllowInsecure,
			ALPN: hc.ALPN, Obfs: hc.Obfs, UpMbps: hc.UpMbps, DownMbps: hc.DownMbps, Resolver: res}
	default:
		return nil, 0, fmt.Errorf("v2tun: unknown protocol %q", cfg.Protocol)
	}
	if cfg.Mux != nil && cfg.Mux.Enabled && muxable {
		out = &proxy.Mux{Base: out, Concurrency: cfg.Mux.Concurrency}
	}
	return out, to, nil
}

// ActiveOutbound tells which config the client currently uses: 0 for the main
// config, 1 for the first backup, and so on.
func (c *Client) ActiveOutbound() int {
	if f, ok := c.out.(*proxy.Failover); ok {
		return f.Current()
	}
	return 0
}

// Close releases long-lived resources: the SSH session, shared Mux.Cool
// connections, Hysteria's QUIC connection and the udpgw stream. A Client that
// is just dropped keeps them (and their keepalive goroutines) alive after the
// VPN stops.
func (c *Client) Close() error {
	if cl, ok := c.out.(io.Closer); ok {
		cl.Close()
	}
	if c.gw != nil {
		c.gw.Close()
	}
	return nil
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
// Order: routing rule, native UDP of the protocol (for a Failover: of any of
// its outbounds), then BadVPN udpgw.
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
		if proxy.SupportsUDP(c.out) {
			conn, err = c.out.(proxy.UDPOutbound).DialUDP(ctx, addr)
		} else if c.gw != nil {
			// udpgw only takes IP targets, but the TUN layer hands over a
			// domain when fake-IP DNS or sniffing recovered one: resolve it
			// here (protected resolver) instead of failing every such flow.
			var ipAddr string
			if ipAddr, err = c.resolveAddr(ctx, addr); err == nil {
				conn, err = c.gw.DialUDP(ctx, ipAddr)
			}
		} else {
			return nil, proxy.ErrNotImplemented
		}
	}
	if err != nil {
		return nil, err
	}
	return countConn{conn}, nil
}

// resolveAddr turns host:port into ip:port using the protected resolver.
// IP literals pass through; IPv4 answers are preferred.
func (c *Client) resolveAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) != nil {
		return addr, nil
	}
	rs := c.resolver
	if rs == nil {
		rs = net.DefaultResolver
	}
	ips, err := rs.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("v2tun: resolve %s: %v", host, err)
	}
	pick := ips[0].IP
	for _, a := range ips {
		if a.IP.To4() != nil {
			pick = a.IP
			break
		}
	}
	return net.JoinHostPort(pick.String(), port), nil
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

// realityDialer validates the REALITY settings and wraps inner with the
// REALITY client handshake.
func realityDialer(cfg *Config, inner transport.Dialer, alpn []string) (transport.Dialer, error) {
	r := cfg.Reality
	pk, err := b64(r.PublicKey)
	if err != nil || len(pk) != 32 {
		return nil, errors.New("v2tun: reality publicKey must be a base64 X25519 key (32 bytes)")
	}
	sid, err := hex.DecodeString(r.ShortID)
	if err != nil || len(sid) > 8 {
		return nil, errors.New("v2tun: reality shortId must be at most 16 hex characters")
	}
	sni := r.ServerName
	if sni == "" {
		sni = cfg.TLS.SNI
	}
	fp := r.Fingerprint
	if fp == "" {
		fp = cfg.TLS.Fingerprint
	}
	return &transport.Reality{Inner: inner, ServerName: sni, PublicKey: pk, ShortID: sid, Fingerprint: fp, ALPN: alpn}, nil
}

// payloadExpectsReply decides whether the HTTP reply to the payload is read
// and dropped before the protocol starts. An explicit expectResponse wins.
// Otherwise: always with a remote proxy, and on a plain tcp stream whenever the
// payload looks like an HTTP request (a preset, or a request line), because
// the server then answers with a status line before the protocol begins, as
// an SSH-WS server does with "101 Switching Protocols". With another transport
// (ws, h2, ...) the payload is front traffic and gets no automatic reply.
func payloadExpectsReply(net_ string, p *PayloadConfig) bool {
	if p.ExpectResponse != nil {
		return *p.ExpectResponse
	}
	if p.Proxy != "" {
		return true
	}
	if net_ != "" && net_ != "tcp" {
		return false
	}
	t := strings.ToLower(p.Template)
	return strings.HasPrefix(strings.TrimSpace(t), "@") || strings.Contains(t, "http/1.") ||
		strings.Contains(t, "[protocol]") || strings.Contains(t, "[netdata]") ||
		strings.Contains(t, "[raw]") || strings.Contains(t, "[real_raw]")
}

// normalizeResponseMap checks a response changer map and lower-cases its keys.
// A key is a status code ("301") or a class ("3xx"); a value is a status code.
func normalizeResponseMap(m map[string]int) (map[string]int, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		k = strings.ToLower(strings.TrimSpace(k))
		isCode := len(k) == 3 && strings.Trim(k, "0123456789") == ""
		isClass := len(k) == 3 && k[1:] == "xx" && k[0] >= '1' && k[0] <= '5'
		if !isCode && !isClass {
			return nil, fmt.Errorf("v2tun: responseMap key %q must be a status code like 301 or a class like 3xx", k)
		}
		if v < 100 || v > 599 {
			return nil, fmt.Errorf("v2tun: responseMap value %d for %q is not a status code", v, k)
		}
		out[k] = v
	}
	return out, nil
}

// baseChain builds tcp -> [payload pre] -> [record layer, Vision only] -> tls|reality -> [payload post] (or QUIC alone).
func baseChain(cfg *Config, net_ string, to time.Duration, alpn []string, res *net.Resolver) (transport.Dialer, error) {
	if net_ == "quic" { // QUIC carries its own TLS; payload and TLS layers don't apply
		return &transport.QUIC{ServerName: cfg.TLS.SNI, ALPN: cfg.TLS.ALPN, AllowInsecure: cfg.TLS.AllowInsecure, Resolver: res}, nil
	}
	var d transport.Dialer = &transport.TCP{Timeout: to, Resolver: res}
	if f := cfg.Fragment; f != nil {
		d = &transport.Fragment{Inner: d, LenMin: f.Length[0], LenMax: f.Length[1], IntMin: f.Interval[0], IntMax: f.Interval[1]}
	}
	psni := cfg.TLS.SNI // value for the payload's [sni]
	if cfg.Reality != nil && cfg.Reality.ServerName != "" {
		psni = cfg.Reality.ServerName
	}
	var pd *transport.Payload
	if p := cfg.Payload; p != nil && p.Template != "" {
		tpl, err := payload.CompileCompat(p.Template)
		if err != nil {
			return nil, err
		}
		rm, err := normalizeResponseMap(p.ResponseMap)
		if err != nil {
			return nil, err
		}
		pd = &transport.Payload{Template: tpl, Host: p.Host, Method: p.Method,
			UserAgent: p.UserAgent, SNI: psni, Vars: p.Vars,
			ExpectResponse: payloadExpectsReply(net_, p), ExpectCodes: p.ExpectCodes,
			Responses: p.ExpectResponses, ResponseMap: rm}
	}
	post := pd != nil && cfg.Payload.Stage == "post-tls"
	if pd != nil && cfg.Payload.Proxy != "" {
		if post {
			return nil, errors.New("v2tun: a payload proxy needs the pre-tls stage")
		}
		if _, _, err := net.SplitHostPort(cfg.Payload.Proxy); err != nil {
			return nil, fmt.Errorf("v2tun: payload proxy must be host:port: %v", err)
		}
		d = &transport.Via{Inner: d, Addr: cfg.Payload.Proxy}
	}
	if pd != nil && !post {
		pd.Inner = d
		d = pd
	}
	if cfg.Flow != "" { // Vision: the record layer must sit directly below TLS / REALITY
		d = &transport.RecordDialer{Inner: d}
	}
	switch {
	case cfg.Reality != nil:
		rd, err := realityDialer(cfg, d, alpn)
		if err != nil {
			return nil, err
		}
		d = rd
	case cfg.TLS.Enabled:
		d = &transport.TLS{Inner: d, ServerName: cfg.TLS.SNI, ALPN: alpn,
			AllowInsecure: cfg.TLS.AllowInsecure, Fingerprint: cfg.TLS.Fingerprint}
	}
	if post {
		pd.Inner = d
		d = pd
	}
	return d, nil
}
