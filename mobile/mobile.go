// Package mobile is the gomobile-friendly surface (strings and primitives only).
//
//	gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	v2tun "io.surprise.vpn"
	"io.surprise.vpn/payload"
	"io.surprise.vpn/route"
	"io.surprise.vpn/socks"
	"io.surprise.vpn/transport"
	"io.surprise.vpn/tun"
)

// Protector is implemented in Kotlin: return VpnService.protect(fd).
type Protector interface{ Protect(fd int) bool }

// SetProtector must be called before Start/StartTun/Probe while the VPN is up.
func SetProtector(p Protector) {
	if p == nil {
		return
	}
	transport.SetProtector(p.Protect)
}

var (
	tunInst *tun.Tun
	active  *v2tun.Client
)

func running() (*v2tun.Client, error) {
	mu.Lock()
	c := active
	mu.Unlock()
	if c == nil {
		return nil, errors.New("v2tun: not running")
	}
	return c, nil
}

// SetRouteList supplies a named list for "list:NAME", "geoip:XX" and
// "geosite:XX" routing entries. items: one domain/CIDR per line.
// Call after Start/StartTun/StartTunEx.
func SetRouteList(name, items string) error {
	c, err := running()
	if err != nil {
		return err
	}
	return c.SetRouteList(name, strings.Split(items, "\n"))
}

// SetRouteLists supplies several lists at once, with one rebuild of the rules.
// listsJSON: {"geoip:cn":["1.0.1.0/24", ...], "list:ads":["domain:x.com", ...]}
func SetRouteLists(listsJSON string) error {
	c, err := running()
	if err != nil {
		return err
	}
	var lists map[string][]string
	if err := json.Unmarshal([]byte(listsJSON), &lists); err != nil {
		return err
	}
	return c.SetRouteLists(lists)
}

// UpdateRouting swaps the routing section (rules, split tunneling, switches)
// while connected. routingJSON is the same object as "routing" in the config.
// The config the VPN started with must contain a "routing" section (may be {}).
func UpdateRouting(routingJSON string) error {
	c, err := running()
	if err != nil {
		return err
	}
	var cfg route.Config
	if err := json.Unmarshal([]byte(routingJSON), &cfg); err != nil {
		return err
	}
	return c.SetRouting(&cfg)
}

// ExplainRoute reports how a connection would be routed, as JSON:
// {"action":"direct","rule":"builtin:lan-ip"}. network is "tcp" or "udp",
// addr is "host:port", protocol (http, tls, bittorrent, ssh) may be empty.
func ExplainRoute(network, addr, protocol string) (string, error) {
	c, err := running()
	if err != nil {
		return "", err
	}
	ctx := context.Background()
	if protocol != "" {
		ctx = route.WithProtocol(ctx, protocol)
	}
	d, err := c.Explain(ctx, network, addr)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]string{"action": string(d.Action), "rule": d.Rule})
	return string(b), err
}

// ValidatePayload reports whether a payload template compiles.
func ValidatePayload(template string) error { return payload.Validate(template) }

// PreviewPayload renders a template with the given server host and port and
// returns it with visible \r\n and markers where it is split or paused.
func PreviewPayload(template, host string, port int) (string, error) {
	t, err := payload.Compile(template)
	if err != nil {
		return "", err
	}
	return t.Preview(payload.Context{Host: host, Port: port}), nil
}

// PayloadPresets lists the built-in payload presets, one per line.
func PayloadPresets() string { return strings.Join(payload.PresetNames(), "\n") }

// StartTun routes the TUN fd through the tunnel with default options.
func StartTun(configJSON string, fd int, mtu int, dns string) error {
	return StartTunEx(configJSON, fd, mtu, dns, false, false)
}

// StartTunEx adds fake-IP DNS (domain routing for DNS-based apps) and
// SNI/Host/protocol sniffing (needed for protocol rules). dns example: "1.1.1.1:53".
func StartTunEx(configJSON string, fd int, mtu int, dns string, fakeDNS, sniff bool) error {
	mu.Lock()
	defer mu.Unlock()
	if tunInst != nil {
		return errors.New("v2tun: tun already running")
	}
	if cancel != nil { // the SOCKS server owns `active`
		return errors.New("v2tun: socks server running; call Stop first")
	}
	c, err := newClient(configJSON)
	if err != nil {
		return err
	}
	o := tun.Options{FD: fd, MTU: uint32(mtu), DNS: dns, Dialer: c, UDP: c, Sniff: sniff}
	if fakeDNS {
		o.Fake = tun.NewFakeDNS()
		if o.DNS == "" {
			o.DNS = "1.1.1.1:53"
		}
	}
	t, err := tun.Start(o)
	if err != nil {
		c.Close()
		return err
	}
	tunInst, active = t, c
	return nil
}

// StopTun tears the TUN stack down and closes the tunnel's long-lived
// connections (SSH session, mux, udpgw).
func StopTun() {
	mu.Lock()
	defer mu.Unlock()
	if tunInst != nil {
		tunInst.Close()
		tunInst = nil
		if active != nil {
			active.Close()
			active = nil
		}
	}
}

var (
	mu     sync.Mutex
	cancel context.CancelFunc
)

func newClient(configJSON string) (*v2tun.Client, error) {
	var cfg v2tun.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, err
	}
	return v2tun.New(&cfg)
}

// Probe dials target (e.g. "example.com:443") through the config and closes.
func Probe(configJSON, target string) error {
	c, err := newClient(configJSON)
	if err != nil {
		return err
	}
	defer c.Close() // a throwaway client must not leave an SSH session behind
	ctx, cf := context.WithTimeout(context.Background(), 20*time.Second)
	defer cf()
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// Start runs a local SOCKS5 server (e.g. "127.0.0.1:10808") through the tunnel.
func Start(configJSON, listenAddr string) error {
	return StartEx(configJSON, listenAddr, "", "")
}

// StartEx is Start with optional SOCKS5 username/password (both empty = no
// authentication). The server supports CONNECT and UDP ASSOCIATE. Without a
// password every app on the device can use the listener.
func StartEx(configJSON, listenAddr, username, password string) error {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		return errors.New("v2tun: already running")
	}
	if tunInst != nil { // the TUN stack owns `active`
		return errors.New("v2tun: tun running; call StopTun first")
	}
	c, err := newClient(configJSON)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		c.Close()
		return err
	}
	ctx, cf := context.WithCancel(context.Background())
	cancel = cf
	active = c
	go socks.ServeOpts(ctx, l, c, socks.Options{Username: username, Password: password, UDP: c})
	return nil
}

// Stop shuts the SOCKS5 server down and closes the tunnel's long-lived connections.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
		cancel = nil
		if active != nil {
			active.Close()
			active = nil
		}
	}
}

// ParseLink converts a vless/vmess/trojan/ss/ssh share link into a JSON config.
// The returned JSON also carries the display name under "name".
func ParseLink(link string) (string, error) {
	cfg, name, err := v2tun.ParseLink(link)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(struct {
		*v2tun.Config
		Name string `json:"name"`
	}{cfg, name})
	return string(b), err
}

// Ping returns latency in milliseconds through the given config.
func Ping(configJSON, url string) (int64, error) {
	c, err := newClient(configJSON)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	d, err := c.Ping(context.Background(), url)
	return d.Milliseconds(), err
}

func TrafficUp() int64   { u, _ := v2tun.Traffic(); return u }
func TrafficDown() int64 { _, d := v2tun.Traffic(); return d }
func ResetTraffic()      { v2tun.ResetTraffic() }
