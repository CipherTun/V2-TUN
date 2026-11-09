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

// jsonUnmarshal is json.Unmarshal for a string (used by the log summary).
func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }

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
	if err := c.SetRouting(&cfg); err != nil {
		mlog.Warn("routing update rejected", "err", err)
		return err
	}
	mlog.Info("routing updated")
	return nil
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

// ValidatePayload reports whether a payload template compiles. It accepts the
// same HTTP Injector spellings as the tunnel itself ([ssh], [real_raw],
// [b64=random16]). Presets are gone, so a bare "@name" is reported as invalid.
func ValidatePayload(template string) error {
	_, err := payload.CompileCompat(template)
	return err
}

// PreviewPayload renders a template and returns it with visible \r\n and
// markers where it is split or paused. host is the payload host ([host], the
// bug host), server the real server ([server], [server_host_port]); an empty
// server means the same as host. The template is compiled the way the tunnel
// compiles it, so aliases such as [ssh] preview as they will be sent.
func PreviewPayload(template, host, server string, port int) (string, error) {
	t, err := payload.CompileCompat(template)
	if err != nil {
		return "", err
	}
	if server == "" {
		server = host
	}
	return t.Preview(payload.Context{Host: host, Port: port, Server: server, ServerPort: port, IP: server}), nil
}

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
		mlog.Warn("start ignored: the vpn tunnel is already running")
		return errors.New("v2tun: tun already running")
	}
	if cancel != nil { // the SOCKS server owns `active`
		mlog.Warn("start ignored: the socks server is running")
		return errors.New("v2tun: socks server running; call Stop first")
	}
	mlog.Info("starting the vpn tunnel", append(summary(configJSON), "mtu", mtu, "dns", dns, "fakeDns", fakeDNS, "sniff", sniff)...)
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
		mlog.Error("could not start the tun stack", "err", err)
		return err
	}
	tunInst, active = t, c
	mlog.Info("vpn tunnel running")
	return nil
}

// StopTun tears the TUN stack down and closes the tunnel's long-lived
// connections (SSH session, mux, udpgw).
func StopTun() {
	mu.Lock()
	defer mu.Unlock()
	if tunInst != nil {
		mlog.Info("stopping the vpn tunnel")
		tunInst.Close()
		tunInst = nil
		if active != nil {
			active.Close()
			active = nil
		}
		mlog.Info("vpn tunnel stopped")
	}
}

var (
	mu     sync.Mutex
	cancel context.CancelFunc
)

func newClient(configJSON string) (*v2tun.Client, error) {
	var cfg v2tun.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		mlog.Error("the config is not valid JSON", "err", err)
		return nil, err
	}
	c, err := v2tun.New(&cfg)
	if err != nil {
		mlog.Error("the config cannot be used", append(describeConfig(&cfg), "err", err)...)
		return nil, err
	}
	mlog.Debug("tunnel client ready", describeConfig(&cfg)...)
	return c, nil
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
	t0 := time.Now()
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		mlog.Warn("probe failed", "target", target, "err", err)
		return err
	}
	mlog.Info("probe ok", "target", target, "ms", time.Since(t0).Milliseconds())
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
		mlog.Warn("start ignored: the socks server is already running")
		return errors.New("v2tun: already running")
	}
	if tunInst != nil { // the TUN stack owns `active`
		mlog.Warn("start ignored: the vpn tunnel is running")
		return errors.New("v2tun: tun running; call StopTun first")
	}
	mlog.Info("starting the socks server", append(summary(configJSON), "listen", listenAddr)...)
	c, err := newClient(configJSON)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		c.Close()
		mlog.Error("could not listen for the socks server", "listen", listenAddr, "err", err)
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
		mlog.Info("stopping the socks server")
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
		mlog.Warn("share link could not be parsed", "err", err)
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
	if err != nil {
		mlog.Warn("ping failed", "url", url, "err", err)
	} else {
		mlog.Info("ping ok", "url", url, "ms", d.Milliseconds())
	}
	return d.Milliseconds(), err
}

func TrafficUp() int64   { u, _ := v2tun.Traffic(); return u }
func TrafficDown() int64 { _, d := v2tun.Traffic(); return d }
func ResetTraffic()      { v2tun.ResetTraffic() }
