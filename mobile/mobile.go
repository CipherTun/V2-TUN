// Package mobile is the gomobile-friendly surface (strings and primitives only).
//
//	gomobile bind -target=android -javapkg=io.surprise -o v2tun.aar io.surprise.vpn/mobile
package mobile

import (
	"context"
	"strings"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	v2tun "io.surprise.vpn"
	"io.surprise.vpn/socks"
	"io.surprise.vpn/transport"
	"io.surprise.vpn/tun"
)

// Protector is implemented in Kotlin: return VpnService.protect(fd).
type Protector interface{ Protect(fd int) bool }

// SetProtector must be called before Start/StartTun/Probe while the VPN is up.
func SetProtector(p Protector) { transport.SetProtector(p.Protect) }

var (
	tunInst *tun.Tun
	active  *v2tun.Client
)

// SetRouteList supplies a named list for "list:NAME" routing entries.
// items: one domain/CIDR per line. Call after Start/StartTun/StartTunEx.
func SetRouteList(name, items string) error {
	mu.Lock()
	c := active
	mu.Unlock()
	if c == nil {
		return errors.New("v2tun: not running")
	}
	return c.SetRouteList(name, strings.Split(items, "\n"))
}

// StartTun routes the TUN fd through the tunnel with default options.
func StartTun(configJSON string, fd int, mtu int, dns string) error {
	return StartTunEx(configJSON, fd, mtu, dns, false, false)
}

// StartTunEx adds fake-IP DNS (domain routing for DNS-based apps) and
// SNI/Host sniffing. dns example: "1.1.1.1:53".
func StartTunEx(configJSON string, fd int, mtu int, dns string, fakeDNS, sniff bool) error {
	mu.Lock()
	defer mu.Unlock()
	if tunInst != nil {
		return errors.New("v2tun: tun already running")
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
		return err
	}
	tunInst, active = t, c
	return nil
}

// StopTun tears the TUN stack down.
func StopTun() {
	mu.Lock()
	defer mu.Unlock()
	if tunInst != nil {
		tunInst.Close()
		tunInst, active = nil, nil
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
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		return errors.New("v2tun: already running")
	}
	c, err := newClient(configJSON)
	if err != nil {
		return err
	}
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	ctx, cf := context.WithCancel(context.Background())
	cancel = cf
	active = c
	go socks.Serve(ctx, l, c)
	return nil
}

// Stop shuts the SOCKS5 server down.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		cancel()
		cancel = nil
		if tunInst == nil {
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
	d, err := c.Ping(context.Background(), url)
	return d.Milliseconds(), err
}

func TrafficUp() int64   { u, _ := v2tun.Traffic(); return u }
func TrafficDown() int64 { _, d := v2tun.Traffic(); return d }
func ResetTraffic()      { v2tun.ResetTraffic() }
