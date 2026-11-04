// Package route decides per connection whether traffic goes through the
// tunnel, directly, or is blocked. Domain rules: "full:x", "domain:x"
// (suffix, also the default for bare names), "keyword:x", "regexp:x".
// IP rules: CIDR/IP or "geoip:private". "list:NAME" pulls entries supplied at
// runtime with SetList (ship your own country lists; no GeoIP db is bundled).
package route

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Action string

const (
	Proxy  Action = "proxy"
	Direct Action = "direct"
	Block  Action = "block"
)

type Rule struct {
	Action  Action   `json:"action"`
	Domain  []string `json:"domain,omitempty"`
	IP      []string `json:"ip,omitempty"`
	Port    string   `json:"port,omitempty"`    // "80,443,1000-2000"
	Network string   `json:"network,omitempty"` // tcp|udp
}

type Config struct {
	Rules          []Rule `json:"rules"`
	Default        Action `json:"default"`        // default proxy
	DomainStrategy string `json:"domainStrategy"` // asis|ipifnonmatch
}

type domMatch struct {
	kind int // 0 suffix, 1 full, 2 keyword, 3 regexp
	s    string
	re   *regexp.Regexp
}

type portRange struct{ lo, hi int }

type matcher struct {
	action  Action
	dom     []domMatch
	ips     []*net.IPNet
	ports   []portRange
	network string
}

type Router struct {
	mu      sync.RWMutex
	cfg     Config
	lists   map[string][]string
	rules   []matcher
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

var privateNets = mustCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
	"169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")

func mustCIDRs(s ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range s {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}

func New(cfg *Config) (*Router, error) {
	r := &Router{cfg: *cfg, lists: map[string][]string{}}
	return r, r.compile()
}

// SetList supplies (or replaces) a named list used by "list:NAME" entries.
func (r *Router) SetList(name string, items []string) error {
	r.mu.Lock()
	r.lists[name] = items
	r.mu.Unlock()
	return r.compile()
}

func (r *Router) expand(entries []string) []string {
	var out []string
	for _, e := range entries {
		if n, ok := strings.CutPrefix(e, "list:"); ok {
			out = append(out, r.lists[n]...)
		} else {
			out = append(out, e)
		}
	}
	return out
}

func (r *Router) compile() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var rules []matcher
	for _, rule := range r.cfg.Rules {
		m := matcher{action: rule.Action, network: strings.ToLower(rule.Network)}
		if m.action == "" {
			m.action = Proxy
		}
		for _, e := range r.expand(rule.Domain) {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" || strings.HasPrefix(e, "#") {
				continue
			}
			d := domMatch{s: e}
			switch {
			case strings.HasPrefix(e, "full:"):
				d.kind, d.s = 1, e[5:]
			case strings.HasPrefix(e, "domain:"):
				d.s = e[7:]
			case strings.HasPrefix(e, "keyword:"):
				d.kind, d.s = 2, e[8:]
			case strings.HasPrefix(e, "regexp:"):
				re, err := regexp.Compile(e[7:])
				if err != nil {
					return err
				}
				d.kind, d.re = 3, re
			case strings.HasPrefix(e, "geosite:"):
				return fmt.Errorf("route: %q needs a list; use list:NAME with SetList", e)
			}
			m.dom = append(m.dom, d)
		}
		for _, e := range r.expand(rule.IP) {
			e = strings.TrimSpace(e)
			if e == "" || strings.HasPrefix(e, "#") {
				continue
			}
			if e == "geoip:private" {
				m.ips = append(m.ips, privateNets...)
				continue
			}
			if strings.HasPrefix(e, "geoip:") {
				return fmt.Errorf("route: %q needs a list; use list:NAME with SetList", e)
			}
			if !strings.Contains(e, "/") {
				if strings.Contains(e, ":") {
					e += "/128"
				} else {
					e += "/32"
				}
			}
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				return err
			}
			m.ips = append(m.ips, n)
		}
		for _, p := range strings.Split(rule.Port, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			lo, hi, _ := strings.Cut(p, "-")
			a, err := strconv.Atoi(lo)
			if err != nil {
				return err
			}
			b := a
			if hi != "" {
				if b, err = strconv.Atoi(hi); err != nil {
					return err
				}
			}
			m.ports = append(m.ports, portRange{a, b})
		}
		rules = append(rules, m)
	}
	r.rules = rules
	return nil
}

func (m *matcher) domOK(host string) bool {
	for _, d := range m.dom {
		switch d.kind {
		case 0:
			if host == d.s || strings.HasSuffix(host, "."+d.s) {
				return true
			}
		case 1:
			if host == d.s {
				return true
			}
		case 2:
			if strings.Contains(host, d.s) {
				return true
			}
		case 3:
			if d.re.MatchString(host) {
				return true
			}
		}
	}
	return false
}

func (m *matcher) ipOK(ip net.IP) bool {
	for _, n := range m.ips {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *matcher) basic(network string, port int) bool {
	if m.network != "" && m.network != network {
		return false
	}
	if len(m.ports) > 0 {
		ok := false
		for _, p := range m.ports {
			if port >= p.lo && port <= p.hi {
				ok = true
			}
		}
		return ok
	}
	return true
}

// Decide returns the action for a connection to host:port.
func (r *Router) Decide(ctx context.Context, network, host string, port int) Action {
	r.mu.RLock()
	rules, cfg := r.rules, r.cfg
	r.mu.RUnlock()
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host)
	for i := range rules {
		m := &rules[i]
		if !m.basic(network, port) {
			continue
		}
		if len(m.dom) > 0 && (ip != nil || !m.domOK(host)) {
			continue
		}
		if len(m.ips) > 0 && (ip == nil || !m.ipOK(ip)) {
			continue
		}
		return m.action
	}
	if ip == nil && cfg.DomainStrategy == "ipifnonmatch" && r.Resolve != nil {
		if ips, err := r.Resolve(ctx, host); err == nil {
			for i := range rules {
				m := &rules[i]
				if len(m.ips) == 0 || len(m.dom) > 0 || !m.basic(network, port) {
					continue
				}
				for _, rip := range ips {
					if m.ipOK(rip) {
						return m.action
					}
				}
			}
		}
	}
	if cfg.Default != "" {
		return cfg.Default
	}
	return Proxy
}
