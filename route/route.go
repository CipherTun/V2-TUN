// Package route decides per connection whether traffic goes through the
// tunnel, directly, or is blocked.
//
// Domain entries: "full:x", "domain:x" (suffix; also the default for bare
// names), "keyword:x", "regexp:x", "dotless:" (single-label names such as
// "router"). IP entries: CIDR or address, "geoip:private". Port lists: "80,443,1000-2000".
//
// "list:NAME" entries pull items supplied at runtime with SetList. "geoip:XX"
// and "geosite:XX" entries use the list stored under exactly that name, so
// SetList("geoip:cn", cidrs) feeds every {"ip":["geoip:cn"]} rule. No country
// database is bundled; bring your own lists.
//
// A rule that names domains or IPs but currently has no entries (for example
// a list that was not supplied yet) never matches. It does not fall through
// to "match everything".
//
// Rule fields are ANDed; "not*" fields exclude. Besides domain/ip/port/network a
// rule can match the sniffed protocol (http, tls, bittorrent, ssh; needs
// sniffing enabled on the TUN), a time-of-day window ("22:00-06:00") and weekdays.
//
// Config.Split adds split tunneling: mode "bypass" sends the listed
// domains/IPs/ports directly and everything else through the tunnel; mode
// "only" tunnels just the listed traffic. (Per-app split tunneling is done by
// the Android VpnService; see the README.) Config.BypassLAN, BlockQUIC and
// BlockBitTorrent are one-switch conveniences.
package route

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Action string

const (
	Proxy  Action = "proxy"
	Direct Action = "direct"
	Block  Action = "block"
)

// normAction accepts the aliases bypass (=direct) and reject/drop (=block).
func normAction(a Action) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(string(a))) {
	case "", "proxy":
		return Proxy, nil
	case "direct", "bypass":
		return Direct, nil
	case "block", "reject", "drop":
		return Block, nil
	}
	return "", fmt.Errorf("route: unknown action %q", a)
}

type Rule struct {
	Name      string   `json:"name,omitempty"`
	Action    Action   `json:"action"`
	Domain    []string `json:"domain,omitempty"`
	IP        []string `json:"ip,omitempty"`
	Port      string   `json:"port,omitempty"`     // "80,443,1000-2000"
	Network   string   `json:"network,omitempty"`  // tcp|udp
	Protocol  []string `json:"protocol,omitempty"` // sniffed: http|tls|bittorrent|ssh
	NotDomain []string `json:"notDomain,omitempty"`
	NotIP     []string `json:"notIp,omitempty"`
	NotPort   string   `json:"notPort,omitempty"`
	Time      string   `json:"time,omitempty"` // local time window "22:00-06:00"
	Days      []string `json:"days,omitempty"` // mon..sun, weekday, weekend
}

// Split configures split tunneling by destination.
type Split struct {
	Mode   string   `json:"mode"` // off | bypass (listed -> direct) | only (listed -> tunnel, rest direct)
	Domain []string `json:"domain,omitempty"`
	IP     []string `json:"ip,omitempty"`
	Port   string   `json:"port,omitempty"`
}

type Config struct {
	Rules           []Rule `json:"rules"`
	Default         Action `json:"default"`        // default proxy
	DomainStrategy  string `json:"domainStrategy"` // asis | ipifnonmatch | ipondemand
	Split           *Split `json:"split,omitempty"`
	BypassLAN       bool   `json:"bypassLan,omitempty"`       // private ranges and *.local, *.lan, single-label names go direct
	BlockQUIC       bool   `json:"blockQuic,omitempty"`       // drop UDP/443 so browsers fall back to TCP
	BlockBitTorrent bool   `json:"blockBittorrent,omitempty"` // needs sniffing
}

// Meta describes one connection attempt.
type Meta struct {
	Network  string // tcp | udp
	Host     string
	Port     int
	Protocol string    // sniffed protocol, may be empty
	Now      time.Time // zero => time.Now()
}

// Decision is the verdict plus the rule that produced it.
type Decision struct {
	Action Action
	Rule   string // rule name, "builtin:...", "split:..." or "default"
}

type ctxKey struct{}

// WithProtocol attaches the sniffed protocol to ctx so Decide can match
// protocol rules.
func WithProtocol(ctx context.Context, p string) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// ProtocolFrom returns the protocol attached with WithProtocol.
func ProtocolFrom(ctx context.Context) string {
	p, _ := ctx.Value(ctxKey{}).(string)
	return p
}

// ---- domain and IP sets ----

type domSet struct {
	suffix  map[string]struct{}
	full    map[string]struct{}
	kw      []string
	re      []*regexp.Regexp
	dotless bool
	n       int
}

func newDomSet() *domSet {
	return &domSet{suffix: map[string]struct{}{}, full: map[string]struct{}{}}
}

func (d *domSet) empty() bool { return d == nil || d.n == 0 }

func (d *domSet) add(s string) error {
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "regexp:") {
		if i := strings.IndexAny(low, " \t"); i > 0 { // v2fly list attributes ("@cn")
			low = low[:i]
		}
	}
	switch {
	case strings.HasPrefix(low, "include:"):
		return nil
	case strings.HasPrefix(low, "regexp:"):
		re, err := regexp.Compile("(?i)" + s[len("regexp:"):])
		if err != nil {
			return err
		}
		d.re = append(d.re, re)
	case strings.HasPrefix(low, "full:"):
		d.full[strings.TrimSuffix(low[len("full:"):], ".")] = struct{}{}
	case strings.HasPrefix(low, "domain:"):
		d.suffix[strings.TrimSuffix(low[len("domain:"):], ".")] = struct{}{}
	case strings.HasPrefix(low, "suffix:"):
		d.suffix[strings.TrimSuffix(low[len("suffix:"):], ".")] = struct{}{}
	case strings.HasPrefix(low, "keyword:"):
		d.kw = append(d.kw, low[len("keyword:"):])
	case strings.HasPrefix(low, "dotless:"):
		d.dotless = true
	default:
		d.suffix[strings.TrimSuffix(low, ".")] = struct{}{}
	}
	d.n++
	return nil
}

func (d *domSet) match(host string) bool {
	if _, ok := d.full[host]; ok {
		return true
	}
	// "domain:x" matches x and every subdomain: walk the labels.
	for h := host; ; {
		if _, ok := d.suffix[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	if d.dotless && !strings.Contains(host, ".") {
		return true
	}
	for _, k := range d.kw {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, re := range d.re {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

type rng4 struct{ lo, hi uint64 }

type ipSet struct {
	v4 []rng4 // sorted, merged
	v6 []*net.IPNet
	n  int
}

func (s *ipSet) empty() bool { return s == nil || s.n == 0 }

func (s *ipSet) addNet(n *net.IPNet) {
	ones, bits := n.Mask.Size()
	if v4 := n.IP.To4(); v4 != nil && bits == 32 {
		m := ^uint32(0) << uint(32-ones)
		lo := binary.BigEndian.Uint32(v4) & m
		s.v4 = append(s.v4, rng4{uint64(lo), uint64(lo | ^m)})
		return
	}
	s.v6 = append(s.v6, n)
}

func (s *ipSet) add(e string) error {
	low := strings.ToLower(e)
	if low == "geoip:private" || low == "geoip:lan" {
		for _, n := range privateNets {
			s.addNet(n)
		}
		s.n++
		return nil
	}
	if !strings.Contains(e, "/") {
		ip := net.ParseIP(e)
		if ip == nil {
			return fmt.Errorf("route: bad ip %q", e)
		}
		if ip.To4() != nil {
			e += "/32"
		} else {
			e += "/128"
		}
	}
	_, n, err := net.ParseCIDR(e)
	if err != nil {
		return err
	}
	s.addNet(n)
	s.n++
	return nil
}

func (s *ipSet) finish() {
	sort.Slice(s.v4, func(i, j int) bool { return s.v4[i].lo < s.v4[j].lo })
	var out []rng4
	for _, r := range s.v4 {
		if k := len(out) - 1; k >= 0 && r.lo <= out[k].hi+1 {
			if r.hi > out[k].hi {
				out[k].hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	s.v4 = out
}

func (s *ipSet) contains(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		v := uint64(binary.BigEndian.Uint32(v4))
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].hi >= v })
		return i < len(s.v4) && s.v4[i].lo <= v
	}
	for _, n := range s.v6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
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

// ---- compiled rules ----

type portRange struct{ lo, hi int }

type matcher struct {
	name    string
	action  Action
	network string

	dom, ndom       *domSet
	ips, nips       *ipSet
	hasDom, hasIP   bool // the rule lists domains / IPs (possibly all still empty)
	hasNDom, hasNIP bool

	ports, nports []portRange
	protos        map[string]bool

	hasTime bool
	t0, t1  int   // minutes since midnight
	days    uint8 // bit per time.Weekday (Sunday = bit 0)
}

type entry struct {
	s    string
	list bool // came from a runtime list: bad lines are skipped, not fatal
}

type Router struct {
	mu       sync.RWMutex
	cfg      Config
	lists    map[string][]string
	rules    []matcher
	def      Action
	strategy string

	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

func New(cfg *Config) (*Router, error) {
	r := &Router{cfg: *cfg, lists: map[string][]string{}}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r, r.rebuild()
}

func listKey(name string) string {
	low := strings.ToLower(name)
	if strings.HasPrefix(low, "geoip:") || strings.HasPrefix(low, "geosite:") {
		return low
	}
	return name
}

// SetList supplies (or replaces) a named list. Names "geoip:XX" and
// "geosite:XX" are matched case-insensitively.
func (r *Router) SetList(name string, items []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lists[listKey(name)] = items
	return r.rebuild()
}

// SetLists replaces several lists with a single rebuild.
func (r *Router) SetLists(lists map[string][]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, items := range lists {
		r.lists[listKey(name)] = items
	}
	return r.rebuild()
}

// Reconfigure swaps the rule set at runtime; supplied lists are kept. On error
// the previous configuration stays active.
func (r *Router) Reconfigure(cfg *Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.cfg
	r.cfg = *cfg
	if err := r.rebuild(); err != nil {
		r.cfg = old
		return err
	}
	return nil
}

// rebuild recompiles the rules; the caller holds r.mu.
func (r *Router) rebuild() error {
	rules, def, strat, err := r.build()
	if err != nil {
		return err
	}
	r.rules, r.def, r.strategy = rules, def, strat
	return nil
}

func (r *Router) expand(in []string, fromList bool, depth int) []entry {
	var out []entry
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		low := strings.ToLower(e)
		if n, ok := strings.CutPrefix(e, "list:"); ok {
			if depth < 3 {
				out = append(out, r.expand(r.lists[n], true, depth+1)...)
			}
			continue
		}
		if (strings.HasPrefix(low, "geoip:") || strings.HasPrefix(low, "geosite:")) && low != "geoip:private" && low != "geoip:lan" {
			if depth < 3 {
				out = append(out, r.expand(r.lists[low], true, depth+1)...)
			}
			continue
		}
		out = append(out, entry{e, fromList})
	}
	return out
}

func (r *Router) domains(in []string) (*domSet, error) {
	ds := newDomSet()
	for _, e := range r.expand(in, false, 0) {
		if err := ds.add(e.s); err != nil && !e.list {
			return nil, err
		}
	}
	return ds, nil
}

func (r *Router) ipSet(in []string) (*ipSet, error) {
	s := &ipSet{}
	for _, e := range r.expand(in, false, 0) {
		if err := s.add(e.s); err != nil && !e.list {
			return nil, err
		}
	}
	s.finish()
	return s, nil
}

func parsePorts(spec string) ([]portRange, error) {
	var out []portRange
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lo, hi, _ := strings.Cut(p, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 0 || a > 65535 {
			return nil, fmt.Errorf("route: bad port %q", p)
		}
		b := a
		if hi != "" {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("route: bad port range %q", p)
			}
		}
		out = append(out, portRange{a, b})
	}
	if strings.TrimSpace(spec) != "" && len(out) == 0 {
		return nil, fmt.Errorf("route: bad port list %q", spec)
	}
	return out, nil
}

func inRanges(rs []portRange, port int) bool {
	for _, p := range rs {
		if port >= p.lo && port <= p.hi {
			return true
		}
	}
	return false
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("route: bad time %q (want HH:MM)", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || (hh == 24 && mm != 0) {
		return 0, fmt.Errorf("route: bad time %q (want HH:MM)", s)
	}
	return hh*60 + mm, nil
}

var dayBits = map[string]uint8{"sun": 1 << 0, "mon": 1 << 1, "tue": 1 << 2, "wed": 1 << 3, "thu": 1 << 4, "fri": 1 << 5, "sat": 1 << 6}

func parseDays(days []string) (uint8, error) {
	var mask uint8
	for _, d := range days {
		d = strings.ToLower(strings.TrimSpace(d))
		switch d {
		case "weekday", "weekdays":
			mask |= dayBits["mon"] | dayBits["tue"] | dayBits["wed"] | dayBits["thu"] | dayBits["fri"]
			continue
		case "weekend", "weekends":
			mask |= dayBits["sat"] | dayBits["sun"]
			continue
		case "daily", "all", "":
			mask |= 0x7f
			continue
		}
		if len(d) < 3 {
			return 0, fmt.Errorf("route: bad day %q", d)
		}
		b, ok := dayBits[d[:3]]
		if !ok {
			return 0, fmt.Errorf("route: bad day %q", d)
		}
		mask |= b
	}
	return mask, nil
}

func (r *Router) compileRule(rule Rule) (matcher, error) {
	act, err := normAction(rule.Action)
	if err != nil {
		return matcher{}, err
	}
	m := matcher{name: rule.Name, action: act, network: strings.ToLower(strings.TrimSpace(rule.Network)),
		hasDom: len(rule.Domain) > 0, hasIP: len(rule.IP) > 0,
		hasNDom: len(rule.NotDomain) > 0, hasNIP: len(rule.NotIP) > 0}
	if m.network != "" && m.network != "tcp" && m.network != "udp" {
		return m, fmt.Errorf("route: bad network %q", rule.Network)
	}
	if m.hasDom {
		if m.dom, err = r.domains(rule.Domain); err != nil {
			return m, err
		}
	}
	if m.hasIP {
		if m.ips, err = r.ipSet(rule.IP); err != nil {
			return m, err
		}
	}
	if m.hasNDom {
		if m.ndom, err = r.domains(rule.NotDomain); err != nil {
			return m, err
		}
	}
	if m.hasNIP {
		if m.nips, err = r.ipSet(rule.NotIP); err != nil {
			return m, err
		}
	}
	if m.ports, err = parsePorts(rule.Port); err != nil {
		return m, err
	}
	if m.nports, err = parsePorts(rule.NotPort); err != nil {
		return m, err
	}
	if len(rule.Protocol) > 0 {
		m.protos = map[string]bool{}
		for _, p := range rule.Protocol {
			m.protos[strings.ToLower(strings.TrimSpace(p))] = true
		}
	}
	if t := strings.TrimSpace(rule.Time); t != "" {
		a, b, ok := strings.Cut(t, "-")
		if !ok {
			return m, fmt.Errorf("route: bad time window %q (want HH:MM-HH:MM)", t)
		}
		if m.t0, err = parseClock(a); err != nil {
			return m, err
		}
		if m.t1, err = parseClock(b); err != nil {
			return m, err
		}
		m.hasTime = true
	}
	if len(rule.Days) > 0 {
		if m.days, err = parseDays(rule.Days); err != nil {
			return m, err
		}
	}
	return m, nil
}

// build turns the configuration into matchers; the caller holds r.mu.
func (r *Router) build() ([]matcher, Action, string, error) {
	cfg := &r.cfg
	var rs []Rule
	if cfg.BlockBitTorrent {
		rs = append(rs, Rule{Name: "builtin:block-bittorrent", Action: Block, Protocol: []string{"bittorrent"}})
	}
	if cfg.BlockQUIC {
		rs = append(rs, Rule{Name: "builtin:block-quic", Action: Block, Network: "udp", Port: "443"})
	}
	if cfg.BypassLAN {
		rs = append(rs,
			Rule{Name: "builtin:lan-ip", Action: Direct, IP: []string{"geoip:private"}},
			Rule{Name: "builtin:lan-name", Action: Direct,
				Domain: []string{"full:localhost", "domain:local", "domain:lan", "domain:home.arpa", "dotless:"}})
	}
	for i, rule := range cfg.Rules {
		if rule.Name == "" {
			rule.Name = "rule#" + strconv.Itoa(i+1)
		}
		rs = append(rs, rule)
	}
	def, err := normAction(cfg.Default)
	if err != nil {
		return nil, "", "", err
	}
	if sp := cfg.Split; sp != nil {
		mode := strings.ToLower(strings.TrimSpace(sp.Mode))
		switch mode {
		case "", "off":
		case "bypass", "only":
			act := Direct
			if mode == "only" {
				act = Proxy
				def = Direct
			}
			if len(sp.Domain) > 0 {
				rs = append(rs, Rule{Name: "split:domain", Action: act, Domain: sp.Domain})
			}
			if len(sp.IP) > 0 {
				rs = append(rs, Rule{Name: "split:ip", Action: act, IP: sp.IP})
			}
			if strings.TrimSpace(sp.Port) != "" {
				rs = append(rs, Rule{Name: "split:port", Action: act, Port: sp.Port})
			}
		default:
			return nil, "", "", fmt.Errorf("route: unknown split mode %q", sp.Mode)
		}
	}
	strat := strings.ToLower(strings.TrimSpace(cfg.DomainStrategy))
	switch strat {
	case "", "asis", "ipifnonmatch", "ipondemand":
	default:
		return nil, "", "", fmt.Errorf("route: unknown domainStrategy %q", cfg.DomainStrategy)
	}
	out := make([]matcher, 0, len(rs))
	for _, rule := range rs {
		m, err := r.compileRule(rule)
		if err != nil {
			return nil, "", "", err
		}
		out = append(out, m)
	}
	return out, def, strat, nil
}

// ---- matching ----

func (m *matcher) timeOK(now time.Time) bool {
	if !m.hasTime && m.days == 0 {
		return true
	}
	if now.IsZero() {
		now = time.Now()
	}
	if m.days != 0 && m.days&(1<<uint(now.Weekday())) == 0 {
		return false
	}
	if m.hasTime {
		cur := now.Hour()*60 + now.Minute()
		if m.t0 <= m.t1 {
			return cur >= m.t0 && cur < m.t1
		}
		return cur >= m.t0 || cur < m.t1 // window crosses midnight
	}
	return true
}

func (m *matcher) basic(meta *Meta) bool {
	if m.network != "" && m.network != meta.Network {
		return false
	}
	if len(m.ports) > 0 && !inRanges(m.ports, meta.Port) {
		return false
	}
	if len(m.nports) > 0 && inRanges(m.nports, meta.Port) {
		return false
	}
	if len(m.protos) > 0 && !m.protos[meta.Protocol] {
		return false
	}
	return m.timeOK(meta.Now)
}

// addrOK matches the destination: host is lowercase; ip is non-nil when the
// target (or a resolved address) is an IP.
func (m *matcher) addrOK(host string, ip net.IP) bool {
	if m.hasDom && (m.dom.empty() || ip != nil || !m.dom.match(host)) {
		return false
	}
	if m.hasIP && (m.ips.empty() || ip == nil || !m.ips.contains(ip)) {
		return false
	}
	if m.hasNDom && ip == nil && m.ndom.match(host) {
		return false
	}
	if m.hasNIP && ip != nil && m.nips.contains(ip) {
		return false
	}
	return true
}

func (m *matcher) ipRuleOnly() bool { return m.hasIP && !m.hasDom }

// DecideMeta returns the verdict and the rule behind it.
func (r *Router) DecideMeta(ctx context.Context, meta Meta) Decision {
	r.mu.RLock()
	rules, def, strat := r.rules, r.def, r.strategy
	r.mu.RUnlock()
	host := strings.ToLower(strings.TrimSuffix(meta.Host, "."))
	meta.Network = strings.ToLower(meta.Network)
	ip := net.ParseIP(host)

	var resolved []net.IP
	done := false
	resolve := func() []net.IP {
		if !done {
			done = true
			if ip == nil && r.Resolve != nil {
				if ips, err := r.Resolve(ctx, host); err == nil {
					resolved = ips
				}
			}
		}
		return resolved
	}
	viaIP := func(m *matcher) bool {
		for _, rip := range resolve() {
			if m.addrOK(host, rip) {
				return true
			}
		}
		return false
	}

	for i := range rules {
		m := &rules[i]
		if !m.basic(&meta) {
			continue
		}
		if m.addrOK(host, ip) {
			return Decision{m.action, m.name}
		}
		if strat == "ipondemand" && ip == nil && m.ipRuleOnly() && viaIP(m) {
			return Decision{m.action, m.name}
		}
	}
	if strat == "ipifnonmatch" && ip == nil {
		for i := range rules {
			m := &rules[i]
			if m.ipRuleOnly() && m.basic(&meta) && viaIP(m) {
				return Decision{m.action, m.name}
			}
		}
	}
	return Decision{def, "default"}
}

// Decide returns the action for a connection to host:port. A protocol
// attached to ctx with WithProtocol is used for protocol rules.
func (r *Router) Decide(ctx context.Context, network, host string, port int) Action {
	return r.DecideMeta(ctx, Meta{Network: network, Host: host, Port: port, Protocol: ProtocolFrom(ctx)}).Action
}
