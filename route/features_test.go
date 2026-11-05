package route

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func newRouter(t *testing.T, cfg Config) *Router {
	t.Helper()
	r, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func verdict(r *Router, network, host string, port int) Action {
	return r.Decide(context.Background(), network, host, port)
}

func TestSplitBypass(t *testing.T) {
	r := newRouter(t, Config{Split: &Split{Mode: "bypass",
		Domain: []string{"domain:bank.example"}, IP: []string{"203.0.113.0/24"}, Port: "9999"}})
	cases := []struct {
		host string
		port int
		want Action
	}{
		{"www.bank.example", 443, Direct},
		{"203.0.113.9", 443, Direct},
		{"other.example", 9999, Direct},
		{"other.example", 443, Proxy},
		{"8.8.8.8", 53, Proxy},
	}
	for _, c := range cases {
		if got := verdict(r, "tcp", c.host, c.port); got != c.want {
			t.Errorf("%s:%d: got %s, want %s", c.host, c.port, got, c.want)
		}
	}
}

func TestSplitOnly(t *testing.T) {
	r := newRouter(t, Config{
		Rules: []Rule{{Action: Block, Domain: []string{"keyword:ads."}}},
		Split: &Split{Mode: "only", Domain: []string{"domain:work.example"}, IP: []string{"198.51.100.0/24"}},
	})
	cases := []struct {
		host string
		want Action
	}{
		{"git.work.example", Proxy},
		{"198.51.100.7", Proxy},
		{"news.example", Direct},
		{"ads.work.example", Block}, // user rules still come first
	}
	for _, c := range cases {
		if got := verdict(r, "tcp", c.host, 443); got != c.want {
			t.Errorf("%s: got %s, want %s", c.host, got, c.want)
		}
	}
	if _, err := New(&Config{Split: &Split{Mode: "sideways"}}); err == nil {
		t.Fatal("unknown split mode must be rejected")
	}
}

func TestBypassLAN(t *testing.T) {
	r := newRouter(t, Config{BypassLAN: true})
	for host, want := range map[string]Action{
		"192.168.1.1": Direct, "10.0.0.5": Direct, "127.0.0.1": Direct,
		"router": Direct, "printer.local": Direct, "nas.lan": Direct, "localhost": Direct,
		"example.com": Proxy, "8.8.8.8": Proxy,
	} {
		if got := verdict(r, "tcp", host, 80); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func TestBlockQUIC(t *testing.T) {
	r := newRouter(t, Config{BlockQUIC: true})
	if got := verdict(r, "udp", "example.com", 443); got != Block {
		t.Errorf("udp/443: got %s", got)
	}
	if got := verdict(r, "tcp", "example.com", 443); got != Proxy {
		t.Errorf("tcp/443: got %s", got)
	}
	if got := verdict(r, "udp", "example.com", 53); got != Proxy {
		t.Errorf("udp/53: got %s", got)
	}
}

func TestProtocolRules(t *testing.T) {
	r := newRouter(t, Config{BlockBitTorrent: true,
		Rules: []Rule{{Action: Direct, Protocol: []string{"HTTP"}}}})
	ctx := context.Background()
	if got := r.DecideMeta(ctx, Meta{Network: "tcp", Host: "1.2.3.4", Port: 6881, Protocol: "bittorrent"}); got.Action != Block {
		t.Errorf("bittorrent: %+v", got)
	}
	if got := r.DecideMeta(ctx, Meta{Network: "tcp", Host: "1.2.3.4", Port: 80, Protocol: "http"}); got.Action != Direct {
		t.Errorf("http: %+v", got)
	}
	if got := r.DecideMeta(ctx, Meta{Network: "tcp", Host: "1.2.3.4", Port: 443, Protocol: "tls"}); got.Action != Proxy {
		t.Errorf("tls: %+v", got)
	}
	// the protocol travels in the context for Decide
	if got := r.Decide(WithProtocol(ctx, "bittorrent"), "tcp", "1.2.3.4", 1); got != Block {
		t.Errorf("ctx protocol: got %s", got)
	}
}

func TestNotRules(t *testing.T) {
	r := newRouter(t, Config{Rules: []Rule{{Action: Direct, NotDomain: []string{"domain:example.com"}}}})
	for host, want := range map[string]Action{
		"a.example.com": Proxy, "other.org": Direct, "8.8.8.8": Direct,
	} {
		if got := verdict(r, "tcp", host, 443); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
	r = newRouter(t, Config{Rules: []Rule{{Action: Block, NotPort: "80,443"}}})
	if got := verdict(r, "tcp", "x.test", 8080); got != Block {
		t.Errorf("8080: got %s", got)
	}
	if got := verdict(r, "tcp", "x.test", 443); got != Proxy {
		t.Errorf("443: got %s", got)
	}
}

func TestTimeAndDays(t *testing.T) {
	r := newRouter(t, Config{Rules: []Rule{{Action: Block, Time: "22:00-06:00"}}})
	at := func(h, m int) Meta {
		return Meta{Network: "tcp", Host: "x.test", Port: 80, Now: time.Date(2026, 11, 4, h, m, 0, 0, time.UTC)}
	}
	ctx := context.Background()
	for _, c := range []struct {
		h, m int
		want Action
	}{{23, 30, Block}, {3, 0, Block}, {6, 0, Proxy}, {12, 0, Proxy}, {22, 0, Block}} {
		if got := r.DecideMeta(ctx, at(c.h, c.m)).Action; got != c.want {
			t.Errorf("%02d:%02d: got %s, want %s", c.h, c.m, got, c.want)
		}
	}
	// 2026-11-07 is a Saturday, 2026-11-04 a Wednesday
	r = newRouter(t, Config{Rules: []Rule{{Action: Block, Days: []string{"weekend"}}}})
	sat := Meta{Network: "tcp", Host: "x.test", Port: 80, Now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	wed := Meta{Network: "tcp", Host: "x.test", Port: 80, Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	if got := r.DecideMeta(ctx, sat).Action; got != Block {
		t.Errorf("saturday: got %s", got)
	}
	if got := r.DecideMeta(ctx, wed).Action; got != Proxy {
		t.Errorf("wednesday: got %s", got)
	}
}

func TestGeoIPListAndMerge(t *testing.T) {
	var cidrs []string
	for i := 0; i < 1000; i++ {
		cidrs = append(cidrs, fmt.Sprintf("%d.%d.0.0/16", 20+i/256, i%256))
	}
	cidrs = append(cidrs, "20.0.0.0/8", "2001:db8::/32", "# comment", "not-a-cidr")
	r := newRouter(t, Config{Rules: []Rule{{Action: Direct, IP: []string{"geoip:cn"}}}})
	if got := verdict(r, "tcp", "21.5.9.9", 443); got != Proxy {
		t.Fatalf("before the list is supplied: got %s", got)
	}
	if err := r.SetList("GEOIP:CN", cidrs); err != nil { // bad lines are skipped, not fatal
		t.Fatal(err)
	}
	for host, want := range map[string]Action{
		"21.5.9.9": Direct, "20.200.1.1": Direct, "23.231.255.255": Direct,
		"8.8.8.8": Proxy, "24.0.0.1": Proxy, "2001:db8::1": Direct, "2001:db9::1": Proxy,
	} {
		if got := verdict(r, "tcp", host, 443); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func TestGeositeList(t *testing.T) {
	r := newRouter(t, Config{Rules: []Rule{{Action: Block, Domain: []string{"geosite:ads"}}}})
	err := r.SetList("geosite:ads", []string{"domain:tracker.example", "full:x.example", "keyword:doubleclick",
		"include:other", "regexp:^ad\\d+\\.", "evil.test @ads"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]Action{
		"a.tracker.example": Block, "x.example": Block, "y.x.example": Proxy,
		"stats.doubleclick.net": Block, "ad42.site.test": Block, "adx.site.test": Proxy,
		"www.evil.test": Block, "fine.test": Proxy,
	} {
		if got := verdict(r, "tcp", host, 443); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func TestIPOnDemandOrder(t *testing.T) {
	r := newRouter(t, Config{
		DomainStrategy: "ipondemand",
		Rules: []Rule{
			{Action: Block, IP: []string{"10.1.0.0/16"}},
			{Action: Direct, IP: []string{"10.0.0.0/8"}},
		},
	})
	r.Resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "inner.test" {
			return []net.IP{net.IPv4(10, 1, 2, 3)}, nil
		}
		return []net.IP{net.IPv4(10, 9, 9, 9)}, nil
	}
	if got := verdict(r, "tcp", "inner.test", 443); got != Block {
		t.Errorf("inner.test: got %s, want %s (first matching rule wins)", got, Block)
	}
	if got := verdict(r, "tcp", "other.test", 443); got != Direct {
		t.Errorf("other.test: got %s, want %s", got, Direct)
	}
}

func TestExplain(t *testing.T) {
	r := newRouter(t, Config{BypassLAN: true, Rules: []Rule{
		{Action: Block, Domain: []string{"domain:bad.test"}},
		{Name: "mine", Action: Direct, Port: "22"},
	}})
	ctx := context.Background()
	for _, c := range []struct {
		host string
		port int
		rule string
	}{
		{"192.168.0.1", 80, "builtin:lan-ip"},
		{"www.bad.test", 80, "rule#1"},
		{"example.com", 22, "mine"},
		{"example.com", 80, "default"},
	} {
		if got := r.DecideMeta(ctx, Meta{Network: "tcp", Host: c.host, Port: c.port}); got.Rule != c.rule {
			t.Errorf("%s:%d: rule %q, want %q", c.host, c.port, got.Rule, c.rule)
		}
	}
}

func TestReconfigureKeepsLists(t *testing.T) {
	r := newRouter(t, Config{Rules: []Rule{{Action: Direct, Domain: []string{"list:mine"}}}})
	if err := r.SetList("mine", []string{"domain:kept.test"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Reconfigure(&Config{Rules: []Rule{{Action: Block, Domain: []string{"list:mine"}}}}); err != nil {
		t.Fatal(err)
	}
	if got := verdict(r, "tcp", "a.kept.test", 443); got != Block {
		t.Errorf("after reconfigure: got %s", got)
	}
	if err := r.Reconfigure(&Config{Rules: []Rule{{Action: "teleport"}}}); err == nil {
		t.Fatal("bad config must be rejected")
	}
	if got := verdict(r, "tcp", "a.kept.test", 443); got != Block {
		t.Errorf("a rejected reconfigure must keep the old rules: got %s", got)
	}
}

func TestBadConfigs(t *testing.T) {
	for name, cfg := range map[string]Config{
		"action":   {Rules: []Rule{{Action: "teleport"}}},
		"network":  {Rules: []Rule{{Network: "icmp"}}},
		"time":     {Rules: []Rule{{Time: "late"}}},
		"days":     {Rules: []Rule{{Days: []string{"funday"}}}},
		"port":     {Rules: []Rule{{Port: "abc"}}},
		"strategy": {DomainStrategy: "sometimes"},
		"cidr":     {Rules: []Rule{{IP: []string{"10.0.0.0/99"}}}},
		"regexp":   {Rules: []Rule{{Domain: []string{"regexp:("}}}},
	} {
		if _, err := New(&cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// aliases are accepted
	r := newRouter(t, Config{Rules: []Rule{{Action: "reject", Domain: []string{"x.test"}}, {Action: "bypass", Domain: []string{"y.test"}}}})
	if verdict(r, "tcp", "x.test", 1) != Block || verdict(r, "tcp", "y.test", 1) != Direct {
		t.Error("reject/bypass aliases")
	}
}

func TestIPSetMerge(t *testing.T) {
	s := &ipSet{}
	for _, c := range []string{"10.0.0.0/9", "10.128.0.0/9", "192.168.0.0/16", "192.168.5.0/24"} {
		if err := s.add(c); err != nil {
			t.Fatal(err)
		}
	}
	s.finish()
	if len(s.v4) != 2 {
		t.Fatalf("want 2 merged ranges, got %+v", s.v4)
	}
	for ip, want := range map[string]bool{
		"10.0.0.0": true, "10.255.255.255": true, "9.255.255.255": false, "11.0.0.0": false,
		"192.168.5.5": true, "192.169.0.0": false,
	} {
		if got := s.contains(net.ParseIP(ip)); got != want {
			t.Errorf("%s: got %v, want %v", ip, got, want)
		}
	}
}
