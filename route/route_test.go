package route

import (
	"context"
	"net"
	"testing"
)

func mustRouter(t *testing.T, cfg Config) *Router {
	t.Helper()
	r, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func decide(r *Router, host string, port int) Action {
	return r.Decide(context.Background(), "tcp", host, port)
}

// A rule whose list has not been supplied yet must not match everything,
// otherwise "direct" would leak all traffic and "block" would cut it all.
func TestEmptyListNeverMatches(t *testing.T) {
	r := mustRouter(t, Config{Rules: []Rule{{Action: Direct, Domain: []string{"list:later"}}}})
	if got := decide(r, "example.com", 443); got != Proxy {
		t.Fatalf("empty list matched: got %s, want %s", got, Proxy)
	}
	r = mustRouter(t, Config{Rules: []Rule{{Action: Block, IP: []string{"list:later"}}}})
	if got := decide(r, "8.8.8.8", 443); got != Proxy {
		t.Fatalf("empty ip list matched: got %s, want %s", got, Proxy)
	}
}

func TestListFilledLater(t *testing.T) {
	r := mustRouter(t, Config{Rules: []Rule{{Action: Direct, Domain: []string{"list:later"}}}})
	if err := r.SetList("later", []string{"example.com", "# comment", ""}); err != nil {
		t.Fatal(err)
	}
	if got := decide(r, "a.example.com", 443); got != Direct {
		t.Fatalf("got %s, want %s", got, Direct)
	}
	if got := decide(r, "other.org", 443); got != Proxy {
		t.Fatalf("got %s, want %s", got, Proxy)
	}
}

func TestRegexpKeepsEscapes(t *testing.T) {
	r := mustRouter(t, Config{Rules: []Rule{{Action: Block, Domain: []string{`regexp:^ads\D+\.example\.com$`}}}})
	if got := decide(r, "adsx.example.com", 443); got != Block {
		t.Fatalf("adsx: got %s, want %s", got, Block)
	}
	if got := decide(r, "ads12.example.com", 443); got != Proxy {
		t.Fatalf("ads12: got %s, want %s", got, Proxy)
	}
}

func TestDomainKinds(t *testing.T) {
	r := mustRouter(t, Config{Rules: []Rule{
		{Action: Block, Domain: []string{"keyword:ads."}},
		{Action: Direct, Domain: []string{"full:exact.test", "domain:suffix.test"}},
	}})
	cases := map[string]Action{
		"ads.tracker.net": Block,
		"exact.test":      Direct,
		"x.exact.test":    Proxy,
		"suffix.test":     Direct,
		"a.b.suffix.test": Direct,
		"notsuffix.test":  Proxy,
	}
	for host, want := range cases {
		if got := decide(r, host, 443); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func TestPrivateAndPortOnly(t *testing.T) {
	r := mustRouter(t, Config{Rules: []Rule{
		{Action: Direct, IP: []string{"geoip:private"}},
		{Action: Block, Port: "25,6881-6889"},
	}})
	if got := decide(r, "192.168.1.5", 80); got != Direct {
		t.Fatalf("private: got %s", got)
	}
	if got := decide(r, "8.8.8.8", 80); got != Proxy {
		t.Fatalf("public: got %s", got)
	}
	if got := decide(r, "mail.example.com", 25); got != Block {
		t.Fatalf("port 25: got %s", got)
	}
	if got := decide(r, "mail.example.com", 6885); got != Block {
		t.Fatalf("port 6885: got %s", got)
	}
}

func TestIPIfNonMatch(t *testing.T) {
	r := mustRouter(t, Config{
		DomainStrategy: "ipifnonmatch",
		Rules:          []Rule{{Action: Direct, IP: []string{"10.0.0.0/8"}}},
	})
	r.Resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.IPv4(10, 1, 2, 3)}, nil
	}
	if got := decide(r, "intranet.example", 443); got != Direct {
		t.Fatalf("got %s, want %s", got, Direct)
	}
}
