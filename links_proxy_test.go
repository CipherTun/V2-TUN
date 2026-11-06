package v2tun

import "testing"

func TestParseProxyLinks(t *testing.T) {
	cases := []struct {
		link  string
		proto string
		port  int
		tls   bool
	}{
		{"socks5://u:p@example.com:1081#a", "socks5", 1081, false},
		{"socks://example.com#a", "socks5", 1080, false},
		{"socks4://example.com:9050#a", "socks4", 9050, false},
		{"http://u:p@example.com#a", "http", 8080, false},
		{"https://u:p@example.com#a", "https", 443, true},
	}
	for _, c := range cases {
		cfg, name, err := ParseLink(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.link, err)
		}
		if cfg.Protocol != c.proto || cfg.Port != c.port || cfg.TLS.Enabled != c.tls || cfg.Server != "example.com" || name != "a" {
			t.Errorf("%s: got protocol=%s port=%d tls=%v server=%s name=%q", c.link, cfg.Protocol, cfg.Port, cfg.TLS.Enabled, cfg.Server, name)
		}
	}
	cfg, _, err := ParseLink("socks5://u:p@example.com:1081")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "u" || cfg.Password != "p" {
		t.Fatalf("credentials: %q / %q", cfg.Username, cfg.Password)
	}
}
