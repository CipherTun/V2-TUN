package v2tun

import "testing"

func TestParseHysteria2Links(t *testing.T) {
	cfg, name, err := ParseLink("hysteria2://secret@example.com:8443/?sni=cover.example.com&insecure=1" +
		"&obfs=salamander&obfs-password=pw&pinSHA256=AB:CD#node")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "hysteria2" || cfg.Server != "example.com" || cfg.Port != 8443 || cfg.Password != "secret" || name != "node" {
		t.Fatalf("%+v name=%q", cfg, name)
	}
	if cfg.TLS.SNI != "cover.example.com" || !cfg.TLS.AllowInsecure {
		t.Fatalf("tls: %+v", cfg.TLS)
	}
	if cfg.Hysteria == nil || cfg.Hysteria.Obfs != "pw" || cfg.Hysteria.PinSHA256 != "AB:CD" {
		t.Fatalf("hysteria: %+v", cfg.Hysteria)
	}

	cfg, _, err = ParseLink("hy2://user:pass@example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "hysteria2" || cfg.Port != 443 || cfg.Password != "user:pass" {
		t.Fatalf("%+v", cfg)
	}

	if _, _, err := ParseLink("hysteria2://x@example.com:20000-30000/"); err == nil {
		t.Fatal("port hopping must be rejected")
	}
	if _, _, err := ParseLink("hysteria2://x@example.com/?obfs=other&obfs-password=p"); err == nil {
		t.Fatal("an unknown obfs must be rejected")
	}
}

func TestParseHysteria1Links(t *testing.T) {
	cfg, _, err := ParseLink("hysteria://example.com:443?protocol=udp&auth=abc&peer=sni.example.com&insecure=1" +
		"&upmbps=20&downmbps=100&alpn=h3&obfs=xplus&obfsParam=pw")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "hysteria" || cfg.Password != "abc" || cfg.TLS.SNI != "sni.example.com" || !cfg.TLS.AllowInsecure {
		t.Fatalf("%+v", cfg)
	}
	h := cfg.Hysteria
	if h == nil || h.UpMbps != 20 || h.DownMbps != 100 || h.ALPN != "h3" || h.Obfs != "pw" {
		t.Fatalf("hysteria: %+v", h)
	}
	if _, _, err := ParseLink("hysteria://example.com:443?protocol=faketcp&auth=x"); err == nil {
		t.Fatal("faketcp must be rejected")
	}
}

func TestHysteriaConfigs(t *testing.T) {
	for _, p := range []string{"hysteria2", "hy2", "hysteria", "hy"} {
		if _, err := New(&Config{Protocol: p, Server: "example.com", Port: 443, Password: "x"}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	cases := map[string]*Config{
		"payload": {Protocol: "hysteria2", Server: "example.com", Port: 443, Payload: &PayloadConfig{Template: "@connect"}},
		"network": {Protocol: "hysteria2", Server: "example.com", Port: 443, Network: "ws"},
		"reality": {Protocol: "hysteria", Server: "example.com", Port: 443, Reality: &RealityConfig{PublicKey: "x"}},
	}
	for name, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("hysteria with %s must be rejected", name)
		}
	}
}
