package v2tun

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESS(t *testing.T) {
	cfg, name, err := ParseLink("vless://11111111-2222-3333-4444-555555555555@example.com:443" +
		"?type=ws&security=tls&sni=sni.example.com&host=cdn.example.com&path=%2Fws#My%20Node")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "vless" || cfg.Server != "example.com" || cfg.Port != 443 {
		t.Fatalf("bad endpoint: %+v", cfg)
	}
	if cfg.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("uuid: %q", cfg.UUID)
	}
	if cfg.Network != "ws" || cfg.WS.Path != "/ws" || cfg.WS.Host != "cdn.example.com" {
		t.Fatalf("transport: %+v", cfg.WS)
	}
	if !cfg.TLS.Enabled || cfg.TLS.SNI != "sni.example.com" {
		t.Fatalf("tls: %+v", cfg.TLS)
	}
	if name != "My Node" {
		t.Fatalf("name: %q", name)
	}
}

func TestVLESSFlowRejected(t *testing.T) {
	base := "vless://11111111-2222-3333-4444-555555555555@example.com:443?"
	for _, q := range []string{
		"flow=xtls-rprx-vision",                        // no TLS or REALITY
		"flow=xtls-rprx-vision&security=none",          // explicitly none
		"flow=xtls-rprx-vision&security=tls&type=ws",   // Vision needs plain tcp
		"flow=xtls-rprx-vision&security=tls&type=grpc", // ditto
		"flow=xtls-rprx-direct&security=tls",           // an unsupported flow
		"flow=xtls-rprx-splice&security=tls&type=tcp",  // ditto
	} {
		if _, _, err := ParseLink(base + q); err == nil {
			t.Errorf("%q: expected an error", q)
		}
	}
}

func TestParseVLESSVision(t *testing.T) {
	base := "vless://11111111-2222-3333-4444-555555555555@example.com:443?"
	pbk := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, q := range []string{
		"type=tcp&security=tls&sni=example.com&flow=xtls-rprx-vision",
		"security=tls&flow=XTLS-RPRX-VISION",
		"security=tls&flow=xtls-rprx-vision-udp443",
		"type=tcp&security=reality&pbk=" + pbk + "&sid=abcd&sni=cover.example.com&fp=chrome&flow=xtls-rprx-vision",
	} {
		cfg, _, err := ParseLink(base + q)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if cfg.Flow == "" || cfg.Flow != strings.ToLower(cfg.Flow) {
			t.Fatalf("%q: flow = %q", q, cfg.Flow)
		}
		if _, err := New(cfg); err != nil {
			t.Fatalf("%q: New rejected the parsed config: %v", q, err)
		}
	}
}

func TestVisionConfigValidation(t *testing.T) {
	mk := func(mut func(*Config)) error {
		cfg := &Config{Protocol: "vless", UUID: "11111111-2222-3333-4444-555555555555", Server: "example.com", Port: 443,
			Flow: "xtls-rprx-vision", TLS: TLSConfig{Enabled: true}}
		mut(cfg)
		_, err := New(cfg)
		return err
	}
	if err := mk(func(*Config) {}); err != nil {
		t.Fatalf("valid Vision config rejected: %v", err)
	}
	if mk(func(c *Config) { c.TLS.Enabled = false }) == nil {
		t.Error("Vision without TLS or REALITY must be rejected")
	}
	if mk(func(c *Config) { c.Network = "ws" }) == nil {
		t.Error("Vision over ws must be rejected")
	}
	if mk(func(c *Config) { c.Mux = &MuxConfig{Enabled: true} }) == nil {
		t.Error("Vision with mux must be rejected")
	}
	if mk(func(c *Config) { c.Protocol = "trojan" }) == nil {
		t.Error("flow on a non-vless protocol must be rejected")
	}
	if mk(func(c *Config) { c.Flow = "xtls-rprx-direct" }) == nil {
		t.Error("an unsupported flow must be rejected")
	}
}

func TestParseVLESSReality(t *testing.T) {
	pbk := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	cfg, name, err := ParseLink("vless://11111111-2222-3333-4444-555555555555@example.com:443" +
		"?type=tcp&security=reality&pbk=" + pbk + "&sid=abcd1234&sni=cover.example.com&fp=chrome#R")
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Reality
	if r == nil {
		t.Fatal("reality settings missing")
	}
	if r.PublicKey != pbk || r.ShortID != "abcd1234" || r.ServerName != "cover.example.com" || r.Fingerprint != "chrome" {
		t.Fatalf("reality: %+v", r)
	}
	if cfg.TLS.Enabled {
		t.Fatal("reality replaces the TLS layer; TLS.Enabled must stay false")
	}
	if name != "R" {
		t.Fatalf("name: %q", name)
	}
	// the parsed config must be accepted by New
	if _, err := New(cfg); err != nil {
		t.Fatalf("New rejected a parsed reality config: %v", err)
	}
}

func TestRealityLinkNeedsPublicKey(t *testing.T) {
	if _, _, err := ParseLink("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sid=ab"); err == nil {
		t.Fatal("a reality link without pbk must be rejected")
	}
}

func TestParseTrojanDefaultsToTLS(t *testing.T) {
	cfg, _, err := ParseLink("trojan://secret@example.com:443#t")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLS.Enabled || cfg.Password != "secret" {
		t.Fatalf("%+v", cfg)
	}
	cfg, _, err = ParseLink("trojan://secret@example.com:443?security=none#t")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.Enabled {
		t.Fatal("security=none must disable TLS")
	}
}

func TestParseVMess(t *testing.T) {
	js := `{"v":"2","ps":"vm","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555",` +
		`"aid":"0","scy":"auto","net":"ws","host":"h.example.com","path":"/p","tls":"tls","sni":"s.example.com"}`
	cfg, name, err := ParseLink("vmess://" + base64.StdEncoding.EncodeToString([]byte(js)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "vmess" || cfg.Server != "example.com" || cfg.Port != 443 || cfg.Network != "ws" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.WS.Host != "h.example.com" || cfg.WS.Path != "/p" || !cfg.TLS.Enabled || cfg.TLS.SNI != "s.example.com" {
		t.Fatalf("%+v", cfg)
	}
	if name != "vm" {
		t.Fatalf("name: %q", name)
	}
}

func TestParseShadowsocks(t *testing.T) {
	// SIP002: base64(method:password)@host:port
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))
	cfg, name, err := ParseLink("ss://" + ui + "@example.com:8388#n%201")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Protocol != "shadowsocks" || cfg.Method != "aes-256-gcm" || cfg.Password != "pw" ||
		cfg.Server != "example.com" || cfg.Port != 8388 || name != "n 1" {
		t.Fatalf("%+v name=%q", cfg, name)
	}
	// legacy: base64(method:password@host:port)
	all := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw2@10.0.0.1:1234"))
	cfg, _, err = ParseLink("ss://" + all)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Method != "chacha20-ietf-poly1305" || cfg.Password != "pw2" || cfg.Server != "10.0.0.1" || cfg.Port != 1234 {
		t.Fatalf("%+v", cfg)
	}
}

func TestShadowsocksPluginRejected(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))
	if _, _, err := ParseLink("ss://" + ui + "@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp#n"); err == nil {
		t.Fatal("plugin links must be rejected, not silently stripped")
	}
}

func TestSSHDefaultPort(t *testing.T) {
	cfg, _, err := ParseLink("ssh://user:pw@example.com#s")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 22 || cfg.Username != "user" || cfg.Password != "pw" {
		t.Fatalf("%+v", cfg)
	}
}

func TestUnsupportedScheme(t *testing.T) {
	// hysteria2:// and hy2:// are supported since the Hysteria wiring; use a scheme that really is not.
	if _, _, err := ParseLink("wireguard://x@example.com:443"); err == nil {
		t.Fatal("expected an error")
	}
}
