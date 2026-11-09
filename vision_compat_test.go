package v2tun

import "testing"

const visionTestUUID = "11111111-2222-3333-4444-555555555555"

// Vision is a VLESS feature: every other protocol, including the Hysteria
// ones that bring their own QUIC/TLS, must refuse a flow instead of ignoring it.
func TestVisionFlowOnlyForVLESS(t *testing.T) {
	for _, proto := range []string{"hysteria2", "hy2", "hysteria", "hy", "trojan", "vmess", "shadowsocks", "ssh"} {
		_, err := New(&Config{Protocol: proto, Server: "example.com", Port: 443, UUID: visionTestUUID,
			Password: "x", Flow: "xtls-rprx-vision", TLS: TLSConfig{Enabled: true}})
		if err == nil {
			t.Errorf("%s: a flow must be rejected", proto)
		}
	}
}

// The record layer sits directly under TLS / REALITY, so a pre-tls payload and
// the ClientHello fragmenter, which sit below it, must keep working.
func TestVisionWithPayloadAndFragment(t *testing.T) {
	cfg := &Config{Protocol: "vless", Server: "example.com", Port: 443, UUID: visionTestUUID,
		Flow: "xtls-rprx-vision", TLS: TLSConfig{Enabled: true, SNI: "example.com"},
		Payload:  &PayloadConfig{Template: connectPayload, Host: "bug.example.com"},
		Fragment: &FragmentConfig{Length: [2]int{10, 40}, Interval: [2]int{5, 20}}}
	if _, err := New(cfg); err != nil {
		t.Fatalf("Vision with a payload and fragment: %v", err)
	}
}

// Links of the other protocols must not pick up a flow.
func TestHysteriaLinkHasNoFlow(t *testing.T) {
	cfg, _, err := ParseLink("hysteria2://secret@example.com:443/?sni=example.com#h")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Flow != "" {
		t.Fatalf("flow = %q", cfg.Flow)
	}
}
