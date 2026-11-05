package v2tun

import (
	"encoding/base64"
	"testing"
)

func TestRealityConfigValidation(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	mk := func(r *RealityConfig) error {
		_, err := New(&Config{Protocol: "vless", UUID: "11111111-2222-3333-4444-555555555555",
			Server: "example.com", Port: 443, Reality: r})
		return err
	}
	if err := mk(&RealityConfig{PublicKey: good, ShortID: "abcd1234", ServerName: "cover.example.com"}); err != nil {
		t.Fatalf("valid reality config rejected: %v", err)
	}
	if err := mk(&RealityConfig{PublicKey: good}); err != nil {
		t.Fatalf("empty shortId must be allowed: %v", err)
	}
	if mk(&RealityConfig{PublicKey: "short"}) == nil {
		t.Error("a public key that is not 32 bytes must be rejected")
	}
	if mk(&RealityConfig{PublicKey: good, ShortID: "zz"}) == nil {
		t.Error("a non-hex shortId must be rejected")
	}
	if mk(&RealityConfig{PublicKey: good, ShortID: "00112233445566778899"}) == nil {
		t.Error("a shortId longer than 8 bytes must be rejected")
	}
}

func TestRealityRejectsQUIC(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, err := New(&Config{Protocol: "vless", UUID: "11111111-2222-3333-4444-555555555555",
		Server: "example.com", Port: 443, Network: "quic", Reality: &RealityConfig{PublicKey: good}})
	if err == nil {
		t.Fatal("reality + quic must be rejected")
	}
}
