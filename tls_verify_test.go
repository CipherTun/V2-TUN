package v2tun

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTLSPinAndVerifyNameConfig(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	colons := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	mk := func(tc TLSConfig) error {
		c, err := New(&Config{Protocol: "trojan", Password: "x", Server: "example.com", Port: 443, TLS: tc})
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := mk(TLSConfig{Enabled: true, PinSHA256: []string{pin}}); err != nil {
		t.Fatalf("a valid pin must be accepted: %v", err)
	}
	if err := mk(TLSConfig{Enabled: true, PinSHA256: []string{colons, pin}}); err != nil {
		t.Fatalf("a pin with colons and a second pin must be accepted: %v", err)
	}
	if err := mk(TLSConfig{Enabled: true, VerifyName: "front.example.com"}); err != nil {
		t.Fatalf("verifyName must be accepted: %v", err)
	}
	if mk(TLSConfig{Enabled: true, PinSHA256: []string{"abcd"}}) == nil {
		t.Error("a malformed pin must be rejected")
	}
	if mk(TLSConfig{PinSHA256: []string{pin}}) == nil {
		t.Error("a pin without tls.enabled must be rejected (it would be ignored)")
	}
	if mk(TLSConfig{VerifyName: "front.example.com"}) == nil {
		t.Error("verifyName without tls.enabled must be rejected")
	}
}

func TestTLSPinRejectedWhereItCannotApply(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, err := New(&Config{Protocol: "vless", UUID: "11111111-2222-3333-4444-555555555555", Server: "example.com", Port: 443,
		Reality: &RealityConfig{PublicKey: good}, TLS: TLSConfig{PinSHA256: []string{pin}}})
	if err == nil {
		t.Error("a tls pin with reality must be rejected")
	}
	_, err = New(&Config{Protocol: "trojan", Password: "x", Server: "example.com", Port: 443, Network: "quic",
		TLS: TLSConfig{Enabled: true, PinSHA256: []string{pin}}})
	if err == nil {
		t.Error("a tls pin with the quic transport must be rejected")
	}
	_, err = New(&Config{Protocol: "hysteria2", Password: "x", Server: "example.com", Port: 443,
		TLS: TLSConfig{PinSHA256: []string{pin}}})
	if err == nil {
		t.Error("a tls pin with hysteria must be rejected (use hysteria.pinSha256)")
	}
}
