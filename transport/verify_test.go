package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinVerifierMatchesAnyCertificate(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	pin := hex.EncodeToString(sum[:])
	v := pinVerifier([]string{pin})
	if v == nil {
		t.Fatal("a valid pin must give a verifier")
	}
	if err := v([][]byte{[]byte("leaf"), []byte("abc")}, nil); err != nil {
		t.Errorf("a matching certificate in the chain must pass: %v", err)
	}
	if v([][]byte{[]byte("leaf")}, nil) == nil {
		t.Error("a chain without the pinned certificate must fail")
	}
	if pinVerifier(nil) != nil || pinVerifier([]string{"zz"}) != nil {
		t.Error("no usable pin means no verifier")
	}
}

func TestNormalizePin(t *testing.T) {
	p := strings.Repeat("AB", 32)
	got, ok := NormalizePin(p)
	if !ok || got != strings.Repeat("ab", 32) {
		t.Errorf("upper case pin: %q %v", got, ok)
	}
	colons := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	if _, ok := NormalizePin(colons); !ok {
		t.Error("a pin with colons must be accepted")
	}
	if _, ok := NormalizePin("abcd"); ok {
		t.Error("a short pin must be rejected")
	}
}

func TestNameVerifierRejectsBadInput(t *testing.T) {
	called := false
	v := nameVerifier("example.com", func([][]byte, [][]*x509Certificate) error {
		called = true
		return nil
	})
	if v(nil, nil) == nil {
		t.Error("no certificate must fail")
	}
	if v([][]byte{[]byte("not a certificate")}, nil) == nil {
		t.Error("an unparsable certificate must fail")
	}
	if called {
		t.Error("the pin check must not run after a failed name check")
	}
}

func TestTLSPinOverRealHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	good := hex.EncodeToString(sum[:])
	bad := strings.Repeat("00", 32)
	addr := srv.Listener.Addr().String()

	dial := func(pins []string) error {
		d := &TLS{Inner: &TCP{}, ServerName: "example.com", AllowInsecure: true, PinSHA256: pins}
		c, err := d.DialContext(context.Background(), "tcp", addr)
		if err == nil {
			c.Close()
		}
		return err
	}
	if err := dial([]string{good}); err != nil {
		t.Fatalf("the right pin must connect (also with allowInsecure): %v", err)
	}
	if err := dial([]string{bad}); err == nil {
		t.Fatal("a wrong pin must fail the handshake")
	}
	if err := dial(nil); err != nil {
		t.Fatalf("no pin keeps the old behaviour: %v", err)
	}
}
