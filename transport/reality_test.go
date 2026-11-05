package transport

import (
	"bytes"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Canary for the uTLS dependency: REALITY needs the private key behind the
// hello's X25519 key share and the raw hello layout. If a uTLS upgrade moves
// either, this test fails before a user hits a broken handshake.
func TestRealityHelloLayoutAndKey(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	uc := utls.UClient(a, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	h := uc.HandshakeState.Hello
	if h == nil || len(h.Raw) < 71 || h.Raw[38] != 32 || len(h.Random) != 32 {
		t.Fatalf("unexpected hello layout (raw %d bytes)", len(h.Raw))
	}
	key, err := x25519Key(uc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(h.Raw, key.PublicKey().Bytes()) {
		t.Fatal("the X25519 key found by reflection is not the one in the ClientHello")
	}
}

func TestRealityRejectsBadParameters(t *testing.T) {
	d := &Reality{Inner: &TCP{}, PublicKey: make([]byte, 31)}
	if _, err := d.DialContext(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("short public key must be rejected")
	}
	d = &Reality{Inner: &TCP{}, PublicKey: make([]byte, 32), ShortID: make([]byte, 9)}
	if _, err := d.DialContext(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("long shortId must be rejected")
	}
}

func TestVerifyRealityRejectsForeignCertificates(t *testing.T) {
	if err := verifyReality(nil, make([]byte, 32)); err == nil {
		t.Fatal("no certificate must fail")
	}
	if err := verifyReality([][]byte{{1, 2, 3}}, make([]byte, 32)); err == nil {
		t.Fatal("garbage certificate must fail")
	}
}
