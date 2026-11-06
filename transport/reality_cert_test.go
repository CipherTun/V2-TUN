package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func realityTestTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reality-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

// realityTestCert returns a self-signed ed25519 certificate. When authKey is
// set, the signature is replaced by HMAC-SHA512(authKey, public key), which is
// how a REALITY server proves that it knows the shared secret. The signature
// is the last 64 bytes of the encoded certificate (ed25519 signatures and
// HMAC-SHA512 are both 64 bytes), and parsing does not check it.
func realityTestCert(t *testing.T, authKey []byte) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := realityTestTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if authKey != nil {
		mac := hmac.New(sha512.New, authKey)
		mac.Write(pub)
		sig := mac.Sum(nil)
		copy(der[len(der)-len(sig):], sig)
	}
	return der
}

func TestVerifyRealityAcceptsValidCertificate(t *testing.T) {
	authKey := bytes.Repeat([]byte{7}, 32)
	der := realityTestCert(t, authKey)
	if err := verifyReality([][]byte{der}, authKey); err != nil {
		t.Fatalf("a certificate carrying the right HMAC was rejected: %v", err)
	}
}

func TestVerifyRealityRejectsWrongKey(t *testing.T) {
	der := realityTestCert(t, bytes.Repeat([]byte{7}, 32))
	if err := verifyReality([][]byte{der}, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("a certificate signed with a different shared secret must be rejected")
	}
}

func TestVerifyRealityRejectsOrdinaryEd25519Certificate(t *testing.T) {
	der := realityTestCert(t, nil) // normal signature, not an HMAC
	if err := verifyReality([][]byte{der}, bytes.Repeat([]byte{7}, 32)); err == nil {
		t.Fatal("an ordinary ed25519 certificate must be rejected")
	}
}

func TestVerifyRealityRejectsNonEd25519Certificate(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := realityTestTemplate()
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReality([][]byte{der}, bytes.Repeat([]byte{7}, 32)); err == nil {
		t.Fatal("the cover site's real certificate (not ed25519) must be rejected")
	}
}
