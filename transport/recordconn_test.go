package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func rcTestCert(t *testing.T) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"x"}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestTLSOverRecordConnThenDetach(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		s := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{rcTestCert(t)}})
		if err := s.Handshake(); err != nil {
			t.Error(err)
			return
		}
		s.Write([]byte("hello over tls"))
		// after the TLS layer's last record, raw bytes
		time.Sleep(50 * time.Millisecond)
		b.Write([]byte("RAW-TAIL"))
	}()
	rc := NewRecordConn(a)
	c := tls.Client(rc, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS13})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "hello over tls" {
		t.Fatalf("%q %v", buf[:n], err)
	}
	rc.Detach()
	m, err := io.ReadFull(rc, buf[:8])
	if err != nil || string(buf[:m]) != "RAW-TAIL" {
		t.Fatalf("%q %v", buf[:m], err)
	}
	if rc.NetConn() != a {
		t.Fatal("NetConn")
	}
}
