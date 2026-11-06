package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func hyTestServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
		NextProtos:   []string{"hysteria"},
		MinVersion:   tls.VersionTLS13,
	}
}

// A minimal Hysteria 1 server written from the protocol spec: hello, one TCP
// request, then echo. It checks the client's wire format end to end over a
// real QUIC connection.
func TestHysteria1TCP(t *testing.T) {
	ln, err := quic.ListenAddr("127.0.0.1:0", hyTestServerTLS(t), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan string, 4)
	go func() {
		ctx := context.Background()
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		ctl, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		hdr := make([]byte, 1+8+8+2)
		if _, err := io.ReadFull(ctl, hdr); err != nil {
			return
		}
		auth := make([]byte, binary.BigEndian.Uint16(hdr[17:19]))
		if _, err := io.ReadFull(ctl, auth); err != nil {
			return
		}
		got <- "auth:" + string(auth)
		resp := []byte{1}
		resp = binary.BigEndian.AppendUint64(resp, 1<<20)
		resp = binary.BigEndian.AppendUint64(resp, 1<<20)
		resp = binary.BigEndian.AppendUint16(resp, 2)
		resp = append(resp, "hi"...)
		if _, err := ctl.Write(resp); err != nil {
			return
		}
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		rh := make([]byte, 3) // type + host length
		if _, err := io.ReadFull(st, rh); err != nil {
			return
		}
		host := make([]byte, binary.BigEndian.Uint16(rh[1:3]))
		if _, err := io.ReadFull(st, host); err != nil {
			return
		}
		pb := make([]byte, 2)
		if _, err := io.ReadFull(st, pb); err != nil {
			return
		}
		got <- "req:" + string(rh[0]+'0') + ":" + string(host) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
		st.Write([]byte{1, 0, 0, 0, 0, 0, 0}) // OK, session id 0, empty message
		io.Copy(st, st)
	}()

	h := &Hysteria1{Server: ln.Addr().String(), Auth: "secret", SNI: "localhost", AllowInsecure: true}
	t.Cleanup(func() { h.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := h.DialContext(ctx, "tcp", "target.example:80")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo returned %q", buf)
	}
	recv := func() string {
		select {
		case s := <-got:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("the fake server saw nothing")
			return ""
		}
	}
	if a := recv(); a != "auth:secret" {
		t.Fatalf("server saw %q", a)
	}
	if r := recv(); r != "req:0:target.example:80" {
		t.Fatalf("server saw %q", r)
	}
}
