package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// Reality is the client side of REALITY (Xray's TLS camouflage). It replaces the
// TLS layer: a Chrome-like uTLS ClientHello carries an authenticated session id
// (X25519 against the server's public key, sealed with AES-GCM), and the
// server proves itself with an ed25519 certificate whose signature is an HMAC
// keyed by the shared secret. Servers that fail the check forward you to the
// cover site, so a wrong key, shortId or server name shows up as an error.
//
// Not supported: the spiderX crawl, and XTLS Vision (use flows without it).
type Reality struct {
	Inner       Dialer
	ServerName  string // the cover site's name (SNI); empty => host of addr
	PublicKey   []byte // server X25519 public key, 32 bytes
	ShortID     []byte // 0 to 8 bytes
	Fingerprint string // default chrome
	ALPN        []string
}

func (d *Reality) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(d.PublicKey) != 32 {
		return nil, errors.New("reality: public key must be 32 bytes")
	}
	if len(d.ShortID) > 8 {
		return nil, errors.New("reality: shortId is at most 8 bytes")
	}
	c, err := d.Inner.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uc, err := d.handshake(ctx, NewRecordConn(c), addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	return uc, nil
}

func (d *Reality) handshake(ctx context.Context, c net.Conn, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	sni := d.ServerName
	if sni == "" {
		sni = host
	}
	id := utls.HelloChrome_Auto
	if fp := strings.ToLower(d.Fingerprint); fp != "" && fp != "random" { // a random hello may lack X25519
		if v, ok := fingerprints[fp]; ok {
			id = v
		}
	}
	var authKey []byte
	uc := utls.UClient(c, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // the server is authenticated by the certificate HMAC below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			return verifyReality(raw, authKey)
		},
	}, id)
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if len(d.ALPN) > 0 {
		patched := false
		for _, ext := range uc.Extensions {
			if e, ok := ext.(*utls.ALPNExtension); ok {
				e.AlpnProtocols = d.ALPN
				patched = true
			}
		}
		if patched { // re-serialize the hello with our ALPN
			if err := uc.MarshalClientHello(); err != nil {
				return nil, err
			}
		}
	}
	hello := uc.HandshakeState.Hello
	if hello == nil || len(hello.Raw) < 39+32 || len(hello.Random) != 32 || hello.Raw[38] != 32 {
		return nil, errors.New("reality: unexpected ClientHello layout")
	}
	// Session id layout: version(3) reserved(1) unix time(4) shortId(8), then sealed.
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // the AEAD additional data has a zeroed session id
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 1, 8, 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], d.ShortID)

	priv, err := x25519Key(uc)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(d.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: bad public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	authKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:32], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("reality handshake: %w", err)
	}
	return uc, nil
}

func verifyReality(raw [][]byte, authKey []byte) error {
	if len(raw) == 0 {
		return errors.New("reality: server sent no certificate")
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("reality: server did not present a REALITY certificate (wrong public key, shortId or server name?)")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		return errors.New("reality: certificate HMAC mismatch (wrong public key or shortId?)")
	}
	return nil
}

// x25519Key returns the private key behind the hello's X25519 key share. uTLS
// keeps it in different places across versions, so look it up by reflection:
// State13.EcdheKey, State13.KeyShareKeys.Ecdhe, or KeyShareKeys.GetEcdheKey.
func x25519Key(uc *utls.UConn) (key *ecdh.PrivateKey, err error) {
	errNone := errors.New("reality: this uTLS version does not expose the X25519 key share")
	defer func() {
		if r := recover(); r != nil {
			key, err = nil, errNone
		}
	}()
	st := reflect.ValueOf(&uc.HandshakeState).Elem().FieldByName("State13")
	if !st.IsValid() {
		return nil, errNone
	}
	asKey := func(v reflect.Value) *ecdh.PrivateKey {
		if v.IsValid() && v.Kind() == reflect.Ptr && !v.IsNil() && v.CanInterface() {
			if k, ok := v.Interface().(*ecdh.PrivateKey); ok {
				return k
			}
		}
		return nil
	}
	if k := asKey(st.FieldByName("EcdheKey")); k != nil {
		return k, nil
	}
	ks := st.FieldByName("KeyShareKeys")
	if ks.IsValid() && ks.Kind() == reflect.Ptr && !ks.IsNil() {
		if k := asKey(ks.Elem().FieldByName("Ecdhe")); k != nil {
			return k, nil
		}
		if m := ks.MethodByName("GetEcdheKey"); m.IsValid() {
			out := m.Call([]reflect.Value{reflect.ValueOf(utls.X25519)})
			if len(out) > 0 {
				if k := asKey(out[0]); k != nil {
					return k, nil
				}
			}
		}
	}
	return nil, errNone
}
