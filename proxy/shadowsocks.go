package proxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"io.surprise.vpn/transport"
)

// Shadowsocks supports AEAD (aes-*-gcm, chacha20-ietf-poly1305) and the legacy
// stream ciphers (aes-*-cfb, aes-*-ctr, rc4-md5, chacha20-ietf).
type Shadowsocks struct {
	Server   string
	Dialer   transport.Dialer
	Method   string
	Password string
}

type ssSpec struct {
	keySize int
	aead    func(key []byte) (cipher.AEAD, error)
	ivSize  int
	stream  func(key, iv []byte, enc bool) (cipher.Stream, error)
}

func gcmFn(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aesStream(ctr bool) func(key, iv []byte, enc bool) (cipher.Stream, error) {
	return func(key, iv []byte, enc bool) (cipher.Stream, error) {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		switch {
		case ctr:
			return cipher.NewCTR(b, iv), nil
		case enc:
			return cipher.NewCFBEncrypter(b, iv), nil
		default:
			return cipher.NewCFBDecrypter(b, iv), nil
		}
	}
}

var ssMethods = map[string]ssSpec{
	"aes-128-gcm":            {keySize: 16, aead: gcmFn},
	"aes-192-gcm":            {keySize: 24, aead: gcmFn},
	"aes-256-gcm":            {keySize: 32, aead: gcmFn},
	"chacha20-ietf-poly1305": {keySize: 32, aead: chacha20poly1305.New},
	"aes-128-cfb":            {keySize: 16, ivSize: 16, stream: aesStream(false)},
	"aes-192-cfb":            {keySize: 24, ivSize: 16, stream: aesStream(false)},
	"aes-256-cfb":            {keySize: 32, ivSize: 16, stream: aesStream(false)},
	"aes-128-ctr":            {keySize: 16, ivSize: 16, stream: aesStream(true)},
	"aes-192-ctr":            {keySize: 24, ivSize: 16, stream: aesStream(true)},
	"aes-256-ctr":            {keySize: 32, ivSize: 16, stream: aesStream(true)},
	"rc4-md5": {keySize: 16, ivSize: 16, stream: func(key, iv []byte, _ bool) (cipher.Stream, error) {
		h := md5.New()
		h.Write(key)
		h.Write(iv)
		return rc4.NewCipher(h.Sum(nil))
	}},
	"chacha20-ietf": {keySize: 32, ivSize: 12, stream: func(key, iv []byte, _ bool) (cipher.Stream, error) {
		return chacha20.NewUnauthenticatedCipher(key, iv)
	}},
}

func evpKey(pw string, n int) []byte {
	var out, prev []byte
	for len(out) < n {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(pw))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func (s *Shadowsocks) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	spec, ok := ssMethods[strings.ToLower(s.Method)]
	if !ok {
		return nil, fmt.Errorf("shadowsocks: unsupported method %q", s.Method)
	}
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	raw, err := s.Dialer.DialContext(ctx, "tcp", s.Server)
	if err != nil {
		return nil, err
	}
	key := evpKey(s.Password, spec.keySize)
	var c net.Conn
	if spec.aead != nil {
		c = &ssAEADConn{Conn: raw, spec: spec, master: key}
	} else {
		c = &ssStreamConn{Conn: raw, spec: spec, key: key}
	}
	if _, err := c.Write(a.socks()); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// ---- AEAD ----

type ssAEADConn struct {
	net.Conn
	spec    ssSpec
	master  []byte
	w, r    cipher.AEAD
	wn, rn  []byte
	rbuf    []byte
}

func (c *ssAEADConn) subAEAD(salt []byte) (cipher.AEAD, error) {
	sub := make([]byte, c.spec.keySize)
	if _, err := io.ReadFull(hkdf.New(sha1.New, c.master, salt, []byte("ss-subkey")), sub); err != nil {
		return nil, err
	}
	return c.spec.aead(sub)
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func (c *ssAEADConn) Write(p []byte) (int, error) {
	if c.w == nil {
		salt := make([]byte, c.spec.keySize)
		rand.Read(salt)
		a, err := c.subAEAD(salt)
		if err != nil {
			return 0, err
		}
		c.w, c.wn = a, make([]byte, a.NonceSize())
		if _, err := c.Conn.Write(salt); err != nil {
			return 0, err
		}
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 0x3FFF {
			n = 0x3FFF
		}
		out := c.w.Seal(nil, c.wn, binary.BigEndian.AppendUint16(nil, uint16(n)), nil)
		incNonce(c.wn)
		out = c.w.Seal(out, c.wn, p[:n], nil)
		incNonce(c.wn)
		if _, err := c.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *ssAEADConn) Read(p []byte) (int, error) {
	if len(c.rbuf) == 0 {
		if c.r == nil {
			salt := make([]byte, c.spec.keySize)
			if _, err := io.ReadFull(c.Conn, salt); err != nil {
				return 0, err
			}
			a, err := c.subAEAD(salt)
			if err != nil {
				return 0, err
			}
			c.r, c.rn = a, make([]byte, a.NonceSize())
		}
		lb := make([]byte, 2+c.r.Overhead())
		if _, err := io.ReadFull(c.Conn, lb); err != nil {
			return 0, err
		}
		l, err := c.r.Open(nil, c.rn, lb, nil)
		if err != nil {
			return 0, err
		}
		incNonce(c.rn)
		n := int(binary.BigEndian.Uint16(l)) & 0x3FFF
		pb := make([]byte, n+c.r.Overhead())
		if _, err := io.ReadFull(c.Conn, pb); err != nil {
			return 0, err
		}
		if c.rbuf, err = c.r.Open(nil, c.rn, pb, nil); err != nil {
			return 0, err
		}
		incNonce(c.rn)
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}

// ---- legacy stream ----

type ssStreamConn struct {
	net.Conn
	spec     ssSpec
	key      []byte
	enc, dec cipher.Stream
}

func (c *ssStreamConn) Write(p []byte) (int, error) {
	var out []byte
	if c.enc == nil {
		iv := make([]byte, c.spec.ivSize)
		rand.Read(iv)
		e, err := c.spec.stream(c.key, iv, true)
		if err != nil {
			return 0, err
		}
		c.enc = e
		out = append(out, iv...)
	}
	start := len(out)
	out = append(out, p...)
	c.enc.XORKeyStream(out[start:], out[start:])
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ssStreamConn) Read(p []byte) (int, error) {
	if c.dec == nil {
		iv := make([]byte, c.spec.ivSize)
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return 0, err
		}
		d, err := c.spec.stream(c.key, iv, false)
		if err != nil {
			return 0, err
		}
		c.dec = d
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.dec.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}
