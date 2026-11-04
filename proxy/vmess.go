package proxy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/fnv"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	"io.surprise.vpn/transport"
)

const vmessMagic = "c48619fe-8f02-49e0-b9e9-edf763e17e21"

// VMess supports AEAD headers (AlterID == 0) and the legacy MD5 header
// (AlterID > 0) that Xray removed. Body security: auto|aes-128-gcm|
// chacha20-poly1305|none. Plaintext works when no TLS layer is in the chain.
type VMess struct {
	Server   string
	Dialer   transport.Dialer
	UUID     string
	AlterID  int
	Security string
}

func vmessKDF(key []byte, path ...string) []byte {
	mk := func() hash.Hash { return hmac.New(sha256.New, []byte("VMess AEAD KDF")) }
	for _, p := range path {
		parent, pv := mk, []byte(p)
		mk = func() hash.Hash { return hmac.New(parent, pv) }
	}
	h := mk()
	h.Write(key)
	return h.Sum(nil)
}

func gcm16(key []byte) cipher.AEAD {
	b, _ := aes.NewCipher(key[:16])
	g, _ := cipher.NewGCM(b)
	return g
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

func md5sum(parts ...[]byte) []byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func vmessSec(s string) (byte, error) {
	switch strings.ToLower(s) {
	case "", "auto", "aes-128-gcm":
		return 3, nil
	case "chacha20-poly1305":
		return 4, nil
	case "none":
		return 5, nil
	}
	return 0, fmt.Errorf("vmess: unsupported security %q", s)
}

func (v *VMess) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return v.dial(ctx, target, 1)
}

func (v *VMess) dial(ctx context.Context, target string, cmd byte) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(target, "v1.mux.cool:") {
		cmd = 3
	}
	id, err := parseUUID(v.UUID)
	if err != nil {
		return nil, err
	}
	sec, err := vmessSec(v.Security)
	if err != nil {
		return nil, err
	}
	bodyKey, bodyIV := randBytes(16), randBytes(16)
	respV := randBytes(1)[0]
	padLen := int(randInt(16))

	h := []byte{1}
	h = append(h, bodyIV...)
	h = append(h, bodyKey...)
	h = append(h, respV, 1|4) // option: chunk stream + chunk masking
	h = append(h, byte(padLen<<4)|sec, 0, cmd)
	if cmd != 3 {
	h = binary.BigEndian.AppendUint16(h, a.port)
	switch {
	case a.ip != nil && a.ip.To4() != nil:
		h = append(h, 1)
		h = append(h, a.ip.To4()...)
	case a.ip != nil:
		h = append(h, 3)
		h = append(h, a.ip.To16()...)
	default:
		h = append(h, 2, byte(len(a.host)))
		h = append(h, a.host...)
	}
	}
	h = append(h, randBytes(padLen)...)
	f := fnv.New32a()
	f.Write(h)
	h = f.Sum(h)

	cmdKey := md5sum(id[:], []byte(vmessMagic))
	legacy := v.AlterID > 0
	var wire []byte
	if legacy {
		ts := binary.BigEndian.AppendUint64(nil, uint64(time.Now().Unix()+randInt(61)-30))
		mac := hmac.New(md5.New, id[:])
		mac.Write(ts)
		wire = mac.Sum(nil)
		blk, _ := aes.NewCipher(cmdKey)
		enc := cipher.NewCFBEncrypter(blk, md5sum(ts, ts, ts, ts))
		enc.XORKeyStream(h, h)
		wire = append(wire, h...)
	} else {
		authid := make([]byte, 16)
		binary.BigEndian.PutUint64(authid, uint64(time.Now().Unix()))
		copy(authid[8:12], randBytes(4))
		binary.BigEndian.PutUint32(authid[12:], crc32.ChecksumIEEE(authid[:12]))
		blk, _ := aes.NewCipher(vmessKDF(cmdKey, "AES Auth ID Encryption")[:16])
		blk.Encrypt(authid, authid)
		nonce := randBytes(8)
		aid, nn := string(authid), string(nonce)
		encLen := gcm16(vmessKDF(cmdKey, "VMess Header AEAD Key_Length", aid, nn)).Seal(nil,
			vmessKDF(cmdKey, "VMess Header AEAD Nonce_Length", aid, nn)[:12],
			binary.BigEndian.AppendUint16(nil, uint16(len(h))), authid)
		encHdr := gcm16(vmessKDF(cmdKey, "VMess Header AEAD Key", aid, nn)).Seal(nil,
			vmessKDF(cmdKey, "VMess Header AEAD Nonce", aid, nn)[:12], h, authid)
		wire = append(append(append(authid, encLen...), nonce...), encHdr...)
	}

	raw, err := v.Dialer.DialContext(ctx, "tcp", v.Server)
	if err != nil {
		return nil, err
	}
	if _, err := raw.Write(wire); err != nil {
		raw.Close()
		return nil, err
	}

	var rKey, rIV []byte
	if legacy {
		rKey, rIV = md5sum(bodyKey), md5sum(bodyIV)
	} else {
		k, i := sha256.Sum256(bodyKey), sha256.Sum256(bodyIV)
		rKey, rIV = k[:16], i[:16]
	}
	c := &vmessConn{Conn: raw, sec: sec, wIV: bodyIV, rIV: rIV, rKey: rKey, respV: respV, legacy: legacy}
	if c.wAEAD, err = vmessBody(sec, bodyKey); err != nil {
		raw.Close()
		return nil, err
	}
	c.wMask = vmessMask(bodyIV)
	return c, nil
}

func vmessBody(sec byte, key []byte) (cipher.AEAD, error) {
	switch sec {
	case 3:
		return gcm16(key), nil
	case 4:
		k := md5sum(key)
		k = append(k, md5sum(k)...)
		return chacha20poly1305.New(k)
	}
	return nil, nil // none
}

func vmessMask(iv []byte) sha3.ShakeHash {
	s := sha3.NewShake128()
	s.Write(iv)
	return s
}

func nextMask(s sha3.ShakeHash) uint16 {
	var b [2]byte
	s.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func chunkNonce(count uint16, iv []byte) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint16(n, count)
	copy(n[2:], iv[2:12])
	return n
}

type vmessConn struct {
	net.Conn
	sec    byte
	legacy bool
	respV  byte

	wAEAD  cipher.AEAD
	wIV    []byte
	wCount uint16
	wMask  sha3.ShakeHash

	once   sync.Once
	herr   error
	rKey   []byte
	rIV    []byte
	rAEAD  cipher.AEAD
	rCount uint16
	rMask  sha3.ShakeHash
	rbuf   []byte
}

func (c *vmessConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 8192 {
			n = 8192
		}
		data := p[:n]
		if c.wAEAD != nil {
			data = c.wAEAD.Seal(nil, chunkNonce(c.wCount, c.wIV), data, nil)
			c.wCount++
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(data))^nextMask(c.wMask))
		out = append(out, data...)
		if _, err := c.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *vmessConn) readHeader() error {
	if c.legacy {
		blk, _ := aes.NewCipher(c.rKey)
		dec := cipher.NewCFBDecrypter(blk, c.rIV)
		h := make([]byte, 4)
		if _, err := io.ReadFull(c.Conn, h); err != nil {
			return err
		}
		dec.XORKeyStream(h, h)
		if h[0] != c.respV {
			return fmt.Errorf("vmess: bad response header")
		}
		if h[3] > 0 {
			d := make([]byte, h[3])
			if _, err := io.ReadFull(c.Conn, d); err != nil {
				return err
			}
		}
	} else {
		lb := make([]byte, 18)
		if _, err := io.ReadFull(c.Conn, lb); err != nil {
			return err
		}
		l, err := gcm16(vmessKDF(c.rKey, "AEAD Resp Header Len Key")).Open(nil,
			vmessKDF(c.rIV, "AEAD Resp Header Len IV")[:12], lb, nil)
		if err != nil {
			return err
		}
		hb := make([]byte, int(binary.BigEndian.Uint16(l))+16)
		if _, err := io.ReadFull(c.Conn, hb); err != nil {
			return err
		}
		h, err := gcm16(vmessKDF(c.rKey, "AEAD Resp Header Key")).Open(nil,
			vmessKDF(c.rIV, "AEAD Resp Header IV")[:12], hb, nil)
		if err != nil || len(h) < 4 || h[0] != c.respV {
			return fmt.Errorf("vmess: bad response header")
		}
	}
	// body keys: legacy and AEAD both use the response key/iv as-is
	var err error
	c.rAEAD, err = vmessBody(c.sec, c.rKey)
	c.rMask = vmessMask(c.rIV)
	return err
}

func (c *vmessConn) Read(p []byte) (int, error) {
	c.once.Do(func() { c.herr = c.readHeader() })
	if c.herr != nil {
		return 0, c.herr
	}
	for len(c.rbuf) == 0 {
		var lb [2]byte
		if _, err := io.ReadFull(c.Conn, lb[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(lb[:]) ^ nextMask(c.rMask))
		if n == 0 {
			return 0, io.EOF
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.Conn, buf); err != nil {
			return 0, err
		}
		if c.rAEAD != nil {
			var err error
			if buf, err = c.rAEAD.Open(nil, chunkNonce(c.rCount, c.rIV), buf, nil); err != nil {
				return 0, err
			}
			c.rCount++
		}
		if len(buf) == 0 {
			return 0, io.EOF
		}
		c.rbuf = buf
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}
