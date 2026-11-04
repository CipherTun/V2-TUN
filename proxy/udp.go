package proxy

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"io.surprise.vpn/transport"
)

// UDPOutbound returns a "connected" datagram conn: one Write/Read = one datagram.
type UDPOutbound interface {
	DialUDP(ctx context.Context, target string) (net.Conn, error)
}

// ---------- VLESS / VMess ----------

// lenConn frames datagrams with a 2-byte length over a stream (VLESS UDP).
type lenConn struct{ net.Conn }

func (c *lenConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("udp: datagram too large")
	}
	if _, err := c.Conn.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *lenConn) Read(p []byte) (int, error) {
	var l [2]byte
	if _, err := io.ReadFull(c.Conn, l[:]); err != nil {
		return 0, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, err
	}
	return copy(p, buf), nil
}

func (v *VLESS) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	c, err := v.dial(ctx, target, 2)
	if err != nil {
		return nil, err
	}
	return &lenConn{Conn: c}, nil
}

// VMess: each datagram is exactly one chunk, so the chunked conn already fits.
func (v *VMess) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	return v.dial(ctx, target, 2)
}

// ---------- Trojan ----------

type trojanUDPConn struct {
	net.Conn
	addr []byte
}

func (t *Trojan) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	c, err := t.dial(ctx, target, 3)
	if err != nil {
		return nil, err
	}
	return &trojanUDPConn{Conn: c, addr: a.socks()}, nil
}

func (c *trojanUDPConn) Write(p []byte) (int, error) {
	pkt := append([]byte(nil), c.addr...)
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(len(p)))
	pkt = append(pkt, '\r', '\n')
	pkt = append(pkt, p...)
	if _, err := c.Conn.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *trojanUDPConn) Read(p []byte) (int, error) {
	if _, err := readSocksAddr(c.Conn); err != nil {
		return 0, err
	}
	var h [4]byte // len(2) + CRLF
	if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
		return 0, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(h[:2]))
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return 0, err
	}
	return copy(p, buf), nil
}

func readSocksAddr(r io.Reader) ([]byte, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return nil, err
	}
	var n int
	switch t[0] {
	case 1:
		n = 4 + 2
	case 4:
		n = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		n = int(l[0]) + 2
	default:
		return nil, errors.New("udp: bad address type")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// ---------- Shadowsocks (native UDP packets) ----------

type ssUDPConn struct {
	pc   net.PacketConn
	srv  net.Addr
	spec ssSpec
	key  []byte
	hdr  []byte
}

func (s *Shadowsocks) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	spec, ok := ssMethods[strings.ToLower(s.Method)]
	if !ok {
		return nil, fmt.Errorf("shadowsocks: unsupported method %q", s.Method)
	}
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	srv, err := net.ResolveUDPAddr("udp", s.Server)
	if err != nil {
		return nil, err
	}
	pc, err := transport.ListenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return &ssUDPConn{pc: pc, srv: srv, spec: spec, key: evpKey(s.Password, spec.keySize), hdr: a.socks()}, nil
}

func (c *ssUDPConn) subAEAD(salt []byte) (cipher.AEAD, error) {
	sub := make([]byte, c.spec.keySize)
	if _, err := io.ReadFull(hkdf.New(sha1.New, c.key, salt, []byte("ss-subkey")), sub); err != nil {
		return nil, err
	}
	return c.spec.aead(sub)
}

func (c *ssUDPConn) Write(p []byte) (int, error) {
	plain := append(append([]byte(nil), c.hdr...), p...)
	var out []byte
	if c.spec.aead != nil {
		salt := make([]byte, c.spec.keySize)
		rand.Read(salt)
		a, err := c.subAEAD(salt)
		if err != nil {
			return 0, err
		}
		out = a.Seal(salt, make([]byte, a.NonceSize()), plain, nil)
	} else {
		iv := make([]byte, c.spec.ivSize)
		rand.Read(iv)
		st, err := c.spec.stream(c.key, iv, true)
		if err != nil {
			return 0, err
		}
		st.XORKeyStream(plain, plain)
		out = append(iv, plain...)
	}
	if _, err := c.pc.WriteTo(out, c.srv); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ssUDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		var plain []byte
		if c.spec.aead != nil {
			if n < c.spec.keySize {
				continue
			}
			a, err := c.subAEAD(buf[:c.spec.keySize])
			if err != nil {
				continue
			}
			if plain, err = a.Open(nil, make([]byte, a.NonceSize()), buf[c.spec.keySize:n], nil); err != nil {
				continue
			}
		} else {
			if n < c.spec.ivSize {
				continue
			}
			st, err := c.spec.stream(c.key, buf[:c.spec.ivSize], false)
			if err != nil {
				continue
			}
			plain = make([]byte, n-c.spec.ivSize)
			st.XORKeyStream(plain, buf[c.spec.ivSize:n])
		}
		hl := socksAddrLen(plain)
		if hl == 0 || hl > len(plain) {
			continue
		}
		return copy(p, plain[hl:]), nil
	}
}

func socksAddrLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	switch b[0] {
	case 1:
		return 7
	case 4:
		return 19
	case 3:
		if len(b) < 2 {
			return 0
		}
		return 4 + int(b[1])
	}
	return 0
}

func (c *ssUDPConn) Close() error                       { return c.pc.Close() }
func (c *ssUDPConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *ssUDPConn) RemoteAddr() net.Addr               { return c.srv }
func (c *ssUDPConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *ssUDPConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *ssUDPConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
