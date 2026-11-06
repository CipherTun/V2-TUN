package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// obfsConn XORs every datagram with a hash of (key + random salt) and puts the
// salt in front: the packet format of Hysteria 2 "Salamander" (8-byte salt,
// BLAKE2b-256) and Hysteria 1 "xplus" (16-byte salt, SHA-256).
type obfsConn struct {
	net.PacketConn
	key     []byte
	saltLen int
	hash    func(key, salt []byte) [32]byte

	rmu  sync.Mutex
	rbuf []byte
}

// NewSalamander wraps pc with Hysteria 2's Salamander obfuscation.
func NewSalamander(pc net.PacketConn, key []byte) net.PacketConn {
	return &obfsConn{PacketConn: pc, key: key, saltLen: 8, hash: func(k, s []byte) [32]byte {
		return blake2b.Sum256(append(append([]byte(nil), k...), s...))
	}}
}

// NewXPlus wraps pc with Hysteria 1's "xplus" obfuscation.
func NewXPlus(pc net.PacketConn, key []byte) net.PacketConn {
	return &obfsConn{PacketConn: pc, key: key, saltLen: 16, hash: func(k, s []byte) [32]byte {
		return sha256.Sum256(append(append([]byte(nil), k...), s...))
	}}
}

func (c *obfsConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	out := make([]byte, c.saltLen+len(p))
	salt := out[:c.saltLen]
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	h := c.hash(c.key, salt)
	for i, b := range p {
		out[c.saltLen+i] = b ^ h[i%32]
	}
	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom drops packets that are too short to carry a salt and returns the
// next one that is long enough, de-obfuscated.
func (c *obfsConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	need := len(p) + c.saltLen
	if cap(c.rbuf) < need {
		c.rbuf = make([]byte, need)
	}
	buf := c.rbuf[:need]
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= c.saltLen {
			continue
		}
		h := c.hash(c.key, buf[:c.saltLen])
		m := n - c.saltLen
		for i := 0; i < m; i++ {
			p[i] = buf[c.saltLen+i] ^ h[i%32]
		}
		return m, addr, nil
	}
}
