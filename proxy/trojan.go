package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"

	"io.surprise.vpn/transport"
)

// Trojan works over TLS or plaintext, depending on the Dialer chain.
type Trojan struct {
	Server   string
	Dialer   transport.Dialer
	Password string
}

func (t *Trojan) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return t.dial(ctx, target, 1)
}

func (t *Trojan) dial(ctx context.Context, target string, cmd byte) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	c, err := t.Dialer.DialContext(ctx, "tcp", t.Server)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum224([]byte(t.Password))
	hdr := []byte(hex.EncodeToString(sum[:]))
	hdr = append(hdr, '\r', '\n', cmd) // 1 connect, 3 udp associate
	hdr = append(hdr, a.socks()...)
	hdr = append(hdr, '\r', '\n')
	if _, err := c.Write(hdr); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
