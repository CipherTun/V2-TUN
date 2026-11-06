package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"io.surprise.vpn/transport"
)

// SOCKS tunnels through a SOCKS5 server (user/password auth supported) or a
// SOCKS4/4a server (user id only). Only CONNECT is used, so UDP goes through
// udpgw or another outbound. Put a payload or TLS layer under it with Dialer.
type SOCKS struct {
	Server   string
	Dialer   transport.Dialer
	Username string
	Password string
	Version  int // 5 (default) or 4
}

func (s *SOCKS) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	c, err := s.Dialer.DialContext(ctx, "tcp", s.Server)
	if err != nil {
		return nil, err
	}
	// A server that never answers must not hang the dial past ctx.
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if s.Version == 4 {
		err = s.connect4(c, a)
	} else {
		err = s.connect5(c, a)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (s *SOCKS) connect5(c net.Conn, a addr) error {
	methods := []byte{0}
	if s.Username != "" || s.Password != "" {
		methods = []byte{0, 2}
	}
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[0] != 5 {
		return errors.New("socks5: bad version in the server's reply")
	}
	switch rep[1] {
	case 0:
	case 2:
		if len(s.Username) > 255 || len(s.Password) > 255 {
			return errors.New("socks5: username or password longer than 255 bytes")
		}
		req := []byte{1, byte(len(s.Username))}
		req = append(req, s.Username...)
		req = append(req, byte(len(s.Password)))
		req = append(req, s.Password...)
		if _, err := c.Write(req); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			return err
		}
		if rep[1] != 0 {
			return errors.New("socks5: authentication failed")
		}
	default:
		return fmt.Errorf("socks5: no acceptable authentication method (server chose %#x)", rep[1])
	}
	req := append([]byte{5, 1, 0}, a.socks()...)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	if h[0] != 5 {
		return errors.New("socks5: bad version in the connect reply")
	}
	if h[1] != 0 {
		return fmt.Errorf("socks5: connect failed: %s", socks5Error(h[1]))
	}
	var skip int64
	switch h[3] { // bound address, not needed
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int64(l[0]) + 2
	default:
		return errors.New("socks5: bad address type in the connect reply")
	}
	_, err := io.CopyN(io.Discard, c, skip)
	return err
}

func socks5Error(code byte) string {
	switch code {
	case 1:
		return "general failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	}
	return fmt.Sprintf("code %#x", code)
}

func (s *SOCKS) connect4(c net.Conn, a addr) error {
	req := []byte{4, 1, byte(a.port >> 8), byte(a.port)}
	switch {
	case a.ip != nil && a.ip.To4() != nil:
		req = append(req, a.ip.To4()...)
		req = append(req, s.Username...)
		req = append(req, 0)
	case a.ip != nil:
		return errors.New("socks4: IPv6 targets are not supported")
	default: // SOCKS4a: 0.0.0.x marks a host name after the user id
		req = append(req, 0, 0, 0, 1)
		req = append(req, s.Username...)
		req = append(req, 0)
		req = append(req, a.host...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [8]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return err
	}
	if rep[1] != 0x5a {
		return fmt.Errorf("socks4: request rejected (code %#x)", rep[1])
	}
	return nil
}
