// Package proxy implements outbound protocols on top of transport.Dialer.
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
)

// Outbound dials a target through a remote proxy server.
type Outbound interface {
	DialContext(ctx context.Context, network, target string) (net.Conn, error)
}

var ErrNotImplemented = errors.New("v2tun: protocol not implemented yet")

type addr struct {
	ip   net.IP
	host string
	port uint16
}

func parseTarget(target string) (addr, error) {
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return addr{}, err
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return addr{}, err
	}
	a := addr{port: uint16(n)}
	if ip := net.ParseIP(h); ip != nil {
		a.ip = ip
	} else {
		if len(h) > 255 {
			return addr{}, errors.New("host too long")
		}
		a.host = h
	}
	return a, nil
}

// socksAddr: ATYP(1=v4,3=domain,4=v6) ADDR PORT  (used by Trojan)
func (a addr) socks() []byte {
	var b []byte
	switch {
	case a.ip != nil && a.ip.To4() != nil:
		b = append([]byte{1}, a.ip.To4()...)
	case a.ip != nil:
		b = append([]byte{4}, a.ip.To16()...)
	default:
		b = append([]byte{3, byte(len(a.host))}, a.host...)
	}
	return binary.BigEndian.AppendUint16(b, a.port)
}

// vlessAddr: PORT ATYP(1=v4,2=domain,3=v6) ADDR  (used by VLESS)
func (a addr) vless() []byte {
	b := binary.BigEndian.AppendUint16(nil, a.port)
	switch {
	case a.ip != nil && a.ip.To4() != nil:
		b = append(b, 1)
		b = append(b, a.ip.To4()...)
	case a.ip != nil:
		b = append(b, 3)
		b = append(b, a.ip.To16()...)
	default:
		b = append(b, 2, byte(len(a.host)))
		b = append(b, a.host...)
	}
	return b
}
