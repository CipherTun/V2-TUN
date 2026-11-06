package transport

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
)

var sharedRes atomic.Pointer[net.Resolver]

// SetSharedResolver installs the protected resolver used by helpers that have
// no resolver of their own (for example Shadowsocks native UDP).
func SetSharedResolver(r *net.Resolver) { sharedRes.Store(r) }

// ResolveUDPAddr resolves host:port with the shared (VPN-bypassing) resolver.
// IP literals pass through; IPv4 answers are preferred.
func ResolveUDPAddr(ctx context.Context, addr string) (*net.UDPAddr, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("transport: bad port in %q", addr)
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	rs := sharedRes.Load()
	if rs == nil {
		rs = net.DefaultResolver
	}
	ips, err := rs.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("transport: no address for %s", host)
	}
	pick := ips[0].IP
	for _, a := range ips {
		if a.IP.To4() != nil {
			pick = a.IP
			break
		}
	}
	return &net.UDPAddr{IP: pick, Port: port}, nil
}
