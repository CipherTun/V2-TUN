package transport

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
)

var protect atomic.Pointer[func(int) bool]

// SetProtector installs Android's VpnService.protect(fd) so the tunnel's own
// sockets bypass the VPN (otherwise traffic loops back into the TUN).
func SetProtector(f func(fd int) bool) { protect.Store(&f) }

func controlFn(network, address string, c syscall.RawConn) error {
	p := protect.Load()
	if p == nil {
		return nil
	}
	ok := true
	if err := c.Control(func(fd uintptr) { ok = (*p)(int(fd)) }); err != nil {
		return err
	}
	if !ok {
		return errors.New("transport: protect(fd) failed")
	}
	return nil
}

// ListenUDP opens a protected UDP socket (for Shadowsocks UDP, QUIC, ...).
func ListenUDP(ctx context.Context) (net.PacketConn, error) {
	return (&net.ListenConfig{Control: controlFn}).ListenPacket(ctx, "udp", ":0")
}
