package transport

import (
	"context"
	"net"
)

// Via always connects to Addr, whatever address the layer above asks for.
// It is how the HTTP-Injector style "remote proxy" mode works: put it under a
// Payload layer and the TCP connection goes to the proxy while the payload
// ([host_port], [host], ...) still names the real next hop.
type Via struct {
	Inner Dialer
	Addr  string // host:port to dial instead
}

func (d *Via) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return d.Inner.DialContext(ctx, network, d.Addr)
}
