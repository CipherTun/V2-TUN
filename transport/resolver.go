package transport

import (
	"context"
	"net"
	"time"
)

// NewResolver returns a resolver that asks server ("1.1.1.1:53") over a
// protected socket, so hostname lookups never loop back into the VPN.
func NewResolver(server string) *net.Resolver {
	if server == "" {
		return nil
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second, Control: controlFn}
		return d.DialContext(ctx, network, server)
	}}
}
