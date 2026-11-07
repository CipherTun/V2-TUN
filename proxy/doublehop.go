package proxy

import (
	"context"
	"net"
)

// DoubleHop chains two SSH servers. Jump is reached through the normal dial
// chain (payload, TLS/SNI, WebSocket, ...), so the network only ever sees the
// first hop. Target is then reached from inside the Jump session and is where
// the traffic exits; its handshake is carried entirely inside the first hop's
// encryption.
//
// Jump.Server is host:port as the client reaches it. Target.Server is host:port
// as the jump host reaches it. An *SSH is itself a transport.Dialer, so the
// second hop simply dials through the first.
type DoubleHop struct {
	Jump   *SSH
	Target *SSH
}

var _ Outbound = (*DoubleHop)(nil)

// NewDoubleHop routes target's connection through jump. It sets target.Dialer.
func NewDoubleHop(jump, target *SSH) *DoubleHop {
	target.Dialer = jump
	return &DoubleHop{Jump: jump, Target: target}
}

func (d *DoubleHop) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return d.Target.DialContext(ctx, network, target)
}

// Close ends the target session first, then the jump session, so neither
// keepalive outlives a stopped VPN.
func (d *DoubleHop) Close() error {
	err := d.Target.Close()
	if e := d.Jump.Close(); err == nil {
		err = e
	}
	return err
}
