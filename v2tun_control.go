package v2tun

import "errors"

import "io.surprise.vpn/proxy"

// OutboundCount is how many outbounds the client has: the main config plus
// its backups.
func (c *Client) OutboundCount() int {
	if f, ok := c.out.(*proxy.Failover); ok {
		return len(f.Outs)
	}
	return 1
}

// SelectOutbound pins the tunnel to one outbound (0 is the main config, 1 the
// first backup, ...). A pinned outbound is the only one used: when it fails,
// connections fail instead of moving to the next backup. A negative index
// removes the pin and returns to automatic failover. While pinned, UDP flows
// need the pinned outbound to relay UDP itself (or fall back to nothing).
func (c *Client) SelectOutbound(i int) error {
	f, ok := c.out.(*proxy.Failover)
	if !ok {
		if i <= 0 {
			return nil
		}
		return errors.New("v2tun: the config has no backups to select")
	}
	if i < 0 {
		f.Unpin()
		return nil
	}
	return f.Pin(i)
}
