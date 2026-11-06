package v2tun

import (
	"context"
	"errors"
	"net"
	"strconv"

	"io.surprise.vpn/route"
)

var errNoRouter = errors.New(`v2tun: no routing configured; start with a "routing" section (it may be empty: {}) to change rules while running`)

// SetRouting replaces the routing rules of a running client without
// reconnecting (rules, split tunneling, switches). Lists supplied with
// SetRouteList are kept. On error the old rules stay active.
func (c *Client) SetRouting(cfg *route.Config) error {
	if c.router == nil {
		return errNoRouter
	}
	return c.router.Reconfigure(cfg)
}

// SetRouteLists supplies several named lists ("list:NAME", "geoip:XX",
// "geosite:XX") with a single rebuild of the rules.
func (c *Client) SetRouteLists(lists map[string][]string) error {
	if c.router == nil {
		return errNoRouter
	}
	return c.router.SetLists(lists)
}

// Explain reports what the router would do for a connection to addr and which
// rule decides it. A protocol attached to ctx with route.WithProtocol is honored.
func (c *Client) Explain(ctx context.Context, network, addr string) (route.Decision, error) {
	if c.router == nil {
		return route.Decision{Action: route.Proxy, Rule: "default"}, nil
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return route.Decision{}, err
	}
	port, _ := strconv.Atoi(p)
	return c.router.DecideMeta(ctx, route.Meta{Network: network, Host: h, Port: port, Protocol: route.ProtocolFrom(ctx)}), nil
}
