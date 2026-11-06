package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"io.surprise.vpn/payload"
	"io.surprise.vpn/transport"
)

// HTTPProxy tunnels through an HTTP proxy with CONNECT (Basic auth and extra
// headers supported). For an HTTPS proxy, put TLS in the Dialer chain.
type HTTPProxy struct {
	Server   string
	Dialer   transport.Dialer
	Username string
	Password string
	Headers  map[string]string
}

func (h *HTTPProxy) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if _, err := parseTarget(target); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
	if h.Username != "" || h.Password != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n",
			base64.StdEncoding.EncodeToString([]byte(h.Username+":"+h.Password)))
	}
	for k, v := range h.Headers {
		if strings.ContainsAny(k+v, "\r\n") {
			return nil, fmt.Errorf("http proxy: header %q contains a line break", k)
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")

	c, err := h.Dialer.DialContext(ctx, "tcp", h.Server)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, err := c.Write([]byte(b.String())); err != nil {
		c.Close()
		return nil, err
	}
	code, err := payload.ReadHTTPHeaders(c)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("http proxy: %w", err)
	}
	if code < 200 || code > 299 {
		c.Close()
		return nil, fmt.Errorf("http proxy: CONNECT refused (status %d)", code)
	}
	return c, nil
}
