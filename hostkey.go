package v2tun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"io.surprise.vpn/proxy"
	"io.surprise.vpn/transport"
)

// ProbeHostKey connects to the SSH server of cfg through its transport chain
// (payload, TLS, WebSocket ...), runs the key exchange and returns the host key
// fingerprint as "SHA256:..." without logging in. Put the result into
// Advanced.SSHHostKey to pin the server (trust on first use). A pin already set
// in cfg is ignored: the point is to learn the key.
func ProbeHostKey(ctx context.Context, cfg *Config) (string, error) {
	if !strings.EqualFold(cfg.Protocol, "ssh") {
		return "", errors.New("v2tun: host key probing needs an ssh config")
	}
	dns := cfg.DirectDNS
	if dns == "" {
		dns = "1.1.1.1:53"
	}
	out, _, err := buildOutbound(cfg, transport.NewResolver(dns))
	if err != nil {
		return "", err
	}
	s, ok := out.(*proxy.SSH)
	if !ok {
		return "", fmt.Errorf("v2tun: unexpected outbound %T", out)
	}
	defer s.Close()
	return s.ProbeHostKey(ctx)
}
