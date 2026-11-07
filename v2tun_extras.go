package v2tun

import (
	"net"
	"strconv"
	"strings"
)

// probeAddr is the host:port a latency probe connects to for cfg: the payload
// proxy when one is set (the first thing the carrier sees), otherwise the
// server. Protocols that run over UDP (hysteria, quic) cannot be probed with a
// TCP connect and give "", which proxy.Failover ranks between answering and
// unreachable servers.
func probeAddr(cfg *Config) string {
	switch strings.ToLower(cfg.Protocol) {
	case "hysteria", "hysteria1", "hy", "hysteria2", "hy2":
		return ""
	}
	if strings.EqualFold(cfg.Network, "quic") {
		return ""
	}
	if cfg.Payload != nil && cfg.Payload.Proxy != "" {
		return cfg.Payload.Proxy
	}
	return net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
}
