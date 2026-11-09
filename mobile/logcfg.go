package mobile

import (
	"net"
	"strconv"

	v2tun "io.surprise.vpn"
	"io.surprise.vpn/internal/logx"
)

// mlog is the logger of the app-facing lifecycle (start, stop, probes).
var mlog = logx.L("core")

// describeConfig lists the non-secret facts of a config for the log: no
// password, UUID, key or payload text ever goes in.
func describeConfig(cfg *v2tun.Config) []any {
	network := cfg.Network
	if network == "" {
		network = "tcp"
	}
	return []any{
		"protocol", cfg.Protocol,
		"network", network,
		"server", net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port)),
		"tls", cfg.TLS.Enabled,
		"reality", cfg.Reality != nil,
		"payload", cfg.Payload != nil && cfg.Payload.Template != "",
		"mux", cfg.Mux != nil && cfg.Mux.Enabled,
		"backups", len(cfg.Backups),
	}
}

// summary is describeConfig for a config given as JSON (nil when it does not parse).
func summary(configJSON string) []any {
	var cfg v2tun.Config
	if err := jsonUnmarshal(configJSON, &cfg); err != nil {
		return nil
	}
	return describeConfig(&cfg)
}
