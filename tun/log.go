package tun

import "io.surprise.vpn/internal/logx"

var (
	tunLog = logx.L("tun")

	// A dead network makes every connection and DNS query fail at once, so
	// these entries are rate limited.
	connFailLim logx.Limiter
	udpFailLim  logx.Limiter
	dnsFailLim  logx.Limiter
)
