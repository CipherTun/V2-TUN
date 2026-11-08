package socks

import "io.surprise.vpn/internal/logx"

var (
	socksLog = logx.L("socks")

	// Repeated failures (a dead network, a client guessing passwords) are
	// rate limited.
	authFailLim logx.Limiter
	connFailLim logx.Limiter
	udpFailLim  logx.Limiter
)
