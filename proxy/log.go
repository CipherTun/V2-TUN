package proxy

import (
	"strings"

	"io.surprise.vpn/internal/logx"
)

var (
	failLog = logx.L("failover")
	sshLog  = logx.L("ssh")
	latLog  = logx.L("latency")

	// Every outbound failing is repeated for every connection while the
	// network is down, so those entries are rate limited.
	allFailedLim logx.Limiter
	udpFailedLim logx.Limiter
)

// oneLine flattens a joined error to a single line for the log.
func oneLine(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}
