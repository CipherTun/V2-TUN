package mobile

import (
	"context"
	"encoding/json"
	"time"

	v2tun "io.surprise.vpn"
)

// ProbeHostKey connects to the SSH server in the config (through its payload,
// TLS or WebSocket chain), does the key exchange and returns the server's host
// key fingerprint as "SHA256:..." without logging in. Use it on first use and
// store the result as advanced.sshHostKey to pin the server. timeoutSec <= 0
// means 20 seconds. Like Probe, it needs SetProtector while the VPN is up.
func ProbeHostKey(configJSON string, timeoutSec int) (string, error) {
	var cfg v2tun.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", err
	}
	if timeoutSec <= 0 {
		timeoutSec = 20
	}
	ctx, cf := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cf()
	return v2tun.ProbeHostKey(ctx, &cfg)
}
