package mobile

import (
	"context"
	"encoding/json"
	"time"

	v2tun "io.surprise.vpn"
)

// DiagnoseConfig tests a config layer by layer without starting a tunnel and
// returns the result as JSON:
//
//	{"ok":false,"summary":"Failed at tls: ...","stages":[
//	  {"name":"dns","ok":true,"ms":12,"detail":"..."},
//	  {"name":"payload","ok":false,"ms":8001,"raw":"HTTP/1.1 403 ...","error":"..."}]}
//
// The stages are config, dns, tcp, payload, tls, banner, transport and tunnel;
// they stop at the first one that fails. "raw" is what the server sent back.
// seconds limits the whole test (<= 0 means 60). It can run while the VPN is
// up as long as SetProtector was called, so its sockets bypass the tunnel.
func DiagnoseConfig(configJSON string, seconds int) (string, error) {
	var cfg v2tun.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		mlog.Error("the config is not valid JSON", "err", err)
		return "", err
	}
	if seconds <= 0 {
		seconds = 60
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	rep := v2tun.ProbeStages(ctx, &cfg)
	mlog.Info("connection test finished", "ok", rep.OK, "summary", rep.Summary)
	b, err := json.Marshal(rep)
	return string(b), err
}
