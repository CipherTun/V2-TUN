package mobile

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	v2tun "io.surprise.vpn"
)

// Extra entry points for the app: checking a config without connecting,
// previewing a payload, a speed test and a bug-host scan. All of them build
// their own client, so they work whether or not the VPN is running.

func decodeConfig(configJSON string) (*v2tun.Config, error) {
	var cfg v2tun.Config
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks a config without connecting. It returns an empty string when
// the config is valid and the reason when it is not.
func Validate(configJSON string) string {
	cfg, err := decodeConfig(configJSON)
	if err != nil {
		return err.Error()
	}
	c, err := v2tun.New(cfg)
	if err != nil {
		return err.Error()
	}
	c.Close()
	return ""
}

// PayloadPreview shows what the config's payload would send and how the reply
// is checked, without connecting.
func PayloadPreview(configJSON string) (string, error) {
	cfg, err := decodeConfig(configJSON)
	if err != nil {
		return "", err
	}
	return v2tun.PreviewPayload(cfg)
}

// SpeedTest downloads url (empty: Cloudflare's endpoint) through the config
// for up to seconds and returns {"bytes":..., "bps":...} (bits per second).
func SpeedTest(configJSON, url string, seconds int) (string, error) {
	cfg, err := decodeConfig(configJSON)
	if err != nil {
		return "", err
	}
	c, err := v2tun.New(cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	n, bps, err := c.SpeedTest(context.Background(), url, time.Duration(seconds)*time.Second)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(struct {
		Bytes int64   `json:"bytes"`
		Bps   float64 `json:"bps"`
	}{n, bps})
	return string(out), err
}

// ScanHosts tries the config once per line of values with that value in field
// (server, tls.sni, ws.host, payload.host or payload.proxy) and returns a JSON
// array of {"value", "ok", "ms", "error"}. A target that is a URL is fetched
// through the tunnel; a host:port is only dialed.
func ScanHosts(configJSON, field, values, target string, concurrency, seconds int) (string, error) {
	cfg, err := decodeConfig(configJSON)
	if err != nil {
		return "", err
	}
	var list []string
	for _, l := range strings.Split(values, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			list = append(list, l)
		}
	}
	res := v2tun.Scan(context.Background(), cfg, field, list, target, concurrency, time.Duration(seconds)*time.Second)
	out, err := json.Marshal(res)
	return string(out), err
}

// ActiveOutbound says which config the running tunnel uses: 0 for the main
// config, 1 for the first backup and so on, -1 when nothing is running.
func ActiveOutbound() int {
	mu.Lock()
	c := active
	mu.Unlock()
	if c == nil {
		return -1
	}
	return c.ActiveOutbound()
}
