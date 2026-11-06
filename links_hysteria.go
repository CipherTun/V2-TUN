package v2tun

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// parseHysteriaLink reads hysteria2:// (hy2://) and hysteria:// (hy://) links.
//
//	hysteria2://[auth@]host[:port]/?obfs=salamander&obfs-password=..&sni=..&insecure=1&pinSHA256=..
//	hysteria://host:port?auth=..&peer=..&insecure=1&upmbps=..&downmbps=..&alpn=..&obfs=xplus&obfsParam=..
func parseHysteriaLink(scheme, link string) (*Config, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		// a port range such as 20000-30000 (port hopping) lands here
		return nil, "", fmt.Errorf("link: %v (port hopping is not supported)", err)
	}
	q := u.Query()
	port := 443
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, "", errors.New("link: port hopping is not supported")
		}
		port = n
	}
	cfg := &Config{Server: u.Hostname(), Port: port, Hysteria: &HysteriaConfig{}}
	cfg.TLS.SNI = q.Get("sni")
	cfg.TLS.AllowInsecure = truthy(q.Get("insecure"))

	switch scheme {
	case "hysteria2", "hy2":
		cfg.Protocol = "hysteria2"
		auth := u.User.Username()
		if pw, ok := u.User.Password(); ok {
			auth += ":" + pw
		}
		cfg.Password = auth
		if t := q.Get("obfs"); t != "" {
			if !strings.EqualFold(t, "salamander") {
				return nil, "", fmt.Errorf("link: unsupported obfs %q", t)
			}
			cfg.Hysteria.Obfs = q.Get("obfs-password")
		}
		cfg.Hysteria.PinSHA256 = q.Get("pinSHA256")
	default: // hysteria, hy
		cfg.Protocol = "hysteria"
		cfg.Password = q.Get("auth")
		if cfg.TLS.SNI == "" {
			cfg.TLS.SNI = q.Get("peer")
		}
		switch p := strings.ToLower(q.Get("protocol")); p {
		case "", "udp":
		default:
			return nil, "", fmt.Errorf("link: hysteria protocol %q is not supported (only udp)", p)
		}
		cfg.Hysteria.ALPN = q.Get("alpn")
		cfg.Hysteria.UpMbps, _ = strconv.Atoi(q.Get("upmbps"))
		cfg.Hysteria.DownMbps, _ = strconv.Atoi(q.Get("downmbps"))
		if o := q.Get("obfs"); o != "" {
			if !strings.EqualFold(o, "xplus") {
				return nil, "", fmt.Errorf("link: unsupported obfs %q", o)
			}
			cfg.Hysteria.Obfs = q.Get("obfsParam")
		}
	}
	return cfg, u.Fragment, nil
}
