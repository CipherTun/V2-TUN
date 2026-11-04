package v2tun

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func b64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func truthy(s string) bool { s = strings.ToLower(s); return s == "1" || s == "true" }

// ParseLink converts a share link (vless://, vmess://, trojan://, ss://, ssh://)
// into a Config and the display name.
func ParseLink(link string) (*Config, string, error) {
	link = strings.TrimSpace(link)
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok {
		return nil, "", errors.New("link: missing scheme")
	}
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVMess(rest)
	case "ss":
		return parseSS(rest)
	case "vless", "trojan", "ssh":
		return parseURLLink(strings.ToLower(scheme), link)
	}
	return nil, "", fmt.Errorf("link: unsupported scheme %q", scheme)
}

func applyQuery(cfg *Config, q url.Values) error {
	n := strings.ToLower(q.Get("type"))
	if n == "splithttp" {
		n = "xhttp"
	}
	if n == "tcp" {
		n = ""
	}
	cfg.Network = n
	cfg.WS.Host = q.Get("host")
	cfg.WS.Path = q.Get("path")
	cfg.XHTTPMode = q.Get("mode")
	cfg.GRPCService = q.Get("serviceName")
	switch sec := strings.ToLower(q.Get("security")); sec {
	case "tls":
		cfg.TLS.Enabled = true
	case "reality":
		return errors.New("link: reality is not supported yet")
	case "", "none":
	default:
		return fmt.Errorf("link: unknown security %q", sec)
	}
	cfg.TLS.SNI = q.Get("sni")
	if cfg.TLS.SNI == "" {
		cfg.TLS.SNI = q.Get("peer")
	}
	if a := q.Get("alpn"); a != "" {
		cfg.TLS.ALPN = strings.Split(a, ",")
	}
	cfg.TLS.Fingerprint = q.Get("fp")
	for _, k := range []string{"allowInsecure", "allow_insecure", "insecure"} {
		if truthy(q.Get(k)) {
			cfg.TLS.AllowInsecure = true
		}
	}
	return nil
}

func parseURLLink(scheme, link string) (*Config, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", err
	}
	port, _ := strconv.Atoi(u.Port())
	cfg := &Config{Protocol: scheme, Server: u.Hostname(), Port: port}
	pw, _ := u.User.Password()
	switch scheme {
	case "vless":
		cfg.UUID = u.User.Username()
	case "trojan":
		cfg.Password = u.User.Username()
		cfg.TLS.Enabled = true // trojan defaults to TLS
	case "ssh":
		cfg.Username, cfg.Password = u.User.Username(), pw
	}
	q := u.Query()
	if scheme == "trojan" && strings.EqualFold(q.Get("security"), "none") {
		cfg.TLS.Enabled = false
	}
	if scheme != "ssh" {
		keep := cfg.TLS.Enabled
		if err := applyQuery(cfg, q); err != nil {
			return nil, "", err
		}
		if scheme == "trojan" && q.Get("security") == "" {
			cfg.TLS.Enabled = keep
		}
	}
	return cfg, u.Fragment, nil
}

func parseVMess(rest string) (*Config, string, error) {
	raw, err := b64(rest)
	if err != nil {
		return nil, "", err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", err
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	port, _ := strconv.Atoi(str("port"))
	aid, _ := strconv.Atoi(str("aid"))
	cfg := &Config{Protocol: "vmess", Server: str("add"), Port: port, UUID: str("id"), AlterID: aid,
		Method: str("scy"), Network: str("net")}
	if cfg.Network == "tcp" {
		cfg.Network = ""
	}
	if cfg.Network == "splithttp" {
		cfg.Network = "xhttp"
	}
	cfg.WS.Host, cfg.WS.Path = str("host"), str("path")
	if cfg.Network == "grpc" {
		cfg.GRPCService = str("path")
	}
	cfg.TLS.Enabled = str("tls") == "tls"
	cfg.TLS.SNI = str("sni")
	if a := str("alpn"); a != "" {
		cfg.TLS.ALPN = strings.Split(a, ",")
	}
	cfg.TLS.Fingerprint = str("fp")
	cfg.TLS.AllowInsecure = truthy(str("allowInsecure"))
	return cfg, str("ps"), nil
}

func parseSS(rest string) (*Config, string, error) {
	rest, name, _ := strings.Cut(rest, "#")
	name, _ = url.QueryUnescape(name)
	rest, _, _ = strings.Cut(rest, "?") // plugins are not supported
	var userinfo, hostport string
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		userinfo, hostport = rest[:i], rest[i+1:]
		if !strings.Contains(userinfo, ":") {
			b, err := b64(userinfo)
			if err != nil {
				return nil, "", err
			}
			userinfo = string(b)
		} else if d, err := url.PathUnescape(userinfo); err == nil {
			userinfo = d
		}
	} else {
		b, err := b64(rest)
		if err != nil {
			return nil, "", err
		}
		var ok bool
		userinfo, hostport, ok = strings.Cut(string(b), "@")
		if !ok {
			return nil, "", errors.New("link: bad ss link")
		}
	}
	method, pw, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil, "", errors.New("link: bad ss userinfo")
	}
	host, ps, err := splitHostPort(hostport)
	if err != nil {
		return nil, "", err
	}
	return &Config{Protocol: "shadowsocks", Server: host, Port: ps, Method: method, Password: pw}, name, nil
}

func splitHostPort(hp string) (string, int, error) {
	u, err := url.Parse("x://" + strings.TrimSuffix(hp, "/"))
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(u.Port())
	return u.Hostname(), p, err
}
