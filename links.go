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

// ParseLink converts a share link (vless://, vmess://, trojan://, ss://,
// ssh://, socks5://, socks4://, http://, https://, hysteria2://, hy2://,
// hysteria://) into a Config and the display name.
//
// Features the library cannot honor are rejected with an error instead of
// being dropped silently (which would only show up later as a connection that
// never works): VLESS flows other than xtls-rprx-vision, Vision without TLS or
// REALITY (or on a non-tcp transport), Shadowsocks plugins, Hysteria port
// hopping, faketcp and wechat-video. REALITY links (security=reality with pbk,
// sid, sni, fp) are supported; the spiderX crawl (spx) is ignored.
// http:// and https:// links describe an HTTP proxy (https uses TLS to the
// proxy), socks:// links a SOCKS proxy.
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
	case "vless", "trojan", "ssh", "socks", "socks5", "socks5h", "socks4", "socks4a", "http", "https":
		return parseURLLink(strings.ToLower(scheme), link)
	case "hysteria2", "hy2", "hysteria", "hy":
		return parseHysteriaLink(strings.ToLower(scheme), link)
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
	if n == "grpc" && strings.EqualFold(q.Get("mode"), "multi") {
		cfg.GRPCMulti = true
	}
	if n == "xhttp" {
		if x := q.Get("extra"); x != "" {
			if err := applyXHTTPExtra(cfg, x); err != nil {
				return err
			}
		}
	}
	switch sec := strings.ToLower(q.Get("security")); sec {
	case "tls":
		cfg.TLS.Enabled = true
	case "reality":
		if q.Get("pbk") == "" {
			return errors.New("link: reality link has no pbk (server public key)")
		}
		cfg.Reality = &RealityConfig{
			PublicKey:   q.Get("pbk"),
			ShortID:     q.Get("sid"),
			ServerName:  q.Get("sni"),
			Fingerprint: q.Get("fp"),
		}
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
	defPort := func(p int) {
		if cfg.Port == 0 {
			cfg.Port = p
		}
	}
	switch scheme {
	case "vless":
		cfg.UUID = u.User.Username()
	case "trojan":
		cfg.Password = u.User.Username()
		cfg.TLS.Enabled = true // trojan defaults to TLS
	case "ssh":
		cfg.Username, cfg.Password = u.User.Username(), pw
		defPort(22)
	case "socks", "socks5", "socks5h":
		cfg.Protocol = "socks5"
		cfg.Username, cfg.Password = u.User.Username(), pw
		defPort(1080)
	case "socks4", "socks4a":
		cfg.Protocol = "socks4"
		cfg.Username, cfg.Password = u.User.Username(), pw
		defPort(1080)
	case "http":
		cfg.Username, cfg.Password = u.User.Username(), pw
		defPort(8080)
	case "https":
		cfg.Username, cfg.Password = u.User.Username(), pw
		cfg.TLS.Enabled = true
		defPort(443)
	}
	q := u.Query()
	if scheme == "vless" && q.Get("flow") != "" {
		// A server that expects a flow rejects clients that do not speak it.
		cfg.Flow = strings.ToLower(q.Get("flow"))
		if f := cfg.Flow; f != "xtls-rprx-vision" && f != "xtls-rprx-vision-udp443" {
			return nil, "", fmt.Errorf("link: vless flow %q is not supported", q.Get("flow"))
		}
	}
	if scheme == "trojan" && strings.EqualFold(q.Get("security"), "none") {
		cfg.TLS.Enabled = false
	}
	if scheme != "ssh" {
		keep := cfg.TLS.Enabled
		if err := applyQuery(cfg, q); err != nil {
			return nil, "", err
		}
		if (scheme == "trojan" || scheme == "https") && q.Get("security") == "" {
			cfg.TLS.Enabled = keep
		}
	}
	if err := checkFlow(cfg); err != nil {
		return nil, "", fmt.Errorf("link: %w", err)
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
		cfg.GRPCMulti = strings.EqualFold(str("type"), "multi")
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
	rest, query, _ := strings.Cut(rest, "?")
	if strings.Contains(query, "plugin=") {
		// obfs-local / v2ray-plugin wrap the connection; ignoring them would
		// produce a config that can never connect.
		return nil, "", errors.New("link: shadowsocks plugins are not supported")
	}
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

// applyXHTTPExtra reads the "extra" JSON of an xhttp share link (Xray's
// XHTTP extra settings): xPaddingBytes, scMaxEachPostBytes,
// scMinPostsIntervalMs, headers and downloadSettings. Ranges ("100-1000" or
// {"from":100,"to":1000}) are accepted; padding keeps the range, the other two
// take its lower bound. Keys that have no equivalent here (xmux, noGRPCHeader,
// ...) are ignored; downloadSettings that cannot be honored are an error.
func applyXHTTPExtra(cfg *Config, raw string) error {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return fmt.Errorf("link: bad xhttp extra: %w", err)
	}
	o := cfg.XHTTP
	if o == nil {
		o = &XHTTPOptions{}
	}
	if lo, hi, ok := jsonRange(m["xPaddingBytes"]); ok {
		o.XPaddingBytes = [2]int{lo, hi}
	}
	if lo, _, ok := jsonRange(m["scMaxEachPostBytes"]); ok {
		o.ScMaxEachPostBytes = lo
	}
	if lo, _, ok := jsonRange(m["scMinPostsIntervalMs"]); ok {
		o.ScMinPostsIntervalMs = lo
	}
	if h, ok := m["headers"].(map[string]any); ok {
		if cfg.WS.Headers == nil {
			cfg.WS.Headers = map[string]string{}
		}
		for k, v := range h {
			if sv, ok := v.(string); ok {
				cfg.WS.Headers[k] = sv
			}
		}
	}
	if ds, ok := m["downloadSettings"].(map[string]any); ok {
		dl, err := parseXHTTPDownload(ds)
		if err != nil {
			return err
		}
		o.Download = dl
	}
	cfg.XHTTP = o
	return nil
}

// jsonRange reads a number, a "lo-hi" string or a {"from":..,"to":..} object.
func jsonRange(v any) (lo, hi int, ok bool) {
	switch t := v.(type) {
	case float64:
		return int(t), int(t), true
	case string:
		a, b, _ := strings.Cut(strings.TrimSpace(t), "-")
		l, err := strconv.Atoi(a)
		if err != nil {
			return 0, 0, false
		}
		h := l
		if b != "" {
			if h, err = strconv.Atoi(b); err != nil {
				return 0, 0, false
			}
		}
		return l, h, true
	case map[string]any:
		f, ok1 := t["from"].(float64)
		to, ok2 := t["to"].(float64)
		if ok1 && ok2 {
			return int(f), int(to), true
		}
	}
	return 0, 0, false
}

func parseXHTTPDownload(ds map[string]any) (*XHTTPDownloadConfig, error) {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	if n := strings.ToLower(str(ds, "network")); n != "" && n != "xhttp" && n != "splithttp" {
		return nil, fmt.Errorf("link: xhttp downloadSettings network %q is not supported (only xhttp)", n)
	}
	dl := &XHTTPDownloadConfig{Server: str(ds, "address")}
	if p, ok := ds["port"].(float64); ok {
		dl.Port = int(p)
	}
	switch sec := strings.ToLower(str(ds, "security")); sec {
	case "tls":
		dl.TLS.Enabled = true
		if t, ok := ds["tlsSettings"].(map[string]any); ok {
			dl.TLS.SNI = str(t, "serverName")
			dl.TLS.Fingerprint = str(t, "fingerprint")
			if b, ok := t["allowInsecure"].(bool); ok {
				dl.TLS.AllowInsecure = b
			}
			if a, ok := t["alpn"].([]any); ok {
				for _, x := range a {
					if xs, ok := x.(string); ok {
						dl.TLS.ALPN = append(dl.TLS.ALPN, xs)
					}
				}
			}
		}
	case "reality":
		r, _ := ds["realitySettings"].(map[string]any)
		if str(r, "publicKey") == "" {
			return nil, errors.New("link: xhttp downloadSettings reality has no publicKey")
		}
		dl.Reality = &RealityConfig{PublicKey: str(r, "publicKey"), ShortID: str(r, "shortId"),
			ServerName: str(r, "serverName"), Fingerprint: str(r, "fingerprint")}
	case "", "none":
	default:
		return nil, fmt.Errorf("link: xhttp downloadSettings: unknown security %q", sec)
	}
	if x, ok := ds["xhttpSettings"].(map[string]any); ok {
		dl.Host, dl.Path = str(x, "host"), str(x, "path")
		hdrs, _ := x["headers"].(map[string]any)
		if e, ok := x["extra"].(map[string]any); ok && hdrs == nil {
			hdrs, _ = e["headers"].(map[string]any)
		}
		for k, v := range hdrs {
			if sv, ok := v.(string); ok {
				if dl.Headers == nil {
					dl.Headers = map[string]string{}
				}
				dl.Headers[k] = sv
			}
		}
	}
	return dl, nil
}
