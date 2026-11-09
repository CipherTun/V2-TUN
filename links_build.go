package v2tun

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// BuildLink is the inverse of ParseLink: it turns a config into a share link
// that other clients (v2rayNG, Hiddify, ...) can import, plus the display name
// in the link's fragment. vless://, vmess://, trojan://, ss://, socks5://,
// socks4://, http:// and https:// are supported.
//
// A config that a link cannot express is an error, never a link that drops
// part of it: a payload, xhttp options, extra WebSocket headers, SSH and the
// Hysteria family have no standard link form.
func BuildLink(cfg *Config, name string) (string, error) {
	if cfg == nil {
		return "", errors.New("link: no config")
	}
	proto := strings.ToLower(cfg.Protocol)
	switch proto {
	case "vless", "vmess", "trojan", "shadowsocks", "ss", "socks5", "socks4", "http", "https":
	default:
		return "", fmt.Errorf("link: %s has no standard share link", cfg.Protocol)
	}
	if cfg.Payload != nil {
		return "", errors.New("link: a payload cannot be written into a share link")
	}
	if cfg.XHTTP != nil {
		return "", errors.New("link: xhttp options cannot be written into a share link")
	}
	if len(cfg.WS.Headers) > 0 {
		return "", errors.New("link: extra WebSocket headers cannot be written into a share link")
	}
	host := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))

	switch proto {
	case "vless":
		q := linkQuery(cfg)
		q.Set("encryption", "none")
		if cfg.Flow != "" {
			q.Set("flow", cfg.Flow)
		}
		u := url.URL{Scheme: "vless", User: url.User(cfg.UUID), Host: host, RawQuery: q.Encode(), Fragment: name}
		return u.String(), nil

	case "trojan":
		u := url.URL{Scheme: "trojan", User: url.User(cfg.Password), Host: host, RawQuery: linkQuery(cfg).Encode(), Fragment: name}
		return u.String(), nil

	case "vmess":
		if cfg.Reality != nil {
			return "", errors.New("link: vmess links cannot carry REALITY")
		}
		netw := cfg.Network
		if netw == "" {
			netw = "tcp"
		}
		scy := cfg.Method
		if scy == "" {
			scy = "auto"
		}
		m := map[string]any{
			"v": "2", "ps": name, "add": cfg.Server, "port": strconv.Itoa(cfg.Port),
			"id": cfg.UUID, "aid": strconv.Itoa(cfg.AlterID), "scy": scy, "net": netw, "type": "none",
			"host": cfg.WS.Host, "path": cfg.WS.Path, "tls": "",
			"sni": cfg.TLS.SNI, "alpn": strings.Join(cfg.TLS.ALPN, ","), "fp": cfg.TLS.Fingerprint,
		}
		if cfg.TLS.Enabled {
			m["tls"] = "tls"
		}
		if cfg.TLS.AllowInsecure {
			m["allowInsecure"] = "1"
		}
		if cfg.Network == "grpc" {
			m["path"] = cfg.GRPCService
			if cfg.GRPCMulti {
				m["type"] = "multi"
			}
		}
		b, err := json.Marshal(m)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil

	case "shadowsocks", "ss":
		if cfg.Network != "" || cfg.TLS.Enabled || cfg.Reality != nil {
			return "", errors.New("link: a shadowsocks link cannot carry a transport or TLS")
		}
		ui := base64.RawURLEncoding.EncodeToString([]byte(cfg.Method + ":" + cfg.Password))
		s := "ss://" + ui + "@" + host
		if name != "" {
			s += "#" + url.QueryEscape(name)
		}
		return s, nil

	default: // socks5, socks4, http, https
		u := url.URL{Scheme: proto, Host: host, Fragment: name}
		if cfg.Username != "" || cfg.Password != "" {
			u.User = url.UserPassword(cfg.Username, cfg.Password)
		}
		if proto == "http" || proto == "https" {
			u.RawQuery = linkQuery(cfg).Encode()
		}
		return u.String(), nil
	}
}

// linkQuery writes the transport and security parts of a config the way
// applyQuery reads them.
func linkQuery(cfg *Config) url.Values {
	q := url.Values{}
	netw := cfg.Network
	if netw == "" {
		netw = "tcp"
	}
	q.Set("type", netw)
	switch {
	case cfg.Reality != nil:
		q.Set("security", "reality")
		q.Set("pbk", cfg.Reality.PublicKey)
		if cfg.Reality.ShortID != "" {
			q.Set("sid", cfg.Reality.ShortID)
		}
		sni := cfg.Reality.ServerName
		if sni == "" {
			sni = cfg.TLS.SNI
		}
		if sni != "" {
			q.Set("sni", sni)
		}
		fp := cfg.Reality.Fingerprint
		if fp == "" {
			fp = cfg.TLS.Fingerprint
		}
		if fp != "" {
			q.Set("fp", fp)
		}
	case cfg.TLS.Enabled:
		q.Set("security", "tls")
		if cfg.TLS.SNI != "" {
			q.Set("sni", cfg.TLS.SNI)
		}
		if cfg.TLS.Fingerprint != "" {
			q.Set("fp", cfg.TLS.Fingerprint)
		}
		if len(cfg.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(cfg.TLS.ALPN, ","))
		}
		if cfg.TLS.AllowInsecure {
			q.Set("allowInsecure", "1")
		}
	default:
		q.Set("security", "none")
	}
	if cfg.WS.Host != "" {
		q.Set("host", cfg.WS.Host)
	}
	if cfg.WS.Path != "" {
		q.Set("path", cfg.WS.Path)
	}
	if cfg.XHTTPMode != "" {
		q.Set("mode", cfg.XHTTPMode)
	}
	if cfg.GRPCService != "" {
		q.Set("serviceName", cfg.GRPCService)
	}
	if cfg.Network == "grpc" && cfg.GRPCMulti {
		q.Set("mode", "multi")
	}
	return q
}
