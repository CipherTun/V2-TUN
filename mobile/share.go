package mobile

import v2tun "io.surprise.vpn"

// ShareLink turns a config into a share link (vless://, vmess://, trojan://,
// ss://, socks5://, socks4://, http://, https://) that other clients can
// import, with name as the display name. It returns an error, and no link,
// when the config has no standard link form (a payload, SSH, Hysteria, ...).
func ShareLink(configJSON, name string) (string, error) {
	cfg, err := decodeConfig(configJSON)
	if err != nil {
		return "", err
	}
	return v2tun.BuildLink(cfg, name)
}
