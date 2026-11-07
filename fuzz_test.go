package v2tun

import "testing"

// Fuzz targets for the parsers that read untrusted text. A plain `go test`
// runs only the seeds; `go test -fuzz=FuzzParseLink` explores further.

func FuzzParseLink(f *testing.F) {
	for _, s := range []string{
		"vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=a.b&host=c.d&path=%2Fws#n",
		"vmess://eyJ2IjoiMiIsInBzIjoieCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsIm5ldCI6IndzIn0=",
		"trojan://secret@example.com:443?security=tls#t",
		"ss://YWVzLTI1Ni1nY206cHc@example.com:8388#s",
		"ssh://user:pw@example.com:22#s",
		"socks5://u:p@example.com:1080#s",
		"http://u:p@example.com:8080#h",
		"hysteria2://secret@example.com:443/?sni=a.b&insecure=1&obfs=salamander&obfs-password=pw#h",
		"hysteria://example.com:443?auth=abc&peer=a.b&upmbps=10&downmbps=50#h",
		"", "://", "vless://", "ss://@:", "hy2://%zz",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ParseLink(s) // must not panic, whatever it returns
	})
}
