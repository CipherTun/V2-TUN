package v2tun

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// A link that is parsed, written back and parsed again must give the same config.
func TestBuildLinkRoundTrip(t *testing.T) {
	vm, _ := json.Marshal(map[string]string{
		"v": "2", "ps": "vm", "add": "example.com", "port": "443", "id": "11111111-2222-3333-4444-555555555555",
		"aid": "0", "scy": "auto", "net": "ws", "host": "example.com", "path": "/ws", "tls": "tls", "sni": "example.com",
	})
	links := []string{
		"vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=tls&sni=example.com&host=example.com&path=%2Fws#vl",
		"trojan://secret@example.com:443?type=tcp&security=tls&sni=example.com#tr",
		"vmess://" + base64.StdEncoding.EncodeToString(vm),
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@1.2.3.4:8388#ss",
		"socks5://user:pass@1.2.3.4:1080#sk",
	}
	for _, in := range links {
		c1, n1, err := ParseLink(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		out, err := BuildLink(c1, n1)
		if err != nil {
			t.Fatalf("build %q: %v", in, err)
		}
		c2, n2, err := ParseLink(out)
		if err != nil {
			t.Fatalf("parse built %q: %v", out, err)
		}
		j1, _ := json.Marshal(c1)
		j2, _ := json.Marshal(c2)
		if string(j1) != string(j2) || n1 != n2 {
			t.Errorf("round trip changed the config\n in:  %s\n out: %s\n 1: %s\n 2: %s", in, out, j1, j2)
		}
	}
}

func TestBuildLinkRefusesWhatALinkCannotHold(t *testing.T) {
	for _, in := range []string{"ssh://u:p@1.2.3.4:22#x"} {
		c, n, err := ParseLink(in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := BuildLink(c, n); err == nil {
			t.Errorf("expected an error for %q", in)
		}
	}
}
