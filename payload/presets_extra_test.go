package payload

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestExtraPresets(t *testing.T) {
	c := Context{Host: "h.example", Port: 22}
	got := render(t, "@ssh-ws/tcp", c)
	for _, want := range []string{
		"CONNECT h.example:22 HTTP/1.1\r\n",
		"Host: h.example\r\n",
		"Upgrade: websocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Version: 13\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("@ssh-ws/tcp is missing %q: %q", want, got)
		}
	}
	if !strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("@ssh-ws/tcp must end with an empty line: %q", got)
	}
	if udp := render(t, "@ssh-ws/udp", c); udp != got {
		t.Errorf("@ssh-ws/udp differs from @ssh-ws/tcp: %q", udp)
	}

	if got := render(t, "@get-proxy", Context{Host: "h.example", Port: 80}); !strings.HasPrefix(got, "GET http://h.example/ HTTP/1.1\r\n") {
		t.Errorf("@get-proxy: %q", got)
	}
	if got := render(t, "@head-proxy", Context{Host: "h.example", Port: 80}); !strings.HasPrefix(got, "HEAD http://h.example/ HTTP/1.1\r\n") {
		t.Errorf("@head-proxy: %q", got)
	}
	if got := render(t, "@post-proxy", Context{Host: "h.example", Port: 80}); !strings.Contains(got, "Content-Length: 0\r\n") {
		t.Errorf("@post-proxy: %q", got)
	}
}

func TestExtraPresetsKeepBuiltIns(t *testing.T) {
	// the built-in presets must not be replaced by the extra ones
	if got := render(t, "@get", Context{Host: "h", Port: 80}); !strings.HasPrefix(got, "GET / HTTP/1.1\r\n") {
		t.Errorf("@get changed: %q", got)
	}
	found := map[string]bool{}
	for _, n := range PresetNames() {
		found[n] = true
	}
	for _, n := range []string{"@connect", "@get", "@head", "@post", "@websocket", "@split-connect",
		"@ssh-ws/tcp", "@ssh-ws/udp", "@get-proxy", "@head-proxy", "@post-proxy"} {
		if !found[n] {
			t.Errorf("preset %s is not listed", n)
		}
	}
}

func TestCompatRandom16(t *testing.T) {
	tp, err := CompileCompat("Sec-WebSocket-Key: [b64=random16]")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, s := range tp.Render(Context{}) {
		b.Write(s.Data)
	}
	key := strings.TrimPrefix(b.String(), "Sec-WebSocket-Key: ")
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 16 {
		t.Fatalf("[b64=random16] must be base64 of 16 random bytes, got %q", key)
	}
}
