package payload

import (
	"strings"
	"testing"
)

func renderCompat(t *testing.T, tpl string, c Context) string {
	t.Helper()
	tp, err := CompileCompat(tpl)
	if err != nil {
		t.Fatalf("%q: %v", tpl, err)
	}
	var b strings.Builder
	for _, s := range tp.Render(c) {
		b.Write(s.Data)
	}
	return b.String()
}

// @ssh-ws and @ssh-ws/tcp work with plain Compile and CompileCompat alike,
// and stay two different payloads (GET upgrade vs CONNECT upgrade).
func TestSSHWSPresetsDirect(t *testing.T) {
	c := Context{Host: "h.example", Port: 22}
	ws := render(t, "@ssh-ws", c)
	if !strings.HasPrefix(ws, "GET / HTTP/1.1\r\n") || !strings.Contains(ws, "Upgrade: websocket\r\n") {
		t.Fatalf("@ssh-ws: %q", ws)
	}
	tcp := render(t, "@ssh-ws/tcp", c)
	if !strings.HasPrefix(tcp, "CONNECT h.example:22 HTTP/1.1\r\n") {
		t.Fatalf("@ssh-ws/tcp: %q", tcp)
	}
	if got := renderCompat(t, "@ssh-ws", c); got != ws {
		t.Errorf("CompileCompat(@ssh-ws) = %q, want %q", got, ws)
	}
	if got := renderCompat(t, " @SSH-WS/TCP ", c); got != tcp {
		t.Errorf("CompileCompat(@ssh-ws/tcp) = %q, want %q", got, tcp)
	}
}
