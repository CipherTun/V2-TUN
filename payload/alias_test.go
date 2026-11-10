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

func TestCompatAliases(t *testing.T) {
	c := Context{Host: "h.example", Port: 22}
	if got := renderCompat(t, "CONNECT [ssh] HTTP/1.1", c); got != "CONNECT h.example:22 HTTP/1.1" {
		t.Errorf("[ssh]: %q", got)
	}
	if got := renderCompat(t, "[real_raw]", c); got != "CONNECT h.example:22 HTTP/1.1" {
		t.Errorf("[real_raw]: %q", got)
	}
	if got := renderCompat(t, "Sec-WebSocket-Key: [b64=random16]", c); len(got) != len("Sec-WebSocket-Key: ")+24 {
		t.Errorf("[b64=random16]: %q", got)
	}
	if _, err := CompileCompat("@ssh-ws"); err == nil {
		t.Error("CompileCompat must reject a preset name too")
	}
}

// [ssh] is the SSH server, never the bug host that [host] and [host_port] carry.
func TestCompatSSHIsTheRealServer(t *testing.T) {
	c := Context{Host: "bug.example", Port: 22, Server: "ssh.example", ServerPort: 22}
	if got := renderCompat(t, "CONNECT [ssh] HTTP/1.1", c); got != "CONNECT ssh.example:22 HTTP/1.1" {
		t.Errorf("[ssh] with a bug host: %q", got)
	}
	if got := renderCompat(t, "CONNECT [host_port] HTTP/1.1", c); got != "CONNECT bug.example:22 HTTP/1.1" {
		t.Errorf("[host_port] with a bug host: %q", got)
	}
}
