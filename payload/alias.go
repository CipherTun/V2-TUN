package payload

import (
	"regexp"
	"strings"
)

// SSHWebSocket is the classic "SSH over WebSocket" payload of HTTP-injector
// apps: an HTTP upgrade request, sent in clear text (no TLS needed). The
// server answers "101 Switching Protocols" and then carries the raw SSH
// stream. Put the bug host in the config's host field, or write your own.
const SSHWebSocket = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"

var (
	aliasSSH     = regexp.MustCompile(`(?i)\[ssh\]`)
	aliasRealRaw = regexp.MustCompile(`(?i)\[real_raw\]`)
)

// CompileCompat is Compile plus a few HTTP Injector spellings: [ssh] is
// [host_port], [real_raw] is [raw], and the preset "@ssh-ws" is SSHWebSocket.
func CompileCompat(tpl string) (*Template, error) {
	if strings.EqualFold(strings.TrimSpace(tpl), "@ssh-ws") {
		tpl = SSHWebSocket
	}
	tpl = aliasSSH.ReplaceAllString(tpl, "[host_port]")
	tpl = aliasRealRaw.ReplaceAllString(tpl, "[raw]")
	return Compile(tpl)
}
