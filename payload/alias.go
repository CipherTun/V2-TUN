package payload

import (
	"regexp"
	"strings"
)

// SSHWebSocket is the classic "SSH over WebSocket" payload of HTTP-injector
// apps: an HTTP upgrade request, sent in clear text (no TLS needed). The
// server answers "101 Switching Protocols" and then carries the raw SSH
// stream. Put the bug host in the config's host field, or write your own.
// It is also registered as the preset "@ssh-ws" (see presets_extra.go).
const SSHWebSocket = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"

var (
	aliasSSH     = regexp.MustCompile(`(?i)\[ssh\]`)
	aliasRealRaw = regexp.MustCompile(`(?i)\[real_raw\]`)
	aliasRand16  = regexp.MustCompile(`(?i)\[b64=random16\]`)
)

// CompileCompat is Compile plus a few HTTP Injector spellings: [ssh] is
// [host_port], [real_raw] is [raw] and [b64=random16] is [ws_key] (base64 of
// 16 random bytes, a Sec-WebSocket-Key). Presets such as "@ssh-ws" and
// "@ssh-ws/tcp" are handled by Compile itself.
func CompileCompat(tpl string) (*Template, error) {
	if strings.HasPrefix(strings.TrimSpace(tpl), "@") {
		return Compile(tpl) // a preset name: no tags to rewrite
	}
	tpl = aliasSSH.ReplaceAllString(tpl, "[host_port]")
	tpl = aliasRealRaw.ReplaceAllString(tpl, "[raw]")
	tpl = aliasRand16.ReplaceAllString(tpl, "[ws_key]")
	return Compile(tpl)
}
