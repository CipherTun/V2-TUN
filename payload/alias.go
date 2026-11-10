package payload

import "regexp"

var (
	aliasSSH     = regexp.MustCompile(`(?i)\[ssh\]`)
	aliasRealRaw = regexp.MustCompile(`(?i)\[real_raw\]`)
	aliasRand16  = regexp.MustCompile(`(?i)\[b64=random16\]`)
)

// CompileCompat is Compile plus a few HTTP Injector spellings: [ssh] is
// [server_host_port], [real_raw] is [raw] and [b64=random16] is [ws_key]
// (base64 of 16 random bytes, a Sec-WebSocket-Key).
//
// HTTP Injector documents [ssh] as the SSH server's address and port as set in
// the app settings. That is the real server, not the bug host, so it maps to
// [server_host_port]; [host_port] would name the bug host once one is set.
func CompileCompat(tpl string) (*Template, error) {
	tpl = aliasSSH.ReplaceAllString(tpl, "[server_host_port]")
	tpl = aliasRealRaw.ReplaceAllString(tpl, "[raw]")
	tpl = aliasRand16.ReplaceAllString(tpl, "[ws_key]")
	return Compile(tpl)
}
