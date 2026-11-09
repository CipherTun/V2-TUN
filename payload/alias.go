package payload

import "regexp"

var (
	aliasSSH     = regexp.MustCompile(`(?i)\[ssh\]`)
	aliasRealRaw = regexp.MustCompile(`(?i)\[real_raw\]`)
	aliasRand16  = regexp.MustCompile(`(?i)\[b64=random16\]`)
)

// CompileCompat is Compile plus a few HTTP Injector spellings: [ssh] is
// [host_port], [real_raw] is [raw] and [b64=random16] is [ws_key] (base64 of
// 16 random bytes, a Sec-WebSocket-Key).
func CompileCompat(tpl string) (*Template, error) {
	tpl = aliasSSH.ReplaceAllString(tpl, "[host_port]")
	tpl = aliasRealRaw.ReplaceAllString(tpl, "[raw]")
	tpl = aliasRand16.ReplaceAllString(tpl, "[ws_key]")
	return Compile(tpl)
}
