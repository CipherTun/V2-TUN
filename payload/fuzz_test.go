package payload

import "testing"

// A plain `go test` runs only the seeds; `go test -fuzz=FuzzCompile` explores
// further. Neither compiling nor rendering a template may panic.
func FuzzCompile(f *testing.F) {
	for _, s := range []string{
		"CONNECT [host_port] [protocol][crlf]Host: [host][crlf][crlf]",
		"[split][delay=10]GET / HTTP/1.1[crlf][crlf]",
		"[repeat=3]x[/repeat]",
		"[random=a|b|c]",
		"[rotate=a|b]",
		"@connect",
		"@ssh-ws",
		"[var=token]",
		"[ssh][real_raw]",
		"[unclosed",
		"[repeat=2]no end",
		"[delay=notanumber]",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		tpl, err := CompileCompat(s)
		if err != nil {
			return
		}
		tpl.Render(Context{Host: "host.example", Port: 443})
	})
}
