package payload

import (
	"context"
	"strings"
	"testing"
	"time"
)

func render(t *testing.T, tpl string, c Context) string {
	t.Helper()
	tp, err := Compile(tpl)
	if err != nil {
		t.Fatalf("compile %q: %v", tpl, err)
	}
	var b strings.Builder
	for _, s := range tp.Render(c) {
		b.Write(s.Data)
	}
	return b.String()
}

func TestBasicTags(t *testing.T) {
	c := Context{Host: "example.com", Port: 443, SNI: "front.example"}
	cases := map[string]string{
		"A[crlf]B":                    "A\r\nB",
		"A[crlf*2]B":                  "A\r\n\r\nB",
		"[host]|[port]|[host_port]":   "example.com|443|example.com:443",
		"[sni]":                       "front.example",
		"[ip]":                        "example.com",
		"[method] [protocol]":         "GET HTTP/1.1",
		"[netData]":                   "CONNECT example.com:443 HTTP/1.1",
		"[raw][lf]":                   "CONNECT example.com:443 HTTP/1.1\n",
		"[get]|[post]|[connect]":      "GET|POST|CONNECT",
		"[HOST]":                      "example.com",
		"[tab][space][cr][lf][lfcr]x": "\t \r\n\n\rx",
		"[unknown=thing]":             "[unknown=thing]",
		`\[host\]`:                    "[host]",
		`a\r\nb\x41\\`:                "a\r\nbA\\",
	}
	for tpl, want := range cases {
		if got := render(t, tpl, c); got != want {
			t.Errorf("%q: got %q, want %q", tpl, got, want)
		}
	}
}

func TestMethodOverridesNetData(t *testing.T) {
	got := render(t, "[netData]", Context{Host: "h", Port: 80, Method: "POST"})
	if got != "POST h:80 HTTP/1.1" {
		t.Fatalf("got %q", got)
	}
}

func TestNestedTags(t *testing.T) {
	got := render(t, "[b64=[host]:[port]]", Context{Host: "h", Port: 443})
	if got != "aDo0NDM=" {
		t.Fatalf("got %q", got)
	}
	got = render(t, "[upper=[lower=ABC]]", Context{})
	if got != "ABC" {
		t.Fatalf("got %q", got)
	}
	got = render(t, "[basic=u:p]", Context{})
	if got != "Basic dTpw" {
		t.Fatalf("got %q", got)
	}
	got = render(t, "[hex=AB]", Context{})
	if got != "4142" {
		t.Fatalf("got %q", got)
	}
}

func TestRepeat(t *testing.T) {
	if got := render(t, "[repeat=3]ab[/repeat]", Context{}); got != "ababab" {
		t.Fatalf("got %q", got)
	}
	if got := render(t, "[repeat=2]a[repeat=2]b[/repeat][/repeat]", Context{}); got != "abbabb" {
		t.Fatalf("got %q", got)
	}
}

func TestSplitAndDelay(t *testing.T) {
	tp, err := Compile("AB[split]CD[delay=250]EF[delay_split]GH[delay=1.5s]")
	if err != nil {
		t.Fatal(err)
	}
	segs := tp.Render(Context{})
	wantData := []string{"AB", "CD", "EF", "GH"}
	wantDelay := []time.Duration{0, 250 * time.Millisecond, time.Second, 1500 * time.Millisecond}
	if len(segs) != len(wantData) {
		t.Fatalf("got %d segments: %+v", len(segs), segs)
	}
	for i, s := range segs {
		if string(s.Data) != wantData[i] || s.Delay != wantDelay[i] {
			t.Errorf("segment %d: %q +%v, want %q +%v", i, s.Data, s.Delay, wantData[i], wantDelay[i])
		}
	}
}

func TestRandomAndRotate(t *testing.T) {
	tp, err := Compile("[rotate=a|b][rotate=a|b]")
	if err != nil {
		t.Fatal(err)
	}
	flat := func() string {
		var b strings.Builder
		for _, s := range tp.Render(Context{}) {
			b.Write(s.Data)
		}
		return b.String()
	}
	// every tag keeps its own counter
	if a, b := flat(), flat(); a != "aa" || b != "bb" {
		t.Fatalf("rotate: %q %q", a, b)
	}
	for i := 0; i < 50; i++ {
		if got := render(t, "[random=x|y|z]", Context{}); got != "x" && got != "y" && got != "z" {
			t.Fatalf("random: %q", got)
		}
	}
}

func TestGenerators(t *testing.T) {
	for i := 0; i < 50; i++ {
		got := render(t, "[rand_int=10-12]", Context{})
		if got != "10" && got != "11" && got != "12" {
			t.Fatalf("rand_int: %q", got)
		}
	}
	if got := render(t, "[rand_hex=8]", Context{}); len(got) != 8 {
		t.Fatalf("rand_hex: %q", got)
	}
	if got := render(t, "[rand_num=5]", Context{}); len(got) != 5 || strings.Trim(got, "0123456789") != "" {
		t.Fatalf("rand_num: %q", got)
	}
	if got := render(t, "[uuid]", Context{}); len(got) != 36 || got[14] != '4' {
		t.Fatalf("uuid: %q", got)
	}
	if got := render(t, "[ws_key]", Context{}); len(got) != 24 {
		t.Fatalf("ws_key: %q", got)
	}
	if got := render(t, "[timestamp]", Context{}); len(got) != 10 {
		t.Fatalf("timestamp: %q", got)
	}
	if got := render(t, "[date]", Context{}); !strings.HasSuffix(got, " GMT") {
		t.Fatalf("date: %q", got)
	}
	if got := render(t, "[rand_ua]", Context{}); !strings.Contains(got, "/") {
		t.Fatalf("rand_ua: %q", got)
	}
}

func TestBytesAndVars(t *testing.T) {
	if got := render(t, "[bytes=48 49,0x21]", Context{}); got != "HI!" {
		t.Fatalf("bytes: %q", got)
	}
	got := render(t, "[var=token]-[var=missing]", Context{Vars: map[string]string{"token": "abc"}})
	if got != "abc-" {
		t.Fatalf("vars: %q", got)
	}
}

func TestPresets(t *testing.T) {
	got := render(t, "@websocket", Context{Host: "h.example", Port: 80})
	if !strings.Contains(got, "Upgrade: websocket\r\n") || !strings.Contains(got, "Host: h.example\r\n") ||
		!strings.HasSuffix(got, "\r\n\r\n") {
		t.Fatalf("got %q", got)
	}
	for _, name := range PresetNames() {
		if _, err := Compile(name); err != nil {
			t.Errorf("preset %s: %v", name, err)
		}
	}
}

func TestErrors(t *testing.T) {
	for _, tpl := range []string{"[host", "[repeat=2]x", "[repeat=x]y[/repeat]", "[repeat=5000]y[/repeat]",
		"[delay=abc]", "[rand_int=a-b]", "[rand_hex=-1]", "[bytes=zz]", "[crlf*500]"} {
		if _, err := Compile(tpl); err == nil {
			t.Errorf("%q: expected an error", tpl)
		}
	}
}

func TestExpansionLimit(t *testing.T) {
	if _, err := Compile("[repeat=1000][repeat=1000]x[/repeat][/repeat]"); err == nil {
		t.Fatal("runaway expansion must be rejected")
	}
}

func TestDescribe(t *testing.T) {
	tp, _ := Compile("GET /[crlf][split]Host: x[crlf][delay=100]")
	out := tp.Preview(Context{})
	if !strings.Contains(out, "\\r\\n") || !strings.Contains(out, "--- split ---") || !strings.Contains(out, "--- wait 100ms ---") {
		t.Fatalf("preview:\n%s", out)
	}
}

func TestSendContextStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var b strings.Builder
	if err := SendContext(ctx, &b, []Segment{{Data: []byte("x")}}); err == nil || b.Len() != 0 {
		t.Fatalf("err=%v wrote=%q", err, b.String())
	}
}

func TestReadHTTPHeaders(t *testing.T) {
	r := strings.NewReader("HTTP/1.1 200 Connection established\r\nX: y\r\n\r\nTUNNEL")
	code, err := ReadHTTPHeaders(r)
	if err != nil || code != 200 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	rest := make([]byte, 6)
	if n, _ := r.Read(rest); string(rest[:n]) != "TUNNEL" {
		t.Fatalf("tunnel data was swallowed: %q", rest[:n])
	}
}
