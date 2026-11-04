package payload

import "testing"

func TestRender(t *testing.T) {
	tpl, err := Compile("CONNECT [host_port] [protocol][crlf]Host: [host][crlf][crlf][split][delay=10]GET / HTTP/1.1[crlf]")
	if err != nil {
		t.Fatal(err)
	}
	segs := tpl.Render(Context{Host: "bug.example", Port: 443})
	if len(segs) != 3 {
		t.Fatalf("segments=%d", len(segs))
	}
	if string(segs[0].Data) != "CONNECT bug.example:443 HTTP/1.1\r\nHost: bug.example\r\n\r\n" {
		t.Fatalf("%q", segs[0].Data)
	}
}
