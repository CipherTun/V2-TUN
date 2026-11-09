package transport

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"io.surprise.vpn/payload"
)

func TestWantsWebSocket(t *testing.T) {
	seg := func(s string) []payload.Segment { return []payload.Segment{{Data: []byte(s)}} }
	if !wantsWebSocket(seg("GET /ws HTTP/1.1\r\nHost: x\r\nUPGRADE: WebSocket\r\n\r\n")) {
		t.Error("an upgrade request must be recognised in any letter case")
	}
	if wantsWebSocket(seg("CONNECT h:22 HTTP/1.1\r\n\r\n")) {
		t.Error("a plain CONNECT is not a websocket upgrade")
	}
}

// A plain tunnel starts with the SSH banner and must be passed through as is.
func TestAutoWebSocketPlain(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go b.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	c := autoWebSocket(a, false)
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("plain read: %q %v", buf[:n], err)
	}
	go func() { c.Write([]byte("SSH-2.0-client\r\n")) }()
	got := make([]byte, 16)
	if _, err := io.ReadFull(b, got); err != nil || string(got) != "SSH-2.0-client\r\n" {
		t.Fatalf("plain write must not be framed: %q %v", got, err)
	}
}

// A framed tunnel starts with an unmasked server frame; reads are unwrapped
// and writes leave as masked binary frames.
func TestAutoWebSocketFramed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	banner := "SSH-2.0-OpenSSH_9.6\r\n"
	go b.Write(append([]byte{0x82, byte(len(banner))}, banner...))
	c := autoWebSocket(a, false)
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != banner {
		t.Fatalf("framed read: %q %v", buf[:n], err)
	}
	go func() { c.Write([]byte("hi")) }()
	h := make([]byte, 2+4+2)
	if _, err := io.ReadFull(b, h); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x82 || h[1] != 0x80|2 {
		t.Fatalf("write must be a masked binary frame, got % x", h)
	}
	mask := h[2:6]
	if string([]byte{h[6] ^ mask[0], h[7] ^ mask[1]}) != "hi" {
		t.Fatalf("frame payload wrong: % x", h)
	}
}

// A server that says nothing is taken to be a plain tunnel.
func TestAutoWebSocketSilentIsPlain(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	t0 := time.Now()
	c := autoWebSocket(a, false)
	if time.Since(t0) < autoWSWait/2 {
		t.Fatal("must wait for the server before deciding")
	}
	go c.Write([]byte("x"))
	got := make([]byte, 1)
	if _, err := io.ReadFull(b, got); err != nil || got[0] != 'x' {
		t.Fatalf("silent server: %q %v", got, err)
	}
}

// A silent server whose reply was a real WebSocket handshake (it carried
// Sec-WebSocket-Accept) is taken to be framed: writes leave as masked frames.
func TestAutoWebSocketSilentAcceptedIsFramed(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := autoWebSocket(a, true)
	go c.Write([]byte("hi"))
	h := make([]byte, 2+4+2)
	if _, err := io.ReadFull(b, h); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x82 || h[1] != 0x80|2 {
		t.Fatalf("a silent server after a real handshake must get masked frames, got % x", h)
	}
}

func joinSegs(segs []payload.Segment) string {
	var s string
	for _, g := range segs {
		s += string(g.Data)
	}
	return s
}

func TestWithWebSocketHeadersAddsMissing(t *testing.T) {
	in := "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"
	out := joinSegs(withWebSocketHeaders([]payload.Segment{{Data: []byte(in)}}))
	if !strings.HasPrefix(out, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n") || !strings.HasSuffix(out, "\r\n\r\n") {
		t.Fatalf("request line, headers and the blank line must stay in place: %q", out)
	}
	for _, want := range []string{"\r\nSec-WebSocket-Key: ", "\r\nSec-WebSocket-Version: 13\r\n", "\r\nConnection: Upgrade\r\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
	if strings.Count(out, "\r\n\r\n") != 1 {
		t.Errorf("exactly one blank line expected: %q", out)
	}
}

func TestWithWebSocketHeadersKeepsExisting(t *testing.T) {
	in := "GET /ws HTTP/1.1\r\nHost: x\r\nUPGRADE: WebSocket\r\nconnection: upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if out := joinSegs(withWebSocketHeaders([]payload.Segment{{Data: []byte(in)}})); out != in {
		t.Fatalf("a request that has the headers must not change: %q", out)
	}
}

// A payload split into segments, with a CONNECT and a decoy line in front: only
// the upgrade request gets headers, right before its blank line.
func TestWithWebSocketHeadersSplitAndDecoy(t *testing.T) {
	segs := []payload.Segment{
		{Data: []byte("CONNECT h:22 HTTP/1.1\r\n\r\nGET http://d.example/ HTTP/1.1\r\nHost: d\r\n\r\n")},
		{Data: []byte("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"), Delay: time.Millisecond},
		{Data: []byte("\r\n")},
	}
	out := joinSegs(withWebSocketHeaders(segs))
	head := "CONNECT h:22 HTTP/1.1\r\n\r\nGET http://d.example/ HTTP/1.1\r\nHost: d\r\n\r\nGET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
	if !strings.HasPrefix(out, head) || !strings.HasSuffix(out, "\r\n\r\n") {
		t.Fatalf("earlier requests must stay as they were: %q", out)
	}
	if strings.Count(out, "Sec-WebSocket-Key") != 1 || strings.Index(out, "Sec-WebSocket-Key") < len(head)-2 {
		t.Fatalf("headers belong to the upgrade request only: %q", out)
	}
	res := withWebSocketHeaders(segs)
	if res[1].Delay != time.Millisecond {
		t.Fatal("segments must keep their delay")
	}
	if joinSegs(segs) == out {
		t.Fatal("the input segments must stay untouched")
	}
}
