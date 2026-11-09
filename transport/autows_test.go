package transport

import (
	"io"
	"net"
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
	c := autoWebSocket(a)
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
	c := autoWebSocket(a)
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
	c := autoWebSocket(a)
	if time.Since(t0) < autoWSWait/2 {
		t.Fatal("must wait for the server before deciding")
	}
	go c.Write([]byte("x"))
	got := make([]byte, 1)
	if _, err := io.ReadFull(b, got); err != nil || got[0] != 'x' {
		t.Fatalf("silent server: %q %v", got, err)
	}
}
