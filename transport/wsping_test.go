package transport

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

func TestWSPingFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c := &wsConn{Conn: a, br: bufio.NewReader(a)}
	c.startPing(20 * time.Millisecond)

	_ = b.SetReadDeadline(time.Now().Add(3 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(b, head); err != nil {
		t.Fatal(err)
	}
	if head[0] != 0x89 || head[1] != 0x80|4 {
		t.Fatalf("want a masked ping with 4 bytes of payload (0x89 0x84), got % x", head)
	}
	rest := make([]byte, 8) // 4 mask bytes + 4 payload bytes
	if _, err := io.ReadFull(b, rest); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	for i := range payload {
		payload[i] = rest[4+i] ^ rest[i]
	}
	if string(payload) != "PING" {
		t.Fatalf("ping payload %q", payload)
	}
}
