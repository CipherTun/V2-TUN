package proxy

import (
	"bytes"
	"net"
	"testing"

	"io.surprise.vpn/transport"
)

func visionFrame(uuid []byte, first bool, cmd byte, content []byte, pad int) []byte {
	var f []byte
	if first {
		f = append(f, uuid...)
	}
	f = append(f, cmd, byte(len(content)>>8), byte(len(content)), byte(pad>>8), byte(pad))
	f = append(f, content...)
	f = append(f, make([]byte, pad)...)
	return f
}

// The frame parser must survive any split of the byte stream.
func TestVisionUnpadAcrossReads(t *testing.T) {
	uuid := bytes.Repeat([]byte{7}, 16)
	c := newVisionConn(nil, uuid, nil)
	data := append(visionFrame(uuid, true, 0, []byte("hello"), 10), visionFrame(uuid, false, 1, []byte("world"), 3)...)
	data = append(data, []byte("plain")...)
	for i := 0; i < len(data); i += 3 {
		piece := data[i:min(i+3, len(data))]
		if c.rpad {
			c.unpad(piece)
		} else { // after the End frame Read bypasses the parser
			c.rout = append(c.rout, piece...)
		}
	}
	if got := string(c.rout); got != "helloworldplain" {
		t.Fatalf("got %q", got)
	}
	if c.rpad {
		t.Fatal("padding should have ended after cmd 1")
	}
}

func TestVisionWriteRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	uuid := bytes.Repeat([]byte{9}, 16)
	client := newVisionConn(a, uuid, nil)
	server := newVisionConn(b, uuid, nil)

	hello := append([]byte{0x16, 0x03, 0x01, 0, 0, 0x01}, bytes.Repeat([]byte{1}, 300)...)
	appData := append([]byte{0x17, 0x03, 0x03, 0, 0}, bytes.Repeat([]byte{2}, 50)...)
	plain := []byte("after padding")
	go func() {
		client.Write(hello)
		client.Write(appData)
		client.Write(plain)
	}()

	var want []byte
	want = append(want, hello...)
	want = append(want, appData...)
	want = append(want, plain...)
	var got []byte
	buf := make([]byte, 4096)
	for len(got) < len(want) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (got %d of %d bytes)", err, len(got), len(want))
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload corrupted by the Vision framing")
	}
	if client.wpad {
		t.Fatal("client should have stopped padding after the first application-data record")
	}
}

func TestVisionDirectSwitch(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	uuid := bytes.Repeat([]byte{3}, 16)
	rc := transport.NewRecordConn(a)
	c := newVisionConn(nil, uuid, rc)
	c.unpad(append(visionFrame(uuid, true, 2, []byte("tail"), 0), []byte("RAW")...))
	if !c.rdirect || c.rerr != nil {
		t.Fatalf("direct=%v err=%v", c.rdirect, c.rerr)
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "tailRAW" {
		t.Fatalf("got %q err=%v", buf[:n], err)
	}
	go b.Write([]byte("more")) // later bytes come straight from the socket
	n, err = c.Read(buf)
	if err != nil || string(buf[:n]) != "more" {
		t.Fatalf("got %q err=%v", buf[:n], err)
	}
}

func TestVisionDirectWithoutRecordConn(t *testing.T) {
	uuid := bytes.Repeat([]byte{3}, 16)
	c := newVisionConn(nil, uuid, nil)
	c.unpad(visionFrame(uuid, true, 2, []byte("x"), 0))
	if c.rerr == nil {
		t.Fatal("expected an error: the transport cannot follow a direct-copy switch")
	}
}
