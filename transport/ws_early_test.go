package transport

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"testing"
)

type edTestDialer struct{}

func (edTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// edServer accepts one WebSocket client, reports the Sec-WebSocket-Protocol
// header it saw and the payload of the first masked data frame, then answers
// with an unmasked "pong" frame.
func edServer(t *testing.T) (addr string, protocol <-chan string, frame <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pc, fc := make(chan string, 1), make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		pc <- req.Header.Get("Sec-WebSocket-Protocol")
		sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID))
		c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"))
		var h [2]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			fc <- ""
			return
		}
		n := int(h[1] & 0x7f)
		var mask [4]byte
		io.ReadFull(br, mask[:])
		pl := make([]byte, n)
		io.ReadFull(br, pl)
		for i := range pl {
			pl[i] ^= mask[i%4]
		}
		fc <- string(pl)
		c.Write(append([]byte{0x82, 4}, "pong"...))
		io.Copy(io.Discard, br)
	}()
	return ln.Addr().String(), pc, fc
}

func TestWebSocketEarlyDataSplitsFirstWrite(t *testing.T) {
	addr, proto, frame := edServer(t)
	d := &WebSocket{Inner: edTestDialer{}, Host: "example.test", Path: "/x", MaxEarlyData: 5}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if n, err := c.Write([]byte("helloworld")); err != nil || n != 10 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	got, err := base64.RawURLEncoding.DecodeString(<-proto)
	if err != nil || string(got) != "hello" {
		t.Fatalf("early data = %q, %v; want hello", got, err)
	}
	if f := <-frame; f != "world" {
		t.Fatalf("first frame = %q; want the rest of the write", f)
	}
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
}

func TestWebSocketEarlyDataShortWriteHasNoFrame(t *testing.T) {
	addr, proto, _ := edServer(t)
	d := &WebSocket{Inner: edTestDialer{}, Path: "/", MaxEarlyData: 2048}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if got, _ := base64.RawURLEncoding.DecodeString(<-proto); string(got) != "abc" {
		t.Fatalf("early data = %q; want abc", got)
	}
}

func TestWebSocketReadFirstUpgradesWithoutEarlyData(t *testing.T) {
	addr, proto, frame := edServer(t)
	d := &WebSocket{Inner: edTestDialer{}, Path: "/", MaxEarlyData: 16}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		// The server sees the upgrade from the Read below, with no early
		// data; it answers only after a frame, so send one then.
		if p := <-proto; p != "" {
			t.Errorf("Sec-WebSocket-Protocol = %q; a Read first must not carry early data", p)
		}
		c.Write([]byte("late"))
	}()
	buf := make([]byte, 8)
	if n, err := c.Read(buf); err != nil || string(buf[:n]) != "pong" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	if f := <-frame; f != "late" {
		t.Fatalf("frame = %q; want late", f)
	}
}
