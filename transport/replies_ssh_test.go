package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"io.surprise.vpn/payload"
)

type pipeDialer struct{ c net.Conn }

func (p pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) { return p.c, nil }

// dialPayload runs a Payload dial against a server that writes reply after it
// has read the whole payload, and returns what the client conn then yields.
func dialPayload(t *testing.T, tpl, reply string, mod func(*Payload)) (string, error) {
	t.Helper()
	cl, sv := net.Pipe()
	go func() {
		defer sv.Close()
		buf := make([]byte, 4096)
		sv.SetReadDeadline(time.Now().Add(2 * time.Second))
		sv.Read(buf) // the payload
		sv.Write([]byte(reply))
		time.Sleep(100 * time.Millisecond)
	}()
	tp, err := payload.Compile(tpl)
	if err != nil {
		t.Fatal(err)
	}
	d := &Payload{Inner: pipeDialer{cl}, Template: tp, ExpectResponse: true, SkipBody: true}
	if mod != nil {
		mod(d)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "example.com:22")
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	b, _ := io.ReadAll(c)
	return string(b), nil
}

const twoLines = "CONNECT example.com:22 HTTP/1.1[crlf][crlf]GET / HTTP/1.1[crlf]Host: x[crlf][crlf]"

// A front that answers only the first of two request lines, then carries the
// SSH stream: the banner must not be read as the second reply.
func TestRepliesStopAtSSHBanner(t *testing.T) {
	got, err := dialPayload(t, twoLines, "HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("stream = %q", got)
	}
}

// A server that answers none of the lines and starts the SSH stream.
func TestRepliesNoneBeforeBanner(t *testing.T) {
	got, err := dialPayload(t, twoLines, "SSH-2.0-dropbear\r\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SSH-2.0-dropbear\r\n" {
		t.Fatalf("stream = %q", got)
	}
}

// Both replies present: unchanged behaviour, the banner after them survives.
func TestRepliesBothThenBanner(t *testing.T) {
	got, err := dialPayload(t, twoLines,
		"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nSSH-2.0-x\r\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SSH-2.0-x\r\n" {
		t.Fatalf("stream = %q", got)
	}
}

// An error status is still refused.
func TestRepliesRejectErrorStatus(t *testing.T) {
	if _, err := dialPayload(t, twoLines, "HTTP/1.1 403 Forbidden\r\n\r\n", nil); err == nil {
		t.Fatal("a 403 reply must fail the dial")
	}
}

// With AutoWS and an upgrade payload that gets no reply, the plain SSH stream
// is detected and passed through.
func TestRepliesBannerWithAutoWS(t *testing.T) {
	got, err := dialPayload(t, "GET / HTTP/1.1[crlf]Host: x[crlf]Upgrade: websocket[crlf][crlf]",
		"SSH-2.0-OpenSSH_9.6\r\n", func(p *Payload) { p.AutoWS = true })
	if err != nil {
		t.Fatal(err)
	}
	if got != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Fatalf("stream = %q", got)
	}
}
