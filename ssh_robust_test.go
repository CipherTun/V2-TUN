package v2tun

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// A server that answers with an error status and then tunnels anyway starts
// the tunnel when that status is listed in acceptStatus.
func TestPayloadAcceptStatusListed(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		pxSocks5(c, "", "")
	})
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p,
		Payload: &PayloadConfig{Template: sshWSPayload, AcceptStatus: []int{403}}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
}

// A status outside 100 to 599 is a typo, not a status: refused when the
// config is built.
func TestPayloadAcceptStatusOutOfRange(t *testing.T) {
	for _, code := range []int{0, 99, 600, -1} {
		if _, err := New(&Config{Protocol: "socks5", Server: "example.com", Port: 80,
			Payload: &PayloadConfig{Template: sshWSPayload, AcceptStatus: []int{code}}}); err == nil {
			t.Errorf("acceptStatus %d must be rejected", code)
		}
	}
}

// A reply that carries a short body: the body is dropped before the protocol
// starts, so it is not read as the protocol's first bytes.
func TestPayloadReplyBodySkipped(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
		pxSocks5(c, "", "")
	})
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p,
		Payload: &PayloadConfig{Template: sshWSPayload}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
}

// The reply to a CONNECT request has no body whatever its Content-Length says:
// the tunnel data follows the headers directly and must not be swallowed.
func TestPayloadReplyBodyNotSkippedForConnect(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"))
		pxSocks5(c, "", "")
	})
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p,
		Payload: &PayloadConfig{Template: connectPayload}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
}

// After the server rejects the login, the next dials do not hit it again for a
// while (a flow-per-connection retry would trip fail2ban). The test server
// accepts one connection only, so a second login attempt would fail with a
// connection error instead of the pause message.
func TestSSHLoginPausedAfterRejection(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte(ws101))
		pxSSHServer(c)
	})
	cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "wrong",
		Payload: &PayloadConfig{Template: sshWSPayload, Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cl.DialContext(ctx, "tcp", "target.example:80"); err == nil {
		t.Fatal("a wrong password must fail")
	}
	_, err = cl.DialContext(ctx, "tcp", "target.example:80")
	if err == nil || !strings.Contains(err.Error(), "not trying again") {
		t.Fatalf("second dial: want the login pause, got %v", err)
	}
}
