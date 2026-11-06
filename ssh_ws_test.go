package v2tun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const ws101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

// SSH over WebSocket, the way HTTP-injector apps do it: no TLS, a plain
// upgrade request as the payload, a 101 reply that must not reach the
// protocol, then the raw stream.

func TestSSHWebSocketPayloadDirect(t *testing.T) {
	got := make(chan string, 1)
	h, p := pxServeOnce(t, func(c net.Conn) {
		hdr, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		got <- hdr
		c.Write([]byte(ws101))
		pxSocks5(c, "", "")
	})
	// socks5 stands in for ssh here: the payload layer does not care what follows
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p,
		Payload: &PayloadConfig{Template: "@ssh-ws", Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	hdr := <-got
	if !strings.HasPrefix(hdr, "GET / HTTP/1.1\r\n") || !strings.Contains(hdr, "Host: bug.example.com\r\n") ||
		!strings.Contains(hdr, "Upgrade: websocket\r\n") {
		t.Fatalf("payload: %q", hdr)
	}
}

func pxSSHServer(c net.Conn) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if m.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "direct-tcpip" {
			nc.Reject(ssh.UnknownChannelType, "not supported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(creqs)
		go func() {
			io.Copy(ch, ch)
			ch.Close()
		}()
	}
}

func TestSSHOverWebSocketPayload(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte(ws101))
		pxSSHServer(c) // raw SSH right after the 101, no WebSocket framing
	})
	cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
		Payload: &PayloadConfig{Template: "@ssh-ws", Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	pxEcho(t, cl, "target.example:80")
}

// A payload with two requests: CONNECT to the proxy, then the Upgrade request
// through it. Two replies are read (200, then 101) before the protocol starts.
func TestSSHWebSocketViaProxyTwoReplies(t *testing.T) {
	got := make(chan string, 2)
	ph, pp := pxServeOnce(t, func(c net.Conn) {
		h1, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		got <- h1
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		h2, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		got <- h2
		c.Write([]byte(ws101))
		pxSocks5(c, "", "")
	})
	cl, err := New(&Config{Protocol: "socks5", Server: "origin.example", Port: 80, Payload: &PayloadConfig{
		Template: "CONNECT [host_port] HTTP/1.1[crlf][crlf]GET / HTTP/1.1[crlf]Host: bug.example.com[crlf]Upgrade: websocket[crlf][crlf]",
		Proxy:    net.JoinHostPort(ph, strconv.Itoa(pp)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	if h1 := <-got; !strings.HasPrefix(h1, "CONNECT origin.example:80 HTTP/1.1\r\n") {
		t.Fatalf("first request: %q", h1)
	}
	if h2 := <-got; !strings.Contains(h2, "Upgrade: websocket") {
		t.Fatalf("second request: %q", h2)
	}
}

// The response changer: "301 Moved Permanently" counts as "200 OK".
func TestResponseMapTurns301IntoSuccess(t *testing.T) {
	client := func(m map[string]int) *Client {
		h, p := pxServeOnce(t, func(c net.Conn) {
			if _, err := pxReadHeaders(c); err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: http://example.com/\r\n\r\n"))
			pxSocks5(c, "", "")
		})
		cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p,
			Payload: &PayloadConfig{Template: "@ssh-ws", ResponseMap: m}})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}

	// without a map the 301 is refused
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client(nil).DialContext(ctx, "tcp", "target.example:80"); err == nil {
		t.Fatal("a 301 reply must fail without a responseMap")
	}
	pxEcho(t, client(map[string]int{"301": 200}), "target.example:80")
	pxEcho(t, client(map[string]int{"3xx": 200}), "target.example:80")
}

func TestResponseMapValidation(t *testing.T) {
	bad := []map[string]int{{"abc": 200}, {"301": 99}, {"7xx": 200}, {"30": 200}, {"301": 700}}
	for _, m := range bad {
		_, err := New(&Config{Protocol: "socks5", Server: "example.com", Port: 80,
			Payload: &PayloadConfig{Template: "@ssh-ws", ResponseMap: m}})
		if err == nil {
			t.Errorf("responseMap %v must be rejected", m)
		}
	}
	_, err := New(&Config{Protocol: "socks5", Server: "example.com", Port: 80,
		Payload: &PayloadConfig{Template: "@ssh-ws", ResponseMap: map[string]int{"301": 200, "4XX": 200}}})
	if err != nil {
		t.Fatalf("a valid responseMap was rejected: %v", err)
	}
}
