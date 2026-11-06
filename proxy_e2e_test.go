package v2tun

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Loopback tests for the SOCKS and HTTP proxy outbounds and for the payload's
// remote proxy mode. Each fake server handles one connection.

func pxReadHeaders(c net.Conn) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for !bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		buf = append(buf, b[0])
	}
	return string(buf), nil
}

func pxServeOnce(t *testing.T, handle func(c net.Conn)) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		handle(c)
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return h, port
}

func pxEcho(t *testing.T, cl *Client, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := cl.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo returned %q", buf)
	}
}

// pxSocks5 speaks the server side of SOCKS5 (with password auth when user is
// set) and then echoes.
func pxSocks5(c net.Conn, user, pass string) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if user == "" {
		c.Write([]byte{5, 0})
	} else {
		if !bytes.Contains(methods, []byte{2}) {
			c.Write([]byte{5, 0xff})
			return
		}
		c.Write([]byte{5, 2})
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		u := make([]byte, v[1])
		io.ReadFull(c, u)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		io.ReadFull(c, p)
		if string(u) != user || string(p) != pass {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	var r [4]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return
	}
	switch r[3] {
	case 1:
		io.CopyN(io.Discard, c, 6)
	case 4:
		io.CopyN(io.Discard, c, 18)
	case 3:
		var l [1]byte
		io.ReadFull(c, l[:])
		io.CopyN(io.Discard, c, int64(l[0])+2)
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	io.Copy(c, c)
}

func TestSOCKS5Outbound(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "", "") })
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
}

func TestSOCKS5Auth(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "u", "p") })
	cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")

	h, p = pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "u", "p") })
	bad, err := New(&Config{Protocol: "socks5", Server: h, Port: p, Username: "u", Password: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := bad.DialContext(ctx, "tcp", "target.example:80"); err == nil {
		t.Fatal("a wrong password must fail")
	}
}

func TestSOCKS4aOutbound(t *testing.T) {
	got := make(chan string, 1)
	h, p := pxServeOnce(t, func(c net.Conn) {
		var hd [8]byte
		if _, err := io.ReadFull(c, hd[:]); err != nil {
			return
		}
		readZ := func() string {
			var s []byte
			b := make([]byte, 1)
			for {
				if _, err := io.ReadFull(c, b); err != nil || b[0] == 0 {
					return string(s)
				}
				s = append(s, b[0])
			}
		}
		readZ() // user id
		host := ""
		if hd[4] == 0 && hd[5] == 0 && hd[6] == 0 && hd[7] != 0 {
			host = readZ()
		}
		got <- host
		c.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})
		io.Copy(c, c)
	})
	cl, err := New(&Config{Protocol: "socks4a", Server: h, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	if host := <-got; host != "target.example" {
		t.Fatalf("socks4a host: %q", host)
	}
}

func TestHTTPProxyOutbound(t *testing.T) {
	got := make(chan string, 1)
	h, p := pxServeOnce(t, func(c net.Conn) {
		hdr, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		got <- hdr
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		io.Copy(c, c)
	})
	cl, err := New(&Config{Protocol: "http", Server: h, Port: p, Username: "user", Password: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	hdr := <-got
	if !strings.HasPrefix(hdr, "CONNECT target.example:80 HTTP/1.1\r\n") {
		t.Fatalf("request line: %q", hdr)
	}
	if !strings.Contains(hdr, "Proxy-Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass"))) {
		t.Fatalf("missing proxy credentials in %q", hdr)
	}
}

func TestHTTPProxyRefused(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	})
	cl, err := New(&Config{Protocol: "http", Server: h, Port: p})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cl.DialContext(ctx, "tcp", "target.example:80"); err == nil {
		t.Fatal("a 403 reply to CONNECT must fail the dial")
	}
}

// Remote proxy mode: the TCP connection goes to the proxy, the payload names
// the real server, the proxy answers 200, then the protocol runs through it.
func TestPayloadRemoteProxy(t *testing.T) {
	got := make(chan string, 1)
	ph, pp := pxServeOnce(t, func(c net.Conn) {
		hdr, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		got <- hdr
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		pxSocks5(c, "", "")
	})
	cl, err := New(&Config{
		Protocol: "socks5", Server: "origin.example", Port: 1080,
		Payload: &PayloadConfig{Template: "@connect", Proxy: net.JoinHostPort(ph, strconv.Itoa(pp))},
	})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	if hdr := <-got; !strings.HasPrefix(hdr, "CONNECT origin.example:1080 HTTP/1.1\r\n") {
		t.Fatalf("the payload must name the real server, got %q", hdr)
	}
}

func TestPayloadProxyNeedsPreTLS(t *testing.T) {
	_, err := New(&Config{
		Protocol: "socks5", Server: "origin.example", Port: 1080,
		TLS:     TLSConfig{Enabled: true},
		Payload: &PayloadConfig{Template: "@connect", Proxy: "127.0.0.1:8080", Stage: "post-tls"},
	})
	if err == nil {
		t.Fatal("a payload proxy with the post-tls stage must be rejected")
	}
}

func TestHTTPSProxyNeedsTLS(t *testing.T) {
	if _, err := New(&Config{Protocol: "https", Server: "proxy.example", Port: 443}); err == nil {
		t.Fatal("an https proxy without tls.enabled must be rejected")
	}
}
