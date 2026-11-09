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

// There are no payload presets: tests write their payloads out.
const (
	sshWSPayload   = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
	connectPayload = "CONNECT [host_port] [protocol][crlf]Host: [host][crlf]Proxy-Connection: Keep-Alive[crlf][crlf]"
)

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
		Payload: &PayloadConfig{Template: sshWSPayload, Host: "bug.example.com"}})
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
		Payload: &PayloadConfig{Template: sshWSPayload, Host: "bug.example.com"}})
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

// Replies are judged automatically: everything below 400 lets the tunnel
// start (101, 2xx, 3xx), 4xx and 5xx do not. There is nothing to configure.
func TestReplyStatusRule(t *testing.T) {
	serve := func(status string) *Client {
		h, p := pxServeOnce(t, func(c net.Conn) {
			if _, err := pxReadHeaders(c); err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 " + status + "\r\nLocation: http://example.com/\r\n\r\n"))
			pxSocks5(c, "", "")
		})
		cl, err := New(&Config{Protocol: "socks5", Server: h, Port: p, Payload: &PayloadConfig{Template: sshWSPayload}})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	for _, ok := range []string{"101 Switching Protocols", "200 OK", "204 No Content", "301 Moved Permanently", "302 Found", "307 Temporary Redirect", "399 Custom"} {
		t.Run("accept "+ok, func(t *testing.T) { pxEcho(t, serve(ok), "target.example:80") })
	}
	for _, bad := range []string{"400 Bad Request", "403 Forbidden", "404 Not Found", "407 Proxy Authentication Required", "502 Bad Gateway"} {
		t.Run("refuse "+bad, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := serve(bad).DialContext(ctx, "tcp", "target.example:80"); err == nil {
				t.Fatalf("a %s reply must fail", bad)
			}
		})
	}
}

// [host] is the bug host, [server_host_port] and [ip_port] always the real
// target, also behind a remote proxy (where the socket peer is the proxy).
func TestServerTagsViaProxy(t *testing.T) {
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
	cl, err := New(&Config{Protocol: "socks5", Server: "127.0.0.1", Port: 80, Payload: &PayloadConfig{
		Template: "CONNECT [server_host_port] HTTP/1.1[crlf]Host: [host][crlf]X-Server: [server]:[server_port][crlf]X-Ip: [ip_port][crlf][crlf]",
		Host:     "bug.example.com",
		Proxy:    net.JoinHostPort(ph, strconv.Itoa(pp)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, cl, "target.example:80")
	hdr := <-got
	for _, want := range []string{"CONNECT 127.0.0.1:80 HTTP/1.1\r\n", "Host: bug.example.com\r\n",
		"X-Server: 127.0.0.1:80\r\n", "X-Ip: 127.0.0.1:80\r\n"} {
		if !strings.Contains(hdr, want) {
			t.Errorf("request lacks %q:\n%q", want, hdr)
		}
	}
}

// A payload that is still a preset name is refused instead of being sent as
// the literal text "@ssh-ws".
func TestPresetNameRefused(t *testing.T) {
	if _, err := New(&Config{Protocol: "socks5", Server: "example.com", Port: 80,
		Payload: &PayloadConfig{Template: "@ssh-ws"}}); err == nil {
		t.Fatal("a preset name must be rejected")
	}
}

// srvWS is the server side of a WebSocket stream: it reads masked client
// frames and writes unmasked frames, like a websocket-to-ssh bridge does.
type srvWS struct {
	net.Conn
	rbuf []byte
}

func (s *srvWS) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		var h [2]byte
		if _, err := io.ReadFull(s.Conn, h[:]); err != nil {
			return 0, err
		}
		n := int(h[1] & 0x7f)
		if n == 126 {
			var e [2]byte
			if _, err := io.ReadFull(s.Conn, e[:]); err != nil {
				return 0, err
			}
			n = int(e[0])<<8 | int(e[1])
		} else if n == 127 {
			return 0, errors.New("test server: frame too large")
		}
		var mask [4]byte
		if h[1]&0x80 != 0 {
			if _, err := io.ReadFull(s.Conn, mask[:]); err != nil {
				return 0, err
			}
		}
		pl := make([]byte, n)
		if _, err := io.ReadFull(s.Conn, pl); err != nil {
			return 0, err
		}
		for i := range pl {
			pl[i] ^= mask[i%4]
		}
		if h[0]&0x0f == 8 {
			return 0, io.EOF
		}
		if op := h[0] & 0x0f; op == 0 || op == 1 || op == 2 {
			s.rbuf = pl
		}
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *srvWS) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 4096 {
			n = 4096
		}
		hdr := []byte{0x82, 126, byte(n >> 8), byte(n)}
		if n < 126 {
			hdr = []byte{0x82, byte(n)}
		}
		if _, err := s.Conn.Write(append(hdr, p[:n]...)); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// The same payload works when the server frames the stream: after the 101 the
// client sees a WebSocket frame instead of the SSH banner, switches to
// framing by itself and SSH still logs in. No path, host or mode is set.
func TestSSHOverFramedWebSocketAuto(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil {
			return
		}
		c.Write([]byte(ws101))
		pxSSHServer(&srvWS{Conn: c})
	})
	cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
		Payload: &PayloadConfig{Template: "GET /ws HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]",
			Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	pxEcho(t, cl, "target.example:80")
}

// A real WebSocket server answers 400 to an upgrade request that lacks the
// handshake headers. The payload leaves them out, the library adds them.
func TestSSHWebSocketAddsHandshakeHeaders(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		hdr, err := pxReadHeaders(c)
		if err != nil {
			return
		}
		low := strings.ToLower(hdr)
		if !strings.Contains(low, "\r\nsec-websocket-key: ") || !strings.Contains(low, "\r\nsec-websocket-version: 13\r\n") {
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		c.Write([]byte(ws101))
		pxSSHServer(c)
	})
	cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
		Payload: &PayloadConfig{Template: sshWSPayload, Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	pxEcho(t, cl, "target.example:80")
}

// A decoy request line in front of the upgrade request gets no reply from the
// server. The 101 ends the reading, so the dial does not wait for a second one.
func TestSSHWebSocketDecoyLineDoesNotStall(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) {
		if _, err := pxReadHeaders(c); err != nil { // the decoy
			return
		}
		if _, err := pxReadHeaders(c); err != nil { // the upgrade request
			return
		}
		c.Write([]byte(ws101)) // one reply only
		pxSSHServer(c)
	})
	tpl := "GET http://decoy.example/ HTTP/1.1[crlf]Host: decoy.example[crlf][crlf]" + sshWSPayload
	cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
		Payload: &PayloadConfig{Template: tpl, Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	pxEcho(t, cl, "target.example:80")
}
