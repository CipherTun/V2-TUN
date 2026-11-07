package v2tun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"io.surprise.vpn/route"
)

func TestFallbackTakesOverAndSticks(t *testing.T) {
	// a port nobody listens on
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, dp, _ := net.SplitHostPort(dead.Addr().String())
	dead.Close()
	deadPort := 0
	for _, c := range dp {
		deadPort = deadPort*10 + int(c-'0')
	}

	h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "", "") })
	cl, err := New(&Config{
		Protocol: "socks5", Server: "127.0.0.1", Port: deadPort,
		Fallbacks: []*Config{{Protocol: "socks5", Server: h, Port: p}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.ActiveOutbound() != 0 {
		t.Fatalf("active before any connection: %d", cl.ActiveOutbound())
	}
	pxEcho(t, cl, "target.example:80")
	if cl.ActiveOutbound() != 1 {
		t.Fatalf("the fallback should be active, got %d", cl.ActiveOutbound())
	}
}

func TestFallbackValidation(t *testing.T) {
	base := func() *Config { return &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1} }
	nested := base()
	nested.Fallbacks = []*Config{{Protocol: "socks5", Server: "127.0.0.1", Port: 2,
		Fallbacks: []*Config{{Protocol: "socks5", Server: "127.0.0.1", Port: 3}}}}
	if _, err := New(nested); err == nil {
		t.Fatal("fallbacks of fallbacks must be rejected")
	}
	broken := base()
	broken.Fallbacks = []*Config{{Protocol: "nonsense", Server: "127.0.0.1", Port: 2}}
	if _, err := New(broken); err == nil {
		t.Fatal("an invalid fallback must be reported")
	}
	nilFallback := base()
	nilFallback.Fallbacks = []*Config{nil}
	if _, err := New(nilFallback); err == nil {
		t.Fatal("a null fallback must be rejected")
	}
}

func TestScanFindsTheWorkingValue(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "", "") })
	// 127.0.0.2 does not answer on the listener's port
	res := Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.2", Port: p},
		"server", []string{h, "127.0.0.2"}, "target.example:80", 2, 5*time.Second)
	if len(res) != 2 {
		t.Fatalf("%d results", len(res))
	}
	if !res[0].OK || res[0].Value != h {
		t.Fatalf("the listening address should work: %+v", res[0])
	}
	if res[1].OK || res[1].Error == "" {
		t.Fatalf("the other address should fail: %+v", res[1])
	}
}

func TestScanRejectsUnknownField(t *testing.T) {
	res := Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1},
		"nope", []string{"a"}, "x:1", 1, time.Second)
	if len(res) != 1 || res[0].OK || res[0].Error == "" {
		t.Fatalf("%+v", res)
	}
	res = Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1},
		"payload.host", []string{"a"}, "x:1", 1, time.Second)
	if len(res) != 1 || res[0].OK || !strings.Contains(res[0].Error, "no payload") {
		t.Fatalf("scanning payload.host without a payload: %+v", res)
	}
}

func TestPreviewPayload(t *testing.T) {
	out, err := PreviewPayload(&Config{Protocol: "ssh", Server: "origin.example", Port: 80,
		Payload: &PayloadConfig{Template: "@ssh-ws", Host: "bug.example.com", ResponseMap: map[string]int{"301": 200}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"origin.example:80", "GET / HTTP/1.1", "Host: bug.example.com", "Upgrade: websocket",
		"expects 1 HTTP reply", "301 counts as 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %q:\n%s", want, out)
		}
	}
	out, err = PreviewPayload(&Config{Protocol: "ssh", Server: "origin.example", Port: 22,
		Payload: &PayloadConfig{Template: "CONNECT [host_port] HTTP/1.1[crlf][crlf]GET / HTTP/1.1[crlf]Upgrade: websocket[crlf][crlf]",
			Proxy: "1.2.3.4:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "the proxy 1.2.3.4:8080") || !strings.Contains(out, "expects 2 HTTP reply") {
		t.Errorf("proxy preview:\n%s", out)
	}
	if _, err := PreviewPayload(&Config{Server: "x", Port: 1}); err == nil {
		t.Fatal("no payload must be reported")
	}
}

func TestSpeedTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1<<20))
	}))
	defer srv.Close()
	// route everything direct: the test needs the tunnel plumbing, not a server
	cl, err := New(&Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1,
		Routing: &route.Config{Default: route.Direct}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	n, bps, err := cl.SpeedTest(context.Background(), srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1<<20 || bps <= 0 {
		t.Fatalf("got %d bytes at %f bit/s", n, bps)
	}
}

func pxSSHServeWith(c net.Conn, signer ssh.Signer) {
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

func TestSSHHostKeyPin(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	client := func(pin string) *Client {
		h, p := pxServeOnce(t, func(c net.Conn) { pxSSHServeWith(c, signer) })
		cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
			Advanced: Advanced{SSHHostKey: pin}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}

	pxEcho(t, client(ssh.FingerprintSHA256(signer.PublicKey())), "target.example:80")

	wrong := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client(wrong).DialContext(ctx, "tcp", "target.example:80"); err == nil {
		t.Fatal("a server whose host key does not match the pin must be refused")
	}

	if _, err := New(&Config{Protocol: "ssh", Server: "example.com", Port: 22,
		Advanced: Advanced{SSHHostKey: "not a fingerprint"}}); err == nil {
		t.Fatal("a malformed pin must be rejected when the config is checked")
	}
}
