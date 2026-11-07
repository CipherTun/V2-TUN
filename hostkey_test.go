package v2tun

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hkServer starts an SSH server with one fixed host key (user "u", password
// "p", direct-tcpip echo) and returns its address and the key's fingerprint.
func hkServer(t *testing.T) (string, int, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if m.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
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
			}()
		}
	}()
	h, ps, _ := net.SplitHostPort(l.Addr().String())
	p, _ := strconv.Atoi(ps)
	return h, p, ssh.FingerprintSHA256(signer.PublicKey())
}

func TestProbeHostKeyReturnsTheServerFingerprint(t *testing.T) {
	h, p, want := hkServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := ProbeHostKey(ctx, &Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "SHA256:") {
		t.Fatalf("not in ssh-keygen format: %q", got)
	}
}

func TestProbeHostKeyNeedsSSH(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ProbeHostKey(ctx, &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1}); err == nil {
		t.Fatal("probing a non-ssh config must be rejected")
	}
}

func TestProbeHostKeyFailsWhenNothingListens(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, ps, _ := net.SplitHostPort(l.Addr().String())
	l.Close() // the port is now closed
	p, _ := strconv.Atoi(ps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ProbeHostKey(ctx, &Config{Protocol: "ssh", Server: "127.0.0.1", Port: p, Username: "u", Password: "p"}); err == nil {
		t.Fatal("expected a connection error")
	}
}

// The learned fingerprint is accepted as a pin (SHA256:... and hex forms); any other key is refused.
func TestSSHHostKeyPin(t *testing.T) {
	h, p, fp := hkServer(t)
	mk := func(pin string) *Client {
		cl, err := New(&Config{Protocol: "ssh", Server: h, Port: p, Username: "u", Password: "p",
			Advanced: Advanced{SSHHostKey: pin}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}
	pxEcho(t, mk(""), "target.example:80") // no pin: any key
	pxEcho(t, mk(fp), "target.example:80")  // the real key

	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fp, "SHA256:"))
	if err != nil {
		t.Fatal(err)
	}
	pxEcho(t, mk(hex.EncodeToString(raw)), "target.example:80") // the same fingerprint as hex

	wrong := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, sha256.Size))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = mk(wrong).DialContext(ctx, "tcp", "target.example:80")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a wrong pin must be refused, got %v", err)
	}
}

func TestSSHHostKeyPinMalformed(t *testing.T) {
	_, err := New(&Config{Protocol: "ssh", Server: "example.com", Port: 22, Username: "u", Password: "p",
		Advanced: Advanced{SSHHostKey: "not-a-fingerprint"}})
	if err == nil {
		t.Fatal("a malformed pin must be rejected by New")
	}
}
