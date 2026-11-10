package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"io.surprise.vpn/transport"
)

// sshHandshakeTimeout bounds the SSH banner exchange, key exchange and login on
// a connection that is already open. ssh.ClientConfig.Timeout only covers
// ssh.Dial, never ssh.NewClientConn, so without this a server that accepts the
// connection and then stays silent (a wrong SNI or payload, a dead origin
// behind a CDN) would hang the dial until the caller gives up, with nothing in
// the log.
const sshHandshakeTimeout = 20 * time.Second

// SSH tunnels through an SSH server (direct-tcpip). The Dialer chain lets
// you put payload/TLS(SNI)/WebSocket under SSH like HTTP Injector does.
type SSH struct {
	Server     string
	Dialer     transport.Dialer
	User       string
	Password   string
	PrivateKey []byte
	// Passphrase decrypts PrivateKey when the key is encrypted. It is ignored
	// for a key without a passphrase.
	Passphrase string
	Options    SSHOptions
	// HostKeySHA256 pins the server's host key: an OpenSSH fingerprint
	// ("SHA256:...", as printed by ssh-keygen -l) or 64 hex characters. Empty
	// accepts any key, which is what most tunnel apps do and lets anyone on the
	// path impersonate the server.
	HostKeySHA256 string
	mu            sync.Mutex
	client        *ssh.Client
	lastWarn      time.Time
}

// ParsePrivateKey parses a PEM or OpenSSH private key. An encrypted key needs
// its passphrase; a key without one is parsed as it is, whatever passphrase is
// given.
func ParsePrivateKey(pem []byte, passphrase string) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pem)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, err
	}
	if passphrase == "" {
		return nil, errors.New("ssh: the private key is encrypted; set its passphrase")
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("ssh: cannot decrypt the private key (wrong passphrase?): %w", err)
	}
	return signer, nil
}

// parsePin decodes a host key pin into the 32-byte SHA-256 of the key blob.
func parsePin(p string) ([]byte, bool) {
	p = strings.TrimSpace(p)
	if rest, ok := strings.CutPrefix(p, "SHA256:"); ok {
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(rest, "="))
		return b, err == nil && len(b) == 32
	}
	b, err := hex.DecodeString(strings.ReplaceAll(p, ":", ""))
	return b, err == nil && len(b) == 32
}

// ValidHostKeyPin reports whether p is a usable host key pin.
func ValidHostKeyPin(p string) bool {
	_, ok := parsePin(p)
	return ok
}

func (s *SSH) hostKeyCallback() ssh.HostKeyCallback {
	if s.HostKeySHA256 == "" {
		return ssh.InsecureIgnoreHostKey()
	}
	want, ok := parsePin(s.HostKeySHA256)
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if !ok {
			return errors.New("ssh: the pinned host key fingerprint is malformed")
		}
		sum := sha256.Sum256(key.Marshal())
		if !bytes.Equal(sum[:], want) {
			return fmt.Errorf("ssh: host key %s does not match the pinned fingerprint", ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

// warn logs a warning, at most one every two seconds: with the server down
// every new flow would otherwise repeat the same line. Call it with s.mu held.
func (s *SSH) warn(msg string, args ...any) {
	if time.Since(s.lastWarn) < 2*time.Second {
		return
	}
	s.lastWarn = time.Now()
	sshLog.Warn(msg, args...)
}

// keyboardAnswers answers every keyboard-interactive prompt with the password.
// OpenSSH and JSch fall back to this method when a server (typically a PAM
// setup) offers no plain "password" method, so a login that works there works
// here too.
func (s *SSH) keyboardAnswers(_, _ string, questions []string, _ []bool) ([]string, error) {
	answers := make([]string, len(questions))
	for i := range answers {
		answers[i] = s.Password
	}
	return answers, nil
}

func (s *SSH) connect(ctx context.Context) (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	sshLog.Info("ssh connecting", "server", s.Server)
	raw, err := s.Dialer.DialContext(ctx, "tcp", s.Server)
	if err != nil {
		s.warn("ssh: the connection could not be opened (tcp, tls or payload step)", "server", s.Server, "err", err)
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            s.User,
		HostKeyCallback: s.hostKeyCallback(),
		Timeout:         20 * time.Second,
		Config: ssh.Config{
			Ciphers:      pick(s.Options.Ciphers, sshCiphers),
			KeyExchanges: pick(s.Options.KeyExchanges, sshKEX),
			MACs:         pick(s.Options.MACs, sshMACs),
		},
		HostKeyAlgorithms: pick(s.Options.HostKeyAlgos, sshHostKeys),
	}
	if len(s.PrivateKey) > 0 {
		signer, err := ParsePrivateKey(s.PrivateKey, s.Passphrase)
		if err != nil {
			raw.Close()
			sshLog.Warn("ssh private key unusable", "server", s.Server, "err", err)
			return nil, err
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(s.Password), ssh.KeyboardInteractive(s.keyboardAnswers))
	}
	hctx, cancel := context.WithTimeout(ctx, sshHandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(hctx, func() { raw.Close() })
	cc, chans, reqs, err := ssh.NewClientConn(raw, s.Server, cfg)
	if !stop() { // the deadline or ctx ended first and closed the connection
		raw.Close()
		if err == nil {
			cc.Close()
		}
		switch {
		case ctx.Err() != nil:
			err = fmt.Errorf("ssh: handshake with %s was cancelled: %w", s.Server, ctx.Err())
		case err != nil:
			err = fmt.Errorf("ssh: no SSH handshake from %s within %s (the connection opened but nothing answered; check the SNI, payload and port): %w", s.Server, sshHandshakeTimeout, err)
		default:
			err = fmt.Errorf("ssh: no SSH handshake from %s within %s (the connection opened but nothing answered; check the SNI, payload and port)", s.Server, sshHandshakeTimeout)
		}
		s.warn("ssh handshake did not finish", "server", s.Server, "err", err)
		return nil, err
	}
	if err != nil {
		raw.Close()
		s.warn("ssh handshake or login failed", "server", s.Server, "user", s.User, "err", err)
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	s.client = cl
	sshLog.Info("ssh session established", "server", s.Server, "user", s.User, "remote", string(cc.ServerVersion()))
	go func() { // keepalive so NAT/carriers don't drop the tunnel
		for {
			time.Sleep(25 * time.Second)
			if _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}()
	go func() {
		err := cl.Wait()
		s.mu.Lock()
		unexpected := s.client == cl // we did not drop or close it ourselves
		s.mu.Unlock()
		if unexpected {
			sshLog.Warn("ssh session lost", "server", s.Server, "err", err)
		} else {
			sshLog.Debug("ssh session closed", "server", s.Server)
		}
		s.drop(cl)
	}()
	return cl, nil
}

// drop forgets cl (if it is still the current session) and closes it.
func (s *SSH) drop(cl *ssh.Client) {
	s.mu.Lock()
	if s.client == cl {
		s.client = nil
	}
	s.mu.Unlock()
	cl.Close()
}

// Close ends the SSH session and, with it, the keepalive. Without this the
// session (and its TCP connection) outlives a stopped VPN.
func (s *SSH) Close() error {
	s.mu.Lock()
	cl := s.client
	s.client = nil
	s.mu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}

// dialChannel opens a direct-tcpip channel but gives up when ctx ends
// (ssh.Client.Dial itself has no timeout).
func dialChannel(ctx context.Context, cl *ssh.Client, target string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := cl.Dial("tcp", target)
		ch <- result{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (s *SSH) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		cl, err := s.connect(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := dialChannel(ctx, cl, target)
		if err == nil {
			return conn, nil
		}
		// The target refusing the connection says nothing about the session.
		var refused *ssh.OpenChannelError
		if errors.As(err, &refused) {
			sshLog.Debug("ssh server refused the target", "target", target, "err", err)
			return nil, err
		}
		if attempt > 0 || ctx.Err() != nil {
			return nil, err
		}
		// The session may have died since its last use: reconnect once.
		sshLog.Info("ssh session looks dead, reconnecting", "server", s.Server, "err", err)
		s.drop(cl)
	}
}

// SSHOptions are advanced and optional (not exposed by the UI). Empty lists
// mean "maximum compatibility": modern algorithms first, legacy ones after,
// so old provider servers still connect.
type SSHOptions struct {
	Ciphers      []string
	KeyExchanges []string
	MACs         []string
	HostKeyAlgos []string
}

var (
	sshCiphers = []string{"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc", "arcfour256", "arcfour128"}
	sshKEX = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"}
	sshMACs = []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "hmac-sha1-96"}
	sshHostKeys = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"}
)

func pick(user, def []string) []string {
	if len(user) > 0 {
		return user
	}
	return def
}
