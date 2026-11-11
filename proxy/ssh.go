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

const (
	// sshHandshakeTimeout bounds the SSH banner exchange, key exchange and
	// login on a connection that is already open. ssh.ClientConfig.Timeout
	// only covers ssh.Dial, never ssh.NewClientConn, so without this a server
	// that accepts the connection and then stays silent (a wrong SNI or
	// payload, a dead origin behind a CDN) would hang the dial until the
	// caller gives up, with nothing in the log.
	sshHandshakeTimeout = 20 * time.Second

	// Keepalive, like OpenSSH's ServerAliveInterval and ServerAliveCountMax:
	// a probe every sshKeepaliveEvery, a miss when it is not answered within
	// sshKeepaliveTimeout, and the session is dropped after sshKeepaliveMisses
	// misses in a row so the next dial reconnects.
	sshKeepaliveEvery   = 15 * time.Second
	sshKeepaliveTimeout = 10 * time.Second
	sshKeepaliveMisses  = 3

	// sshAuthCooldown is how long new logins are refused after the server
	// rejected the credentials. Every new flow would otherwise try again and a
	// server with fail2ban or MaxAuthTries locks the account.
	sshAuthCooldown = 30 * time.Second

	// sshClientVersion is the identification string sent when the user sets
	// none. Go's own default ("SSH-2.0-Go") is easy to spot and some servers and
	// middleboxes treat it differently from OpenSSH; MegaProxy and the Android
	// injector apps also look like OpenSSH or JSch.
	sshClientVersion = "SSH-2.0-OpenSSH_8.4"

	// sshChannelOpenTimeout is how long one channel open may wait for the
	// server's answer. The server answers only after it reached the target, so
	// a slow target is not a sick session: a stalled open makes the client
	// probe the session (see channelStalled) instead of dropping it blindly.
	sshChannelOpenTimeout = 15 * time.Second

	// sshMaxOpening limits channel opens that wait for an answer at the same
	// time. A page with many dead hosts would otherwise flood the server with
	// opens, and a server at its limit refuses all of them.
	sshMaxOpening = 32

	// sshShortageRetries is how many times an open is repeated after the server
	// answered "resource shortage" (it is at its channel limit), with a short
	// pause that grows each time.
	sshShortageRetries = 2
)

// ValidClientVersion reports whether v can be sent as the SSH identification
// string: "SSH-2.0-" followed by printable ASCII (a space starts the optional
// comment), 255 bytes at most with the line ending (RFC 4253 section 4.2).
func ValidClientVersion(v string) bool {
	if !strings.HasPrefix(v, "SSH-2.0-") || len(v) == len("SSH-2.0-") || len(v) > 253 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

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
	authFailUntil time.Time
	probing       bool // a session probe after a stalled channel open is running

	slotsOnce sync.Once
	slotsCh   chan struct{} // limits the channel opens that wait for an answer
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

// showBanner logs the text a server sends before the login. Providers use it
// for things like "account expired" or "connection limit reached".
func (s *SSH) showBanner(msg string) error {
	text := strings.Join(strings.Fields(msg), " ")
	if text == "" {
		return nil
	}
	if len(text) > 300 {
		text = text[:300] + "..."
	}
	sshLog.Info("ssh server banner", "server", s.Server, "text", text)
	return nil
}

func (s *SSH) connect(ctx context.Context) (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	if wait := time.Until(s.authFailUntil); wait > 0 {
		return nil, fmt.Errorf("ssh: the server refused the login for %q a moment ago; not trying again for %s to avoid a lockout (check the username and password)", s.User, wait.Round(time.Second))
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
		BannerCallback:  s.showBanner,
		Timeout:         20 * time.Second,
		Config: ssh.Config{
			Ciphers:      pick(s.Options.Ciphers, sshCiphers),
			KeyExchanges: pick(s.Options.KeyExchanges, sshKEX),
			MACs:         pick(s.Options.MACs, sshMACs),
		},
		HostKeyAlgorithms: pick(s.Options.HostKeyAlgos, sshHostKeys),
		ClientVersion:     s.clientVersion(),
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
		if strings.Contains(err.Error(), "unable to authenticate") {
			s.authFailUntil = time.Now().Add(sshAuthCooldown)
			s.warn("ssh login refused, pausing new logins", "server", s.Server, "user", s.User, "pause", sshAuthCooldown.String(), "err", err)
		} else {
			s.warn("ssh handshake or login failed", "server", s.Server, "user", s.User, "err", err)
		}
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	s.client = cl
	sshLog.Info("ssh session established", "server", s.Server, "user", s.User, "remote", string(cc.ServerVersion()))
	go s.keepalive(cl)
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

// current reports whether cl is still the live session.
func (s *SSH) current(cl *ssh.Client) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client == cl
}

// keepalive probes the session so NAT and carriers do not drop it, and so a
// session that went silent is noticed. A probe that gets no answer within
// sshKeepaliveTimeout counts as a miss; sshKeepaliveMisses misses in a row drop
// the session, and the next dial reconnects. Without the timeout a silent
// network leaves the request waiting for as long as TCP takes to give up.
func (s *SSH) keepalive(cl *ssh.Client) {
	t := time.NewTicker(sshKeepaliveEvery)
	defer t.Stop()
	misses := 0
	for range t.C {
		if !s.current(cl) {
			return
		}
		res := make(chan error, 1)
		go func() {
			_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
			res <- err
		}()
		select {
		case err := <-res:
			if err != nil {
				return // the session ended; the Wait goroutine reports it
			}
			misses = 0
		case <-time.After(sshKeepaliveTimeout):
			misses++
			if misses < sshKeepaliveMisses {
				sshLog.Debug("ssh keepalive not answered", "server", s.Server, "misses", misses)
				continue
			}
			sshLog.Warn("ssh session dropped: the server stopped answering keepalives", "server", s.Server, "misses", misses)
			s.drop(cl)
			return
		}
	}
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

// clientVersion is the identification string this client sends.
func (s *SSH) clientVersion() string {
	if v := s.Options.ClientVersion; v != "" {
		return v
	}
	return sshClientVersion
}

// slots returns the semaphore that limits channel opens waiting for an answer.
func (s *SSH) slots() chan struct{} {
	s.slotsOnce.Do(func() { s.slotsCh = make(chan struct{}, sshMaxOpening) })
	return s.slotsCh
}

// errChannelStalled means the server did not answer a channel open in time.
var errChannelStalled = errors.New("ssh: the server did not answer the channel open in time (the target may be unreachable from the server)")

// sessionAlive sends a keepalive and reports whether the server answered
// within timeout. Any answer counts, even a refusal: it proves the session is
// up.
func sessionAlive(cl *ssh.Client, timeout time.Duration) bool {
	res := make(chan error, 1)
	go func() {
		_, _, err := cl.SendRequest("keepalive@openssh.com", true, nil)
		res <- err
	}()
	select {
	case err := <-res:
		return err == nil
	case <-time.After(timeout):
		return false
	}
}

// channelStalled is called when a channel open got no answer in time. A slow
// or dead target causes that as well, so the session is probed with a
// keepalive and dropped only when the server does not answer that either;
// the next dial then reconnects at once instead of after three missed
// keepalives. One probe runs at a time.
func (s *SSH) channelStalled(cl *ssh.Client) {
	s.mu.Lock()
	if s.client != cl || s.probing {
		s.mu.Unlock()
		return
	}
	s.probing = true
	s.mu.Unlock()
	go func() {
		alive := sessionAlive(cl, sshKeepaliveTimeout)
		s.mu.Lock()
		s.probing = false
		if !alive && s.client == cl {
			s.warn("ssh session dropped: a channel open and the probe after it got no answer", "server", s.Server)
		}
		s.mu.Unlock()
		if !alive {
			s.drop(cl)
		}
	}()
}

// openChannel opens a direct-tcpip channel (ssh.Client.Dial has no timeout of
// its own). It gives up when ctx ends or after sshChannelOpenTimeout, and at
// most sshMaxOpening opens wait for an answer at the same time.
func (s *SSH) openChannel(ctx context.Context, cl *ssh.Client, target string) (net.Conn, error) {
	slots := s.slots()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-slots }()

	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := cl.Dial("tcp", target)
		ch <- result{conn, err}
	}()
	// An abandoned open may still succeed later; close what it returns.
	abandon := func() {
		go func() {
			if r := <-ch; r.conn != nil {
				r.conn.Close()
			}
		}()
	}
	timer := time.NewTimer(sshChannelOpenTimeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		abandon()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			s.channelStalled(cl)
		}
		return nil, ctx.Err()
	case <-timer.C:
		abandon()
		s.channelStalled(cl)
		return nil, errChannelStalled
	}
}

func (s *SSH) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	reconnected := false
	shortages := 0
	for {
		cl, err := s.connect(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := s.openChannel(ctx, cl, target)
		if err == nil {
			return conn, nil
		}
		// The target refusing the connection says nothing about the session.
		var refused *ssh.OpenChannelError
		if errors.As(err, &refused) {
			// The server is at its channel limit: ask again after a short pause.
			if refused.Reason == ssh.ResourceShortage && shortages < sshShortageRetries && ctx.Err() == nil {
				shortages++
				sshLog.Debug("ssh server is out of channels, retrying", "target", target, "attempt", shortages)
				select {
				case <-time.After(time.Duration(shortages) * 300 * time.Millisecond):
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			sshLog.Debug("ssh server refused the target", "target", target, "err", err)
			return nil, err
		}
		if errors.Is(err, errChannelStalled) || reconnected || ctx.Err() != nil {
			return nil, err
		}
		// The session may have died since its last use: reconnect once.
		reconnected = true
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
	// ClientVersion is the SSH identification string ("SSH-2.0-..."); empty
	// sends sshClientVersion.
	ClientVersion string
}

var (
	sshCiphers = []string{"aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc", "arcfour256", "arcfour128"}
	// The last three are only used when the server offers nothing from the
	// earlier ones, so they cannot change the outcome for servers that already
	// connect. Group exchange is what some old OpenSSH and Dropbear builds
	// prefer.
	sshKEX = []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
		"diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"}
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
