package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"io.surprise.vpn/transport"
)

// SSH tunnels through an SSH server (direct-tcpip). The Dialer chain lets
// you put payload/TLS(SNI)/WebSocket under SSH like HTTP Injector does.
type SSH struct {
	Server     string
	Dialer     transport.Dialer
	User       string
	Password   string
	PrivateKey []byte
	Options    SSHOptions
	mu         sync.Mutex
	client     *ssh.Client
}

func (s *SSH) connect(ctx context.Context) (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	raw, err := s.Dialer.DialContext(ctx, "tcp", s.Server)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            s.User,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // matches typical tunnel apps; pin later
		Timeout:         20 * time.Second,
		Config: ssh.Config{
			Ciphers:      pick(s.Options.Ciphers, sshCiphers),
			KeyExchanges: pick(s.Options.KeyExchanges, sshKEX),
			MACs:         pick(s.Options.MACs, sshMACs),
		},
		HostKeyAlgorithms: pick(s.Options.HostKeyAlgos, sshHostKeys),
	}
	if len(s.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(s.PrivateKey)
		if err != nil {
			raw.Close()
			return nil, err
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if s.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(s.Password))
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, s.Server, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	s.client = cl
	go func() { // keepalive so NAT/carriers don't drop the tunnel
		for {
			time.Sleep(25 * time.Second)
			if _, _, err := cl.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				return
			}
		}
	}()
	go func() {
		cl.Wait()
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
		if errors.As(err, &refused) || attempt > 0 || ctx.Err() != nil {
			return nil, err
		}
		// The session may have died since its last use: reconnect once.
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
