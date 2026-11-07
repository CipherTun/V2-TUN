package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// ProbeHostKey connects through the dialer chain (payload, TLS, WebSocket ...),
// runs the SSH key exchange and returns the server's host key fingerprint as
// "SHA256:..." (the format of ssh-keygen -l, and of HostKeySHA256) without
// logging in. An app uses it to learn a server's key on first use and then pin
// it. The connection is closed afterwards; the shared session is not touched.
func (s *SSH) ProbeHostKey(ctx context.Context) (string, error) {
	raw, err := s.Dialer.DialContext(ctx, "tcp", s.Server)
	if err != nil {
		return "", err
	}
	defer raw.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() { // ssh.NewClientConn has no context: close the stream when ctx ends
		select {
		case <-ctx.Done():
			raw.Close()
		case <-stop:
		}
	}()

	got := make(chan string, 1)
	cfg := &ssh.ClientConfig{
		User: s.User,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			select {
			case got <- ssh.FingerprintSHA256(key):
			default:
			}
			return errors.New("host key captured") // abort before authentication
		},
		Timeout: 20 * time.Second,
		Config: ssh.Config{
			Ciphers:      pick(s.Options.Ciphers, sshCiphers),
			KeyExchanges: pick(s.Options.KeyExchanges, sshKEX),
			MACs:         pick(s.Options.MACs, sshMACs),
		},
		HostKeyAlgorithms: pick(s.Options.HostKeyAlgos, sshHostKeys),
	}
	_, _, _, err = ssh.NewClientConn(raw, s.Server, cfg)
	select {
	case fp := <-got:
		return fp, nil
	default:
	}
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err == nil {
		err = errors.New("ssh: the server presented no host key")
	}
	return "", err
}
