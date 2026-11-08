package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC is a base transport (replaces TCP).
// Written against quic-go v0.65, where connections and streams are the concrete
// types *quic.Conn and *quic.Stream.
//
// MultiStream=false: one QUIC connection and one bidirectional stream per dial.
// MultiStream=true:  one shared QUIC connection (per server address); every dial
// opens a new stream on it. The session is re-established when it dies.
type QUIC struct {
	ServerName    string
	ALPN          []string
	AllowInsecure bool
	Resolver      *net.Resolver // protected resolver for the server name; nil => system resolver
	MultiStream   bool
	KeepAlive     time.Duration // default 20s
	MaxIdle       time.Duration // default 30s

	mu   sync.Mutex
	sess *quicSession
}

type quicSession struct {
	qc   *quic.Conn
	pc   net.PacketConn
	addr string
	once sync.Once
}

func (s *quicSession) close() {
	s.once.Do(func() {
		s.qc.CloseWithError(0, "")
		// quic.Dial does not own a PacketConn passed to it; without this every
		// connection leaks one UDP socket.
		s.pc.Close()
	})
}

type quicConn struct {
	*quic.Stream
	qc    *quic.Conn
	sess  *quicSession
	owner bool // single-stream mode: closing the stream closes the whole session
}

func (c *quicConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	if c.owner {
		c.sess.close()
	}
	return err
}

func (d *QUIC) resolve(ctx context.Context, addr string) (*net.UDPAddr, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	rs := d.Resolver
	if rs == nil {
		rs = net.DefaultResolver
	}
	ips, err := rs.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("quic: no address for %s", host)
	}
	pick := ips[0].IP
	for _, a := range ips {
		if a.IP.To4() != nil {
			pick = a.IP
			break
		}
	}
	return &net.UDPAddr{IP: pick, Port: port}, nil
}

func (d *QUIC) dial(ctx context.Context, addr string) (*quicSession, error) {
	ua, err := d.resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	pc, err := (&net.ListenConfig{Control: controlFn}).ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	sni := d.ServerName
	if sni == "" {
		sni = host
	}
	alpn := d.ALPN
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	ka := d.KeepAlive
	if ka == 0 {
		ka = 20 * time.Second
	}
	idle := d.MaxIdle
	if idle == 0 {
		idle = 30 * time.Second
	}
	qc, err := quic.Dial(ctx, pc, ua, &tls.Config{ServerName: sni, NextProtos: alpn,
		InsecureSkipVerify: d.AllowInsecure},
		&quic.Config{KeepAlivePeriod: ka, MaxIdleTimeout: idle})
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &quicSession{qc: qc, pc: pc, addr: addr}, nil
}

func (d *QUIC) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !d.MultiStream {
		s, err := d.dial(ctx, addr)
		if err != nil {
			return nil, err
		}
		st, err := s.qc.OpenStreamSync(ctx)
		if err != nil {
			s.close()
			return nil, err
		}
		return &quicConn{Stream: st, qc: s.qc, sess: s, owner: true}, nil
	}
	for try := 0; try < 2; try++ {
		s, err := d.session(ctx, addr)
		if err != nil {
			return nil, err
		}
		st, err := s.qc.OpenStreamSync(ctx)
		if err == nil {
			return &quicConn{Stream: st, qc: s.qc, sess: s}, nil
		}
		d.drop(s) // session is dead or stale: rebuild once
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("quic: cannot open stream")
}

func (d *QUIC) session(ctx context.Context, addr string) (*quicSession, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s := d.sess; s != nil {
		if s.addr == addr && s.qc.Context().Err() == nil {
			return s, nil
		}
		s.close()
		d.sess = nil
	}
	s, err := d.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	d.sess = s
	return s, nil
}

func (d *QUIC) drop(s *quicSession) {
	d.mu.Lock()
	if d.sess == s {
		d.sess = nil
	}
	d.mu.Unlock()
	s.close()
}

// Close tears down the shared session (multi-stream mode).
func (d *QUIC) Close() error {
	d.mu.Lock()
	s := d.sess
	d.sess = nil
	d.mu.Unlock()
	if s != nil {
		s.close()
	}
	return nil
}
