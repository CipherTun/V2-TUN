package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC is a base transport (replaces TCP): one bidirectional QUIC stream per dial.
// Written against quic-go v0.65, where connections and streams are the concrete
// types *quic.Conn and *quic.Stream.
type QUIC struct {
	ServerName    string
	ALPN          []string
	AllowInsecure bool
	Resolver      *net.Resolver // protected resolver for the server name; nil => system resolver
}

type quicConn struct {
	*quic.Stream
	qc   *quic.Conn
	pc   net.PacketConn
	once sync.Once
}

func (c *quicConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

func (c *quicConn) Close() error {
	var err error
	c.once.Do(func() {
		c.Stream.CancelRead(0)
		c.Stream.Close()
		err = c.qc.CloseWithError(0, "")
		// quic.Dial does not own a PacketConn passed to it; without this every
		// connection leaks one UDP socket.
		c.pc.Close()
	})
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

func (d *QUIC) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
	qc, err := quic.Dial(ctx, pc, ua, &tls.Config{ServerName: sni, NextProtos: alpn,
		InsecureSkipVerify: d.AllowInsecure}, &quic.Config{KeepAlivePeriod: 20 * time.Second})
	if err != nil {
		pc.Close()
		return nil, err
	}
	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		qc.CloseWithError(0, "")
		pc.Close()
		return nil, err
	}
	return &quicConn{Stream: st, qc: qc, pc: pc}, nil
}
