package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUIC is a base transport (replaces TCP): one bidirectional QUIC stream per dial.
type QUIC struct {
	ServerName    string
	ALPN          []string
	AllowInsecure bool
}

type quicConn struct {
	quic.Stream
	qc quic.Connection
}

func (c *quicConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }
func (c *quicConn) Close() error {
	c.Stream.CancelRead(0)
	c.Stream.Close()
	return c.qc.CloseWithError(0, "")
}

func (d *QUIC) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
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
		return nil, err
	}
	return &quicConn{Stream: st, qc: qc}, nil
}
