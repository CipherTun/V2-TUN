package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/quic-go/quic-go"

	"io.surprise.vpn/transport"
)

// Hysteria1 is a Hysteria 1 client (protocol v3, spec: v1.hysteria.network).
// A control stream carries the client hello (auth plus the bandwidth the
// server should send/receive at), every TCP connection or UDP session is a
// data stream, and UDP packets ride on QUIC datagrams. It brings its own
// QUIC/TLS, so the payload, TLS and transport layers of a config do not apply.
// Not covered: faketcp, wechat-video, port hopping and Brutal congestion
// control. The server sends at the DownMbps you declare, so set it to what
// your link can really take.
type Hysteria1 struct {
	Server        string // host:port
	Auth          string // auth string
	SNI           string // default: the server host
	ALPN          string // default "hysteria"
	AllowInsecure bool
	Obfs          string // "xplus" password; empty => none
	UpMbps        int    // default 10
	DownMbps      int    // default 50
	Resolver      *net.Resolver

	hyHolder
}

func (h *Hysteria1) dial(ctx context.Context) (*hySession, error) {
	if len(h.Auth) > 65535 {
		return nil, errors.New("hysteria: auth string too long")
	}
	ua, err := hyResolve(ctx, h.Resolver, h.Server)
	if err != nil {
		return nil, err
	}
	var obf func(net.PacketConn) net.PacketConn
	if h.Obfs != "" {
		key := []byte(h.Obfs)
		obf = func(pc net.PacketConn) net.PacketConn { return transport.NewXPlus(pc, key) }
	}
	pc, err := hyPacketConn(ctx, obf)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(h.Server)
	sni := h.SNI
	if sni == "" {
		sni = host
	}
	alpn := h.ALPN
	if alpn == "" {
		alpn = "hysteria"
	}
	qc, err := quic.Dial(ctx, pc, ua, &tls.Config{ServerName: sni, NextProtos: []string{alpn},
		InsecureSkipVerify: h.AllowInsecure, MinVersion: tls.VersionTLS13}, hyQUICConfig())
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("hysteria: %w", err)
	}
	s := newHySession(qc, pc)
	fail := func(err error) (*hySession, error) {
		s.close()
		return nil, err
	}
	ctl, err := qc.OpenStreamSync(ctx)
	if err != nil {
		return fail(err)
	}
	stop := context.AfterFunc(ctx, func() { ctl.CancelRead(0); ctl.CancelWrite(0) })
	defer stop()

	up, down := h.UpMbps, h.DownMbps
	if up <= 0 {
		up = 10
	}
	if down <= 0 {
		down = 50
	}
	hello := []byte{3} // protocol version
	hello = binary.BigEndian.AppendUint64(hello, uint64(up)*125000)
	hello = binary.BigEndian.AppendUint64(hello, uint64(down)*125000)
	hello = binary.BigEndian.AppendUint16(hello, uint16(len(h.Auth)))
	hello = append(hello, h.Auth...)
	if _, err := ctl.Write(hello); err != nil {
		return fail(err)
	}
	var sh [1 + 8 + 8 + 2]byte
	if _, err := io.ReadFull(ctl, sh[:]); err != nil {
		return fail(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(sh[17:19]))
	if _, err := io.ReadFull(ctl, msg); err != nil {
		return fail(err)
	}
	if sh[0] != 1 {
		return fail(fmt.Errorf("hysteria: the server refused the connection: %s", msg))
	}
	s.ctl = ctl
	s.udp = true // a server with UDP disabled refuses the UDP request instead
	s.mux = newHyMux(qc, hy1Encode, hy1Decode, hy1Overhead)
	return s, nil
}

// request opens a data stream for target (typ 0 = TCP, 1 = UDP) and returns
// the stream and the UDP session id from the server's response.
func (h *Hysteria1) request(ctx context.Context, s *hySession, target string, typ byte) (*quic.Stream, uint32, bool, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, 0, false, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 0 || port > 65535 || len(host) > 65535 {
		return nil, 0, false, fmt.Errorf("hysteria: bad target %q", target)
	}
	st, err := s.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, 0, true, err
	}
	fail := func(err error) (*quic.Stream, uint32, bool, error) {
		st.CancelRead(0)
		st.CancelWrite(0)
		return nil, 0, false, err
	}
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()

	req := []byte{typ}
	req = binary.BigEndian.AppendUint16(req, uint16(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := st.Write(req); err != nil {
		return fail(err)
	}
	var rh [1 + 4 + 2]byte
	if _, err := io.ReadFull(st, rh[:]); err != nil {
		return fail(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(rh[5:7]))
	if _, err := io.ReadFull(st, msg); err != nil {
		return fail(err)
	}
	if rh[0] != 1 {
		return fail(fmt.Errorf("hysteria: the server refused %s: %s", target, msg))
	}
	return st, binary.BigEndian.Uint32(rh[1:5]), false, nil
}

// DialContext opens a TCP connection through the server.
func (h *Hysteria1) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		s, err := h.get(ctx, h.dial)
		if err != nil {
			return nil, err
		}
		st, _, retry, err := h.request(ctx, s, target, 0)
		if err == nil {
			return &hyStream{Stream: st, qc: s.qc}, nil
		}
		if !retry || attempt > 0 {
			return nil, err
		}
		h.drop(s) // the connection was stale: reconnect once
	}
}

// DialUDP opens a UDP session through the server (one Write = one packet).
func (h *Hysteria1) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	for attempt := 0; ; attempt++ {
		s, err := h.get(ctx, h.dial)
		if err != nil {
			return nil, err
		}
		st, sess, retry, err := h.request(ctx, s, target, 1)
		if err != nil {
			if !retry || attempt > 0 {
				return nil, err
			}
			h.drop(s)
			continue
		}
		// The data stream stays open for the life of the UDP session;
		// closing it ends the session on both sides.
		flow := s.mux.add(sess, target, func() { st.CancelRead(0); st.Close() })
		go func() {
			io.Copy(io.Discard, st)
			flow.Close()
		}()
		return flow, nil
	}
}

// UDP message: session id, host, port, message id, fragment id, fragment
// count, data length, data.
func hy1Encode(sess uint32, addr string, pkt uint16, fid, fcnt uint8, data []byte) []byte {
	host, ps, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(ps)
	b := make([]byte, 0, 20+len(host)+len(data))
	b = binary.BigEndian.AppendUint32(b, sess)
	b = binary.BigEndian.AppendUint16(b, uint16(len(host)))
	b = append(b, host...)
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	b = binary.BigEndian.AppendUint16(b, pkt)
	b = append(b, fid, fcnt)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func hy1Decode(b []byte) (sess uint32, pkt uint16, fid, fcnt uint8, data []byte, ok bool) {
	if len(b) < 6 {
		return
	}
	hl := int(binary.BigEndian.Uint16(b[4:6]))
	p := 6 + hl + 2 // past the host and the port: the message id starts here
	if len(b) < p+6 {
		return
	}
	dl := int(binary.BigEndian.Uint16(b[p+4 : p+6]))
	if len(b) < p+6+dl {
		return
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[p : p+2]), b[p+2], b[p+3], b[p+6 : p+6+dl], true
}

func hy1Overhead(addr string) int { return 14 + len(addr) }
