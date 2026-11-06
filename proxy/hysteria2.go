package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"io.surprise.vpn/transport"
)

// Hysteria2 is a Hysteria 2 client (protocol spec: v2.hysteria.network, "v4").
// The QUIC connection authenticates with an HTTP/3 POST /auth (status 233),
// then every TCP connection is a bidirectional stream (TCPRequest 0x401) and
// UDP rides on QUIC datagrams. It brings its own QUIC/TLS, so the payload,
// TLS and transport layers of a config do not apply.
// Not covered: port hopping, and Brutal congestion control.
type Hysteria2 struct {
	Server        string // host:port
	Password      string // the Hysteria-Auth value ("user:pass" for userpass servers)
	SNI           string // default: the server host
	AllowInsecure bool
	PinSHA256     string // hex SHA-256 of the server certificate; replaces CA verification
	Obfs          string // Salamander password; empty => none
	DownMbps      int    // advertised receive rate; 0 lets the server decide
	Resolver      *net.Resolver

	hyHolder
}

func (h *Hysteria2) dial(ctx context.Context) (*hySession, error) {
	ua, err := hyResolve(ctx, h.Resolver, h.Server)
	if err != nil {
		return nil, err
	}
	var obf func(net.PacketConn) net.PacketConn
	if h.Obfs != "" {
		key := []byte(h.Obfs)
		obf = func(pc net.PacketConn) net.PacketConn { return transport.NewSalamander(pc, key) }
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
	tc := &tls.Config{ServerName: sni, InsecureSkipVerify: h.AllowInsecure, MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3}}
	if h.PinSHA256 != "" {
		want := strings.ToLower(strings.ReplaceAll(h.PinSHA256, ":", ""))
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("hysteria2: the server sent no certificate")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != want {
				return errors.New("hysteria2: the server certificate does not match pinSHA256")
			}
			return nil
		}
	}

	// The HTTP/3 layer only authenticates. QUIC datagrams are enabled on the
	// QUIC config; HTTP/3 datagram handling stays off so that it does not
	// compete with us for the datagrams.
	var qc *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: tc,
		QUICConfig:      hyQUICConfig(),
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			c, err := quic.Dial(ctx, pc, ua, tlsCfg, hyQUICConfig())
			if err != nil {
				return nil, err
			}
			qc = c
			return c, nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	rx := uint64(0)
	if h.DownMbps > 0 {
		rx = uint64(h.DownMbps) * 125000 // Mbit/s -> bytes/s
	}
	req.Header.Set("Hysteria-Auth", h.Password)
	req.Header.Set("Hysteria-CC-RX", strconv.FormatUint(rx, 10))
	req.Header.Set("Hysteria-Padding", hyPadding())
	resp, err := rt.RoundTrip(req)
	if err != nil {
		if qc != nil {
			qc.CloseWithError(0, "")
		}
		pc.Close()
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if resp.StatusCode != 233 {
		qc.CloseWithError(3, "authentication failed")
		pc.Close()
		return nil, fmt.Errorf("hysteria2: authentication failed (status %d)", resp.StatusCode)
	}
	s := newHySession(qc, pc)
	s.udp = strings.EqualFold(resp.Header.Get("Hysteria-UDP"), "true")
	if s.udp {
		s.mux = newHyMux(qc, hy2Encode, hy2Decode, hy2Overhead)
	}
	return s, nil
}

// DialContext opens a TCP connection through the server.
func (h *Hysteria2) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if _, err := parseTarget(target); err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		s, err := h.get(ctx, h.dial)
		if err != nil {
			return nil, err
		}
		c, retry, err := h.open(ctx, s, target)
		if err == nil {
			return c, nil
		}
		if !retry || attempt > 0 {
			return nil, err
		}
		h.drop(s) // the connection was stale: reconnect once
	}
}

func (h *Hysteria2) open(ctx context.Context, s *hySession, target string) (net.Conn, bool, error) {
	st, err := s.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, true, err
	}
	fail := func(err error) (net.Conn, bool, error) {
		st.CancelRead(0)
		st.CancelWrite(0)
		return nil, false, err
	}
	stop := context.AfterFunc(ctx, func() { st.CancelRead(0); st.CancelWrite(0) })
	defer stop()

	pad := hyRandBytes(int(hyRandBytes(1)[0]) % 64)
	req := appendVarint(nil, 0x401)
	req = appendVarint(req, uint64(len(target)))
	req = append(req, target...)
	req = appendVarint(req, uint64(len(pad)))
	req = append(req, pad...)
	if _, err := st.Write(req); err != nil {
		return fail(err)
	}

	// TCPResponse: status, message, padding
	br := byteReader{st}
	status, err := br.ReadByte()
	if err != nil {
		return fail(err)
	}
	ml, err := readVarint(br)
	if err != nil || ml > 2048 {
		return fail(errors.New("hysteria2: bad TCP response"))
	}
	msg := make([]byte, ml)
	if _, err := io.ReadFull(st, msg); err != nil {
		return fail(err)
	}
	pl, err := readVarint(br)
	if err != nil || pl > 4096 {
		return fail(errors.New("hysteria2: bad TCP response"))
	}
	if _, err := io.CopyN(io.Discard, st, int64(pl)); err != nil {
		return fail(err)
	}
	if status != 0 {
		return fail(fmt.Errorf("hysteria2: the server refused %s: %s", target, msg))
	}
	return &hyStream{Stream: st, qc: s.qc}, false, nil
}

// DialUDP opens a UDP session through the server (one Write = one packet).
func (h *Hysteria2) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	if _, err := parseTarget(target); err != nil {
		return nil, err
	}
	s, err := h.get(ctx, h.dial)
	if err != nil {
		return nil, err
	}
	if !s.udp || s.mux == nil {
		return nil, errors.New("hysteria2: the server has UDP relay disabled")
	}
	return s.mux.add(s.mux.nextID(), target, nil), nil
}

// UDPMessage: session id, packet id, fragment id, fragment count, varint
// address length, address (host:port), payload.
func hy2Encode(sess uint32, addr string, pkt uint16, fid, fcnt uint8, data []byte) []byte {
	b := make([]byte, 0, 12+len(addr)+len(data))
	b = binary.BigEndian.AppendUint32(b, sess)
	b = binary.BigEndian.AppendUint16(b, pkt)
	b = append(b, fid, fcnt)
	b = appendVarint(b, uint64(len(addr)))
	b = append(b, addr...)
	return append(b, data...)
}

func hy2Decode(b []byte) (sess uint32, pkt uint16, fid, fcnt uint8, data []byte, ok bool) {
	if len(b) < 9 {
		return
	}
	n, k := parseVarint(b[8:])
	if k == 0 {
		return
	}
	rest := b[8+k:]
	if uint64(len(rest)) < n {
		return
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[4:6]), b[6], b[7], rest[n:], true
}

func hy2Overhead(addr string) int { return 8 + 2 + len(addr) }
