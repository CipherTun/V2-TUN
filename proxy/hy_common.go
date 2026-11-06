package proxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"io.surprise.vpn/transport"
)

// Shared pieces of the Hysteria 1 and Hysteria 2 clients. Both run over one
// long-lived QUIC connection: TCP is one bidirectional stream per connection,
// UDP rides on QUIC datagrams. Written against quic-go v0.65 (concrete
// *quic.Conn / *quic.Stream types). Neither client has Hysteria's "Brutal"
// congestion control (quic-go has no hook for it), so uploads use quic-go's
// default congestion control.

var (
	_ Outbound    = (*Hysteria2)(nil)
	_ UDPOutbound = (*Hysteria2)(nil)
	_ Outbound    = (*Hysteria1)(nil)
	_ UDPOutbound = (*Hysteria1)(nil)
)

// ---- QUIC variable-length integers (RFC 9000) ----

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return append(b, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(b, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// parseVarint returns the value and the number of bytes used (0 if b is too short).
func parseVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

func readVarint(r io.ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	for i := 1; i < n; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// byteReader reads exactly one byte at a time so nothing after a response
// header is consumed.
type byteReader struct{ r io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var x [1]byte
	_, err := io.ReadFull(b.r, x[:])
	return x[0], err
}

func hyRandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// hyPadding is a random alphanumeric string for the Hysteria-Padding header.
func hyPadding() string {
	const set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := hyRandBytes(64 + int(hyRandBytes(1)[0]))
	for i := range b {
		b[i] = set[int(b[i])%len(set)]
	}
	return string(b)
}

type hyAddr string

func (a hyAddr) Network() string { return "udp" }
func (a hyAddr) String() string  { return string(a) }

// ---- QUIC connection setup ----

func hyQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         8 << 20,
		InitialConnectionReceiveWindow: 20 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
	}
}

func hyResolve(ctx context.Context, rs *net.Resolver, addr string) (*net.UDPAddr, error) {
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
	if rs == nil {
		rs = net.DefaultResolver
	}
	ips, err := rs.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("hysteria: no address for %s", host)
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

// hyPacketConn opens a protected UDP socket (so it bypasses the VPN), wrapped
// by the obfuscator when there is one.
func hyPacketConn(ctx context.Context, obf func(net.PacketConn) net.PacketConn) (net.PacketConn, error) {
	pc, err := transport.ListenUDP(ctx)
	if err != nil {
		return nil, err
	}
	if obf != nil {
		return obf(pc), nil
	}
	return pc, nil
}

// hyStream is a QUIC stream used as a net.Conn.
type hyStream struct {
	*quic.Stream
	qc   *quic.Conn
	once sync.Once
}

func (s *hyStream) LocalAddr() net.Addr  { return s.qc.LocalAddr() }
func (s *hyStream) RemoteAddr() net.Addr { return s.qc.RemoteAddr() }
func (s *hyStream) Close() error {
	s.once.Do(func() {
		s.Stream.CancelRead(0)
		s.Stream.Close()
	})
	return nil
}

// ---- session: one QUIC connection plus its UDP multiplexer ----

type hySession struct {
	qc   *quic.Conn
	pc   net.PacketConn
	ctl  *quic.Stream // Hysteria 1 control stream, kept open for the connection's lifetime
	udp  bool
	mux  *hyMux
	once sync.Once
}

func newHySession(qc *quic.Conn, pc net.PacketConn) *hySession {
	s := &hySession{qc: qc, pc: pc}
	go func() { // free the socket when the connection dies on its own
		<-qc.Context().Done()
		s.close()
	}()
	return s
}

func (s *hySession) alive() bool {
	select {
	case <-s.qc.Context().Done():
		return false
	default:
		return true
	}
}

func (s *hySession) close() {
	s.once.Do(func() {
		s.qc.CloseWithError(0, "")
		s.pc.Close()
	})
}

// hyHolder keeps the current session and replaces it when it has died.
type hyHolder struct {
	mu sync.Mutex
	s  *hySession
}

func (h *hyHolder) get(ctx context.Context, dial func(context.Context) (*hySession, error)) (*hySession, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.s != nil && h.s.alive() {
		return h.s, nil
	}
	if h.s != nil {
		h.s.close()
		h.s = nil
	}
	s, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	h.s = s
	return s, nil
}

func (h *hyHolder) drop(s *hySession) {
	h.mu.Lock()
	if h.s == s {
		h.s = nil
	}
	h.mu.Unlock()
	s.close()
}

// Close shuts the QUIC connection down.
func (h *hyHolder) Close() error {
	h.mu.Lock()
	s := h.s
	h.s = nil
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
	return nil
}

// ---- UDP over QUIC datagrams ----

// hyDatagramBudget keeps every datagram well below QUIC's smallest datagram
// limit (about 1200 bytes); larger UDP packets are split into fragments.
const hyDatagramBudget = 1100

type hyMux struct {
	qc       *quic.Conn
	encode   func(sess uint32, addr string, pkt uint16, fid, fcnt uint8, data []byte) []byte
	decode   func(b []byte) (sess uint32, pkt uint16, fid, fcnt uint8, data []byte, ok bool)
	overhead func(addr string) int // header bytes in front of the data
	ids      atomic.Uint32

	mu    sync.Mutex
	flows map[uint32]*hyFlow
}

func newHyMux(qc *quic.Conn,
	encode func(uint32, string, uint16, uint8, uint8, []byte) []byte,
	decode func([]byte) (uint32, uint16, uint8, uint8, []byte, bool),
	overhead func(string) int) *hyMux {
	m := &hyMux{qc: qc, encode: encode, decode: decode, overhead: overhead, flows: map[uint32]*hyFlow{}}
	go m.run()
	return m
}

func (m *hyMux) nextID() uint32 { return m.ids.Add(1) }

func (m *hyMux) run() {
	for {
		b, err := m.qc.ReceiveDatagram(m.qc.Context())
		if err != nil {
			m.mu.Lock()
			for _, f := range m.flows {
				f.stop()
			}
			m.mu.Unlock()
			return
		}
		sess, pkt, fid, fcnt, data, ok := m.decode(b)
		if !ok {
			continue
		}
		m.mu.Lock()
		f := m.flows[sess]
		m.mu.Unlock()
		if f != nil {
			f.deliver(pkt, fid, fcnt, data)
		}
	}
}

func (m *hyMux) add(sess uint32, addr string, onClose func()) *hyFlow {
	f := &hyFlow{m: m, id: sess, addr: addr, rq: make(chan []byte, 128), done: make(chan struct{}),
		frags: map[uint16]*hyFrag{}, onClose: onClose}
	m.mu.Lock()
	m.flows[sess] = f
	m.mu.Unlock()
	return f
}

type hyFrag struct {
	parts [][]byte
	got   int
	at    time.Time
}

// hyFlow is one UDP session as a datagram net.Conn: one Write is one packet,
// one Read returns one packet.
type hyFlow struct {
	m       *hyMux
	id      uint32
	addr    string
	rq      chan []byte
	done    chan struct{}
	stopO   sync.Once
	closeO  sync.Once
	onClose func()
	pkt     atomic.Uint32

	fmu   sync.Mutex
	frags map[uint16]*hyFrag
}

func (f *hyFlow) stop() { f.stopO.Do(func() { close(f.done) }) }

func (f *hyFlow) push(b []byte) {
	select {
	case f.rq <- b:
	default: // reader too slow: drop, like real UDP
	}
}

// deliver takes one datagram, reassembling fragmented packets.
func (f *hyFlow) deliver(pkt uint16, fid, fcnt uint8, data []byte) {
	if fcnt <= 1 {
		f.push(append([]byte(nil), data...))
		return
	}
	if fid >= fcnt {
		return
	}
	f.fmu.Lock()
	defer f.fmu.Unlock()
	fr := f.frags[pkt]
	if fr == nil || len(fr.parts) != int(fcnt) {
		if len(f.frags) >= 16 { // forget the oldest incomplete packet
			var oldest uint16
			var ot time.Time
			first := true
			for k, v := range f.frags {
				if first || v.at.Before(ot) {
					oldest, ot, first = k, v.at, false
				}
			}
			delete(f.frags, oldest)
		}
		fr = &hyFrag{parts: make([][]byte, fcnt), at: time.Now()}
		f.frags[pkt] = fr
	}
	if fr.parts[fid] == nil {
		part := make([]byte, len(data)) // non-nil even when empty
		copy(part, data)
		fr.parts[fid] = part
		fr.got++
	}
	if fr.got == len(fr.parts) {
		delete(f.frags, pkt)
		var all []byte
		for _, p := range fr.parts {
			all = append(all, p...)
		}
		f.push(all)
	}
}

func (f *hyFlow) Write(p []byte) (int, error) {
	select {
	case <-f.done:
		return 0, io.ErrClosedPipe
	default:
	}
	room := hyDatagramBudget - f.m.overhead(f.addr)
	if room < 200 {
		room = 200
	}
	pkt := uint16(f.pkt.Add(1))
	count := (len(p) + room - 1) / room
	if count == 0 {
		count = 1
	}
	if count > 255 {
		return 0, errors.New("hysteria: UDP packet too large")
	}
	for i := 0; i < count; i++ {
		lo := i * room
		hi := lo + room
		if hi > len(p) {
			hi = len(p)
		}
		if err := f.m.qc.SendDatagram(f.m.encode(f.id, f.addr, pkt, uint8(i), uint8(count), p[lo:hi])); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (f *hyFlow) Read(p []byte) (int, error) {
	select {
	case b := <-f.rq:
		return copy(p, b), nil
	case <-f.done:
		select {
		case b := <-f.rq:
			return copy(p, b), nil
		default:
			return 0, io.EOF
		}
	}
}

func (f *hyFlow) Close() error {
	f.closeO.Do(func() {
		f.stop()
		f.m.mu.Lock()
		delete(f.m.flows, f.id)
		f.m.mu.Unlock()
		if f.onClose != nil {
			f.onClose()
		}
	})
	return nil
}

func (f *hyFlow) LocalAddr() net.Addr                { return f.m.qc.LocalAddr() }
func (f *hyFlow) RemoteAddr() net.Addr               { return hyAddr(f.addr) }
func (f *hyFlow) SetDeadline(time.Time) error      { return nil }
func (f *hyFlow) SetReadDeadline(time.Time) error  { return nil }
func (f *hyFlow) SetWriteDeadline(time.Time) error { return nil }
