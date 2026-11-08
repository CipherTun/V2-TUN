package transport

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// mKCP client transport, wire-compatible with the v2ray/Xray "kcp" network:
//   - packet = [header mimic][auth/encryption][segments...]
//   - no seed  => classic SimpleAuthenticator (FNV32a + 4-byte XOR chain)
//   - seed set => AES-128-GCM, key = sha256(seed)[:16], 12-byte nonce prepended
//   - header   => none|srtp|utp|wechat-video|dtls|wireguard (only the size matters to the peer)
// Like QUIC it is a base transport (replaces TCP): one KCP conversation per dial.

const (
	kcpCmdACK       = 0
	kcpCmdData      = 1
	kcpCmdTerminate = 2
	kcpCmdPing      = 3

	kcpOptClose = 1

	kcpDataHdr    = 18 // conv2 cmd1 opt1 ts4 num4 sendingNext4 len2
	kcpAckHdr     = 17 // conv2 cmd1 opt1 window4 recvNext4 ts4 count1 (+4*count)
	kcpCmdOnlyLen = 16 // conv2 cmd1 opt1 sendingNext4 recvNext4 peerRTO4

	kcpIdleTimeout = 30 * time.Second
	kcpPingEvery   = 3 * time.Second
	kcpCloseDrain  = 2 * time.Second
)

var (
	errKCPTimeout = errors.New("kcp: connection timed out")
	errKCPShort   = errors.New("kcp: short packet")
	errKCPAuth    = errors.New("kcp: invalid packet auth")
)

// ---------- security ----------

type kcpSecurity interface {
	Overhead() int // total bytes added per packet (nonce + tag included)
	Seal(plain []byte) []byte
	Open(packet []byte) ([]byte, error)
}

// kcpSimple is the classic authenticator used when no seed is configured.
type kcpSimple struct{}

func (kcpSimple) Overhead() int { return 4 }

func (kcpSimple) Seal(plain []byte) []byte {
	out := make([]byte, 4+len(plain))
	copy(out[4:], plain)
	h := fnv.New32a()
	h.Write(plain)
	binary.BigEndian.PutUint32(out, h.Sum32())
	for i := 4; i < len(out); i++ {
		out[i] ^= out[i-4]
	}
	return out
}

func (kcpSimple) Open(p []byte) ([]byte, error) {
	if len(p) < 4 {
		return nil, errKCPShort
	}
	x := append([]byte(nil), p...)
	for i := len(x) - 1; i >= 4; i-- {
		x[i] ^= x[i-4]
	}
	h := fnv.New32a()
	h.Write(x[4:])
	if binary.BigEndian.Uint32(x) != h.Sum32() {
		return nil, errKCPAuth
	}
	return x[4:], nil
}

// kcpGCM is the seed mode.
type kcpGCM struct{ aead cipher.AEAD }

func (g kcpGCM) Overhead() int { return g.aead.NonceSize() + g.aead.Overhead() }

func (g kcpGCM) Seal(plain []byte) []byte {
	ns := g.aead.NonceSize()
	out := make([]byte, ns, ns+len(plain)+g.aead.Overhead())
	rand.Read(out)
	return g.aead.Seal(out, out[:ns], plain, nil)
}

func (g kcpGCM) Open(p []byte) ([]byte, error) {
	ns := g.aead.NonceSize()
	if len(p) < ns+g.aead.Overhead() {
		return nil, errKCPShort
	}
	return g.aead.Open(nil, p[:ns], p[ns:], nil)
}

func newKCPSecurity(seed string) kcpSecurity {
	if seed == "" {
		return kcpSimple{}
	}
	k := sha256.Sum256([]byte(seed))
	blk, _ := aes.NewCipher(k[:16])
	g, _ := cipher.NewGCM(blk)
	return kcpGCM{g}
}

// ---------- header mimicry ----------

type kcpHeader interface {
	Size() int
	Serialize(b []byte)
}

type kcpNoHeader struct{}

func (kcpNoHeader) Size() int         { return 0 }
func (kcpNoHeader) Serialize([]byte) {}

type kcpMimic struct {
	kind string
	seq  uint32
	id   uint16
}

func (h *kcpMimic) Size() int {
	switch h.kind {
	case "srtp", "utp", "wireguard":
		return 4
	default: // wechat-video, dtls
		return 13
	}
}

func (h *kcpMimic) Serialize(b []byte) {
	h.seq++
	switch h.kind {
	case "srtp":
		b[0], b[1] = 0xB5, 0xE8
		binary.BigEndian.PutUint16(b[2:], uint16(h.seq))
	case "utp":
		binary.BigEndian.PutUint16(b, h.id)
		b[2], b[3] = 1, 0
	case "wireguard":
		b[0], b[1], b[2], b[3] = 4, 0, 0, 0
	case "wechat-video":
		b[0], b[1] = 0xa1, 0x08
		binary.BigEndian.PutUint32(b[2:], h.seq)
		copy(b[6:], []byte{0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30})
	case "dtls":
		b[0], b[1], b[2], b[3], b[4] = 23, 254, 253, 0, 1
		b[5], b[6] = 0, 0
		binary.BigEndian.PutUint32(b[7:], h.seq)
		b[11], b[12] = 0, 0
	}
}

func newKCPHeader(name string) (kcpHeader, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "", "none":
		return kcpNoHeader{}, nil
	case "wechat", "video":
		n = "wechat-video"
	case "srtp", "utp", "wireguard", "wechat-video", "dtls":
	default:
		return nil, errors.New("kcp: unknown header type " + name)
	}
	var r [2]byte
	rand.Read(r[:])
	return &kcpMimic{kind: n, id: binary.BigEndian.Uint16(r[:]), seq: uint32(binary.BigEndian.Uint16(r[:]))}, nil
}

// ---------- dialer ----------

// KCP is a base transport (replaces TCP). Zero values pick the Xray defaults.
type KCP struct {
	MTU              int // 576..1460, default 1350
	TTI              int // ms, 10..100, default 50
	UplinkCapacity   int // MB/s, default 5
	DownlinkCapacity int // MB/s, default 20
	Congestion       bool
	ReadBufferSize   int // MB, default 2
	WriteBufferSize  int // MB, default 2
	Header           string
	Seed             string
	Resolver         *net.Resolver // protected resolver for the server name; nil => shared resolver
}

type kcpParams struct {
	mtu, tti   int
	inflight   int // max unacked segments (sender)
	rcvWin     int // receive window in segments
	congestion bool
	wBuf       int // bytes
}

func kcpClamp(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (d *KCP) params() kcpParams {
	mtu := kcpClamp(d.MTU, 576, 1460, 1350)
	tti := kcpClamp(d.TTI, 10, 100, 50)
	up := kcpClamp(d.UplinkCapacity, 1, 1000, 5)
	down := kcpClamp(d.DownlinkCapacity, 1, 1000, 20)
	rb := kcpClamp(d.ReadBufferSize, 1, 256, 2)
	wb := kcpClamp(d.WriteBufferSize, 1, 256, 2)
	perTTI := func(mb int) int {
		n := mb * 1048576 / 1000 * tti / mtu
		if n < 32 {
			n = 32
		}
		return n
	}
	rw := perTTI(down)
	if m := rb * 1048576 / mtu; rw > m {
		rw = m
	}
	return kcpParams{mtu: mtu, tti: tti, inflight: perTTI(up), rcvWin: rw,
		congestion: d.Congestion, wBuf: wb * 1048576}
}

func (d *KCP) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var ua *net.UDPAddr
	var err error
	if d.Resolver != nil {
		ua, err = (&QUIC{Resolver: d.Resolver}).resolve(ctx, addr)
	} else {
		ua, err = ResolveUDPAddr(ctx, addr)
	}
	if err != nil {
		return nil, err
	}
	hdr, err := newKCPHeader(d.Header)
	if err != nil {
		return nil, err
	}
	pc, err := (&net.ListenConfig{Control: controlFn}).ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}
	var cb [2]byte
	rand.Read(cb[:])
	return newKCPConn(pc, ua, binary.BigEndian.Uint16(cb[:]), d.params(), newKCPSecurity(d.Seed), hdr), nil
}

// ---------- connection ----------

type kcpSeg struct {
	num    uint32
	data   []byte
	sentAt time.Time
	rto    time.Duration
	xmit   int
	skip   int
}

type kcpConn struct {
	pc      net.PacketConn
	remote  net.Addr
	cfg     kcpParams
	sec     kcpSecurity
	hdr     kcpHeader
	hdrSize int
	mss     int
	conv    uint16
	start   time.Time

	done                    chan struct{}
	kick, readSig, writeSig chan struct{}

	mu        sync.Mutex
	sndQ      [][]byte
	inflight  []*kcpSeg
	sndNext   uint32
	sndUna    uint32
	peerLimit uint32
	pending   int
	cwnd      int

	rcvNext  uint32
	rcvBuf   map[uint32][]byte
	rcvReady []byte
	ackList  []uint32
	lastTS   uint32

	srtt, rttvar       time.Duration
	lastRecv, lastPing time.Time

	closed, closing, peerClosed, finished bool
	closeAt                               time.Time
	err                                   error
	rdl, wdl                              time.Time
}

func newKCPConn(pc net.PacketConn, remote net.Addr, conv uint16, p kcpParams, sec kcpSecurity, hdr kcpHeader) *kcpConn {
	now := time.Now()
	c := &kcpConn{pc: pc, remote: remote, cfg: p, sec: sec, hdr: hdr, hdrSize: hdr.Size(), conv: conv,
		start: now, lastRecv: now, peerLimit: 32, cwnd: 16, rcvBuf: map[uint32][]byte{},
		done: make(chan struct{}), kick: make(chan struct{}, 1),
		readSig: make(chan struct{}, 1), writeSig: make(chan struct{}, 1)}
	c.mss = p.mtu - c.hdrSize - sec.Overhead() - kcpDataHdr
	go c.recvLoop()
	go c.updateLoop()
	return c
}

func kcpNudge(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (c *kcpConn) ms(t time.Time) uint32 { return uint32(t.Sub(c.start) / time.Millisecond) }

func kcpSameAddr(a, b net.Addr) bool {
	ua, ok1 := a.(*net.UDPAddr)
	ub, ok2 := b.(*net.UDPAddr)
	if ok1 && ok2 {
		return ua.Port == ub.Port && ua.IP.Equal(ub.IP)
	}
	return a.String() == b.String()
}

// ---------- serialization ----------

func kcpDataSeg(conv uint16, opt byte, ts, num, sn uint32, payload []byte) []byte {
	b := make([]byte, kcpDataHdr+len(payload))
	binary.BigEndian.PutUint16(b, conv)
	b[2], b[3] = kcpCmdData, opt
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], num)
	binary.BigEndian.PutUint32(b[12:], sn)
	binary.BigEndian.PutUint16(b[16:], uint16(len(payload)))
	copy(b[kcpDataHdr:], payload)
	return b
}

func kcpAckSeg(conv uint16, opt byte, window, recvNext, ts uint32, nums []uint32) []byte {
	b := make([]byte, kcpAckHdr+4*len(nums))
	binary.BigEndian.PutUint16(b, conv)
	b[2], b[3] = kcpCmdACK, opt
	binary.BigEndian.PutUint32(b[4:], window)
	binary.BigEndian.PutUint32(b[8:], recvNext)
	binary.BigEndian.PutUint32(b[12:], ts)
	b[16] = byte(len(nums))
	for i, n := range nums {
		binary.BigEndian.PutUint32(b[kcpAckHdr+4*i:], n)
	}
	return b
}

func kcpCmdSeg(conv uint16, cmd, opt byte, sn, rn, rto uint32) []byte {
	b := make([]byte, kcpCmdOnlyLen)
	binary.BigEndian.PutUint16(b, conv)
	b[2], b[3] = cmd, opt
	binary.BigEndian.PutUint32(b[4:], sn)
	binary.BigEndian.PutUint32(b[8:], rn)
	binary.BigEndian.PutUint32(b[12:], rto)
	return b
}

type kcpPacker struct {
	c   *kcpConn
	max int
	buf []byte
	out [][]byte
}

func (p *kcpPacker) add(seg []byte) {
	if len(p.buf) > 0 && len(p.buf)+len(seg) > p.max {
		p.flush()
	}
	p.buf = append(p.buf, seg...)
}

func (p *kcpPacker) flush() {
	if len(p.buf) == 0 {
		return
	}
	body := p.c.sec.Seal(p.buf)
	out := make([]byte, p.c.hdrSize+len(body))
	p.c.hdr.Serialize(out[:p.c.hdrSize])
	copy(out[p.c.hdrSize:], body)
	p.out = append(p.out, out)
	p.buf = p.buf[:0]
}

// ---------- receive path ----------

func (c *kcpConn) recvLoop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			c.finish(err)
			return
		}
		if !kcpSameAddr(from, c.remote) {
			continue
		}
		c.input(buf[:n])
	}
}

func (c *kcpConn) input(pkt []byte) {
	if len(pkt) <= c.hdrSize {
		return
	}
	plain, err := c.sec.Open(pkt[c.hdrSize:])
	if err != nil {
		return
	}
	now := time.Now()
	terminated := false
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	c.lastRecv = now
	for b := plain; len(b) >= 4; {
		n, term := c.segment(b, now)
		if n == 0 {
			break
		}
		if term {
			terminated = true
		}
		b = b[n:]
	}
	c.mu.Unlock()
	if terminated {
		kcpNudge(c.readSig)
		c.finish(nil)
	}
}

func (c *kcpConn) segment(b []byte, now time.Time) (int, bool) {
	if binary.BigEndian.Uint16(b) != c.conv {
		return 0, false
	}
	cmd := b[2]
	switch cmd {
	case kcpCmdData:
		if len(b) < kcpDataHdr {
			return 0, false
		}
		ts := binary.BigEndian.Uint32(b[4:])
		num := binary.BigEndian.Uint32(b[8:])
		l := int(binary.BigEndian.Uint16(b[16:]))
		if len(b) < kcpDataHdr+l {
			return 0, false
		}
		c.onData(ts, num, b[kcpDataHdr:kcpDataHdr+l])
		return kcpDataHdr + l, false
	case kcpCmdACK:
		if len(b) < kcpAckHdr {
			return 0, false
		}
		win := binary.BigEndian.Uint32(b[4:])
		rn := binary.BigEndian.Uint32(b[8:])
		ts := binary.BigEndian.Uint32(b[12:])
		cnt := int(b[16])
		if len(b) < kcpAckHdr+4*cnt {
			return 0, false
		}
		nums := make([]uint32, cnt)
		for i := range nums {
			nums[i] = binary.BigEndian.Uint32(b[kcpAckHdr+4*i:])
		}
		c.onAck(now, win, rn, ts, nums)
		return kcpAckHdr + 4*cnt, false
	case kcpCmdPing, kcpCmdTerminate:
		if len(b) < kcpCmdOnlyLen {
			return 0, false
		}
		if k := c.removeBelow(binary.BigEndian.Uint32(b[8:])); k > 0 {
			c.updateUna()
			kcpNudge(c.writeSig)
		}
		if cmd == kcpCmdTerminate {
			c.peerClosed = true
			return kcpCmdOnlyLen, true
		}
		return kcpCmdOnlyLen, false
	}
	return 0, false
}

func (c *kcpConn) onData(ts, num uint32, payload []byte) {
	c.lastTS = ts
	if num < c.rcvNext { // duplicate: our ack was probably lost
		c.ackList = append(c.ackList, num)
		return
	}
	if num >= c.rcvNext+uint32(c.cfg.rcvWin) {
		return
	}
	c.ackList = append(c.ackList, num)
	if _, ok := c.rcvBuf[num]; ok {
		return
	}
	c.rcvBuf[num] = append([]byte(nil), payload...)
	got := false
	for {
		d, ok := c.rcvBuf[c.rcvNext]
		if !ok {
			break
		}
		delete(c.rcvBuf, c.rcvNext)
		c.rcvReady = append(c.rcvReady, d...)
		c.rcvNext++
		got = true
	}
	if got {
		kcpNudge(c.readSig)
	}
}

func (c *kcpConn) onAck(now time.Time, win, rn, ts uint32, nums []uint32) {
	if win < rn { // tolerate a relative window
		win += rn
	}
	if win > c.peerLimit {
		c.peerLimit = win
	}
	k := c.removeBelow(rn)
	k += c.removeAcked(nums)
	if k > 0 {
		if d := c.ms(now) - ts; d < 60000 {
			c.sampleRTT(time.Duration(d) * time.Millisecond)
		}
		if c.cfg.congestion {
			c.cwnd += k
		}
		c.updateUna()
		kcpNudge(c.writeSig)
		kcpNudge(c.kick)
	}
}

func (c *kcpConn) removeBelow(n uint32) int {
	i := 0
	for i < len(c.inflight) && c.inflight[i].num < n {
		c.pending -= len(c.inflight[i].data)
		i++
	}
	c.inflight = c.inflight[i:]
	return i
}

func (c *kcpConn) removeAcked(nums []uint32) int {
	if len(nums) == 0 || len(c.inflight) == 0 {
		return 0
	}
	set := make(map[uint32]struct{}, len(nums))
	var maxN uint32
	for _, n := range nums {
		set[n] = struct{}{}
		if n > maxN {
			maxN = n
		}
	}
	k := 0
	keep := c.inflight[:0]
	for _, s := range c.inflight {
		if _, ok := set[s.num]; ok {
			c.pending -= len(s.data)
			k++
			continue
		}
		if s.num < maxN {
			s.skip++
		}
		keep = append(keep, s)
	}
	c.inflight = keep
	return k
}

func (c *kcpConn) updateUna() {
	if len(c.inflight) > 0 {
		c.sndUna = c.inflight[0].num
	} else {
		c.sndUna = c.sndNext
	}
}

func (c *kcpConn) sampleRTT(r time.Duration) {
	if c.srtt == 0 {
		c.srtt, c.rttvar = r, r/2
		return
	}
	d := c.srtt - r
	if d < 0 {
		d = -d
	}
	c.rttvar = (3*c.rttvar + d) / 4
	c.srtt = (7*c.srtt + r) / 8
}

func (c *kcpConn) baseRTO() time.Duration {
	if c.srtt == 0 {
		return 400 * time.Millisecond
	}
	tti := time.Duration(c.cfg.tti) * time.Millisecond
	v := 4 * c.rttvar
	if v < 2*tti {
		v = 2 * tti
	}
	r := c.srtt + v
	if r < 100*time.Millisecond {
		r = 100 * time.Millisecond
	}
	if r > 3*time.Second {
		r = 3 * time.Second
	}
	return r
}

func (c *kcpConn) rcvWindowAbs() uint32 {
	free := c.cfg.rcvWin - len(c.rcvBuf) - len(c.rcvReady)/c.mss
	if free < 1 {
		free = 1
	}
	return c.rcvNext + uint32(free)
}

func (c *kcpConn) window() int {
	w := c.cfg.inflight
	if c.cfg.congestion && c.cwnd < w {
		w = c.cwnd
	}
	return w
}

// ---------- send path ----------

func (c *kcpConn) updateLoop() {
	t := time.NewTicker(time.Duration(c.cfg.tti) * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-c.kick:
		case <-c.done:
			return
		}
		c.flush()
	}
}

func (c *kcpConn) flush() {
	now := time.Now()
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	p := &kcpPacker{c: c, max: c.cfg.mtu - c.hdrSize - c.sec.Overhead()}
	var optc byte
	if c.closing {
		optc = kcpOptClose
	}
	var fin error
	finish := false

	if now.Sub(c.lastRecv) > kcpIdleTimeout {
		fin, finish = errKCPTimeout, true
	} else {
		ts := c.ms(now)
		c.updateUna()

		per := (p.max - kcpAckHdr) / 4
		if per > 255 {
			per = 255
		}
		if per < 1 {
			per = 1
		}
		for len(c.ackList) > 0 {
			n := len(c.ackList)
			if n > per {
				n = per
			}
			p.add(kcpAckSeg(c.conv, optc, c.rcvWindowAbs(), c.rcvNext, c.lastTS, c.ackList[:n]))
			c.ackList = c.ackList[n:]
		}

		limit := c.sndUna + uint32(c.window())
		if c.peerLimit < limit {
			limit = c.peerLimit
		}
		for len(c.sndQ) > 0 && c.sndNext < limit {
			c.inflight = append(c.inflight, &kcpSeg{num: c.sndNext, data: c.sndQ[0]})
			c.sndQ[0] = nil
			c.sndQ = c.sndQ[1:]
			c.sndNext++
		}

		for _, s := range c.inflight {
			send := false
			switch {
			case s.xmit == 0:
				send = true
				s.rto = c.baseRTO()
			case now.Sub(s.sentAt) >= s.rto:
				send = true
				s.rto += s.rto / 2
				if s.rto > 4*time.Second {
					s.rto = 4 * time.Second
				}
				c.onLoss()
			case s.skip >= 3:
				send = true
				c.onLoss()
			}
			if send {
				s.xmit++
				s.skip = 0
				s.sentAt = now
				p.add(kcpDataSeg(c.conv, optc, ts, s.num, c.sndUna, s.data))
			}
		}

		if now.Sub(c.lastPing) >= kcpPingEvery {
			c.lastPing = now
			p.add(kcpCmdSeg(c.conv, kcpCmdPing, optc, c.sndUna, c.rcvNext, uint32(c.baseRTO()/time.Millisecond)))
		}

		if c.closing && ((len(c.sndQ) == 0 && len(c.inflight) == 0) || now.After(c.closeAt)) {
			finish = true
			p.add(kcpCmdSeg(c.conv, kcpCmdTerminate, optc, c.sndUna, c.rcvNext, 0))
		}
	}
	p.flush()
	if finish && fin == nil {
		if n := len(p.out); n > 0 { // terminate is cheap; send it three times
			p.out = append(p.out, p.out[n-1], p.out[n-1])
		}
	}
	out := p.out
	c.mu.Unlock()

	for _, b := range out {
		c.pc.WriteTo(b, c.remote)
	}
	if finish {
		c.finish(fin)
	}
}

func (c *kcpConn) onLoss() {
	if c.cfg.congestion {
		c.cwnd /= 2
		if c.cwnd < 8 {
			c.cwnd = 8
		}
	}
}

func (c *kcpConn) finish(err error) {
	c.mu.Lock()
	if c.finished {
		c.mu.Unlock()
		return
	}
	c.finished = true
	if err != nil && c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	close(c.done)
	c.pc.Close()
	kcpNudge(c.readSig)
	kcpNudge(c.writeSig)
}

// ---------- net.Conn ----------

func (c *kcpConn) wait(sig chan struct{}, dl time.Time) error {
	var tc <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		tc = t.C
	}
	select {
	case <-sig:
	case <-tc:
		return os.ErrDeadlineExceeded
	case <-c.done:
	}
	return nil
}

func (c *kcpConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.rcvReady) > 0 {
			n := copy(p, c.rcvReady)
			c.rcvReady = c.rcvReady[n:]
			if len(c.rcvReady) == 0 {
				c.rcvReady = nil
			}
			c.mu.Unlock()
			return n, nil
		}
		switch {
		case c.peerClosed:
			c.mu.Unlock()
			return 0, io.EOF
		case c.closed:
			c.mu.Unlock()
			return 0, net.ErrClosed
		case c.err != nil:
			err := c.err
			c.mu.Unlock()
			return 0, err
		case c.finished:
			c.mu.Unlock()
			return 0, io.ErrClosedPipe
		}
		dl := c.rdl
		c.mu.Unlock()
		if err := c.wait(c.readSig, dl); err != nil {
			return 0, err
		}
	}
}

func (c *kcpConn) Write(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		c.mu.Lock()
		switch {
		case c.closed:
			c.mu.Unlock()
			return n, net.ErrClosed
		case c.peerClosed || c.finished:
			err := c.err
			c.mu.Unlock()
			if err == nil {
				err = io.ErrClosedPipe
			}
			return n, err
		}
		pushed := false
		for n < len(b) && c.pending < c.cfg.wBuf {
			k := len(b) - n
			if k > c.mss {
				k = c.mss
			}
			chunk := make([]byte, k)
			copy(chunk, b[n:n+k])
			c.sndQ = append(c.sndQ, chunk)
			c.pending += k
			n += k
			pushed = true
		}
		dl := c.wdl
		c.mu.Unlock()
		if pushed {
			kcpNudge(c.kick)
		}
		if n < len(b) {
			if err := c.wait(c.writeSig, dl); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}

// Close stops reads/writes immediately and lets queued data drain (up to 2s)
// before the terminate packets go out.
func (c *kcpConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed, c.closing = true, true
	c.closeAt = time.Now().Add(kcpCloseDrain)
	fin := c.finished
	c.mu.Unlock()
	kcpNudge(c.readSig)
	kcpNudge(c.writeSig)
	if !fin {
		kcpNudge(c.kick)
	}
	return nil
}

func (c *kcpConn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *kcpConn) RemoteAddr() net.Addr { return c.remote }

func (c *kcpConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *kcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	kcpNudge(c.readSig)
	return nil
}

func (c *kcpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	c.mu.Unlock()
	kcpNudge(c.writeSig)
	return nil
}
