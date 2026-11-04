package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const muxTarget = "v1.mux.cool:9527"

// Mux implements Mux.Cool (v2ray/Xray): many TCP/UDP sessions share one
// underlying connection. Base must be VLESS, VMess, Trojan or Shadowsocks.
type Mux struct {
	Base        Outbound
	Concurrency int // sessions per connection (default 8)

	mu    sync.Mutex
	conns []*muxConn
}

func (m *Mux) open(ctx context.Context, network byte, target string) (net.Conn, error) {
	a, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	max := m.Concurrency
	if max <= 0 {
		max = 8
	}
	m.mu.Lock()
	var mc *muxConn
	live := m.conns[:0]
	for _, c := range m.conns {
		if !c.isDead() {
			live = append(live, c)
			if mc == nil && c.count() < max {
				mc = c
			}
		}
	}
	m.conns = live
	if mc == nil {
		raw, err := m.Base.DialContext(ctx, "tcp", muxTarget)
		if err != nil {
			m.mu.Unlock()
			return nil, err
		}
		mc = &muxConn{raw: raw, streams: map[uint16]*muxStream{}}
		m.conns = append(m.conns, mc)
		go mc.readLoop()
	}
	s := mc.newStream(network, a.vless())
	m.mu.Unlock()
	return s, nil
}

func (m *Mux) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return m.open(ctx, 1, target)
}

func (m *Mux) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	return m.open(ctx, 2, target)
}

type muxConn struct {
	raw     net.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	streams map[uint16]*muxStream
	next    uint16
	dead    bool
}

func (c *muxConn) isDead() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.dead }
func (c *muxConn) count() int   { c.mu.Lock(); defer c.mu.Unlock(); return len(c.streams) }

func (c *muxConn) newStream(network byte, addr []byte) *muxStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	s := &muxStream{c: c, id: c.next, network: network, addr: addr,
		rq: make(chan []byte, 64), done: make(chan struct{})}
	c.streams[s.id] = s
	return s
}

func (c *muxConn) writeFrame(meta, data []byte, hasData bool) error {
	f := binary.BigEndian.AppendUint16(nil, uint16(len(meta)))
	f = append(f, meta...)
	if hasData {
		f = binary.BigEndian.AppendUint16(f, uint16(len(data)))
		f = append(f, data...)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.raw.Write(f)
	return err
}

func (c *muxConn) readLoop() {
	defer func() {
		c.mu.Lock()
		c.dead = true
		for _, s := range c.streams {
			s.finish()
		}
		c.mu.Unlock()
		c.raw.Close()
	}()
	for {
		var l [2]byte
		if _, err := io.ReadFull(c.raw, l[:]); err != nil {
			return
		}
		meta := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c.raw, meta); err != nil || len(meta) < 4 {
			return
		}
		id, status, opt := binary.BigEndian.Uint16(meta[:2]), meta[2], meta[3]
		var data []byte
		if opt&1 != 0 {
			if _, err := io.ReadFull(c.raw, l[:]); err != nil {
				return
			}
			data = make([]byte, binary.BigEndian.Uint16(l[:]))
			if _, err := io.ReadFull(c.raw, data); err != nil {
				return
			}
		}
		c.mu.Lock()
		s := c.streams[id]
		c.mu.Unlock()
		if s == nil {
			continue
		}
		switch status {
		case 3: // end
			s.finish()
		case 2: // keep
			if len(data) > 0 {
				select {
				case s.rq <- data:
				case <-s.done:
				}
			}
		}
	}
}

type muxStream struct {
	c       *muxConn
	id      uint16
	network byte
	addr    []byte
	sentNew bool
	wmu     sync.Mutex
	rq      chan []byte
	rbuf    []byte
	done    chan struct{}
	once    sync.Once
}

func (s *muxStream) finish() { s.once.Do(func() { close(s.done) }) }

func (s *muxStream) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	select {
	case <-s.done:
		return 0, errors.New("mux: stream closed")
	default:
	}
	max := 8192
	if s.network == 2 {
		max = 65535
	}
	total := 0
	for len(p) > 0 || total == 0 {
		n := len(p)
		if n > max {
			n = max
		}
		var meta []byte
		meta = binary.BigEndian.AppendUint16(meta, s.id)
		if !s.sentNew {
			meta = append(meta, 1, 1, s.network) // new, data, network
			meta = append(meta, s.addr...)
			s.sentNew = true
		} else {
			meta = append(meta, 2, 1)
		}
		if err := s.c.writeFrame(meta, p[:n], true); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
		if len(p) == 0 {
			break
		}
	}
	return total, nil
}

func (s *muxStream) Read(p []byte) (int, error) {
	for len(s.rbuf) == 0 {
		select {
		case b := <-s.rq:
			s.rbuf = b
		case <-s.done:
			select {
			case b := <-s.rq:
				s.rbuf = b
			default:
				return 0, io.EOF
			}
		}
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *muxStream) Close() error {
	s.once.Do(func() {
		close(s.done)
		if s.sentNew {
			meta := binary.BigEndian.AppendUint16(nil, s.id)
			s.c.writeFrame(append(meta, 3, 0), nil, false)
		}
	})
	s.c.mu.Lock()
	delete(s.c.streams, s.id)
	s.c.mu.Unlock()
	return nil
}

func (s *muxStream) LocalAddr() net.Addr              { return s.c.raw.LocalAddr() }
func (s *muxStream) RemoteAddr() net.Addr             { return s.c.raw.RemoteAddr() }
func (s *muxStream) SetDeadline(time.Time) error      { return nil }
func (s *muxStream) SetReadDeadline(time.Time) error  { return nil }
func (s *muxStream) SetWriteDeadline(time.Time) error { return nil }
