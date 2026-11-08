package transport

import (
	"bytes"
	crand "crypto/rand"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

type kcpMemPC struct {
	in     chan []byte
	peer   *kcpMemPC
	addr   net.Addr
	loss   float64
	mu     sync.Mutex
	rnd    *rand.Rand
	closed chan struct{}
	once   sync.Once
}

func kcpMemPair(loss float64) (*kcpMemPC, *kcpMemPC) {
	mk := func(port int, seed int64) *kcpMemPC {
		return &kcpMemPC{in: make(chan []byte, 4096), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			loss: loss, rnd: rand.New(rand.NewSource(seed)), closed: make(chan struct{})}
	}
	a, b := mk(1000, 1), mk(2000, 2)
	a.peer, b.peer = b, a
	return a, b
}

func (m *kcpMemPC) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-m.in:
		return copy(b, p), m.peer.addr, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	}
}

func (m *kcpMemPC) WriteTo(b []byte, _ net.Addr) (int, error) {
	m.mu.Lock()
	drop := m.rnd.Float64() < m.loss
	m.mu.Unlock()
	if !drop {
		select {
		case m.peer.in <- append([]byte(nil), b...):
		default:
		}
	}
	return len(b), nil
}

func (m *kcpMemPC) Close() error                     { m.once.Do(func() { close(m.closed) }); return nil }
func (m *kcpMemPC) LocalAddr() net.Addr              { return m.addr }
func (m *kcpMemPC) SetDeadline(time.Time) error      { return nil }
func (m *kcpMemPC) SetReadDeadline(time.Time) error  { return nil }
func (m *kcpMemPC) SetWriteDeadline(time.Time) error { return nil }

func TestKCPTransfer(t *testing.T) {
	cases := []struct {
		name, header, seed string
		loss               float64
	}{
		{"classic", "", "", 0},
		{"classic-srtp-lossy", "srtp", "", 0.05},
		{"seed-wechat-lossy", "wechat-video", "s3cret", 0.05},
		{"seed-dtls-lossy", "dtls", "x", 0.10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := kcpMemPair(tc.loss)
			p := (&KCP{TTI: 10}).params()
			mk := func(pc *kcpMemPC, remote net.Addr) *kcpConn {
				h, err := newKCPHeader(tc.header)
				if err != nil {
					t.Fatal(err)
				}
				return newKCPConn(pc, remote, 7, p, newKCPSecurity(tc.seed), h)
			}
			ca, cb := mk(a, b.addr), mk(b, a.addr)
			defer ca.Close()
			defer cb.Close()

			data := make([]byte, 1<<20)
			crand.Read(data)
			got := make([]byte, len(data))
			errc := make(chan error, 2)
			go func() { _, err := ca.Write(data); errc <- err }()
			go func() { _, err := io.ReadFull(cb, got); errc <- err }()
			for i := 0; i < 2; i++ {
				select {
				case err := <-errc:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(40 * time.Second):
					t.Fatal("timeout")
				}
			}
			if !bytes.Equal(got, data) {
				t.Fatal("data mismatch")
			}
		})
	}
}

func TestKCPSecurityRoundTrip(t *testing.T) {
	for _, s := range []kcpSecurity{newKCPSecurity(""), newKCPSecurity("seed")} {
		plain := []byte("hello mkcp, length not multiple of four!")
		out, err := s.Open(s.Seal(plain))
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatalf("%T round trip failed: %v", s, err)
		}
	}
}
