package socks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type netDialer struct{}

func (netDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func (netDialer) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "udp", addr)
}

func startServer(t *testing.T, o Options) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ServeOpts(ctx, l, netDialer{}, o)
	return l.Addr().String()
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func ipv4Request(cmd byte, addr string) []byte {
	ua, _ := net.ResolveTCPAddr("tcp", addr)
	b := []byte{5, cmd, 0, 1}
	b = append(b, ua.IP.To4()...)
	return binary.BigEndian.AppendUint16(b, uint16(ua.Port))
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

func expect(t *testing.T, c net.Conn, want ...byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got % x, want % x", got, want)
		}
	}
}

func TestConnectWithAuth(t *testing.T) {
	echo := tcpEcho(t)
	srv := startServer(t, Options{Username: "u", Password: "p"})

	c := dial(t, srv)
	c.Write([]byte{5, 1, 2})
	expect(t, c, 5, 2)
	c.Write([]byte{1, 1, 'u', 1, 'p'})
	expect(t, c, 1, 0)
	c.Write(ipv4Request(1, echo))
	expect(t, c, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	c.Write([]byte("hello"))
	expect(t, c, 'h', 'e', 'l', 'l', 'o')
}

func TestWrongPasswordAndMissingMethod(t *testing.T) {
	srv := startServer(t, Options{Username: "u", Password: "p"})

	c := dial(t, srv)
	c.Write([]byte{5, 1, 2})
	expect(t, c, 5, 2)
	c.Write([]byte{1, 1, 'u', 1, 'x'})
	expect(t, c, 1, 1)

	c2 := dial(t, srv)
	c2.Write([]byte{5, 1, 0}) // offers only "no authentication"
	expect(t, c2, 5, 0xFF)
}

func TestConnectWithoutAuth(t *testing.T) {
	echo := tcpEcho(t)
	srv := startServer(t, Options{})
	c := dial(t, srv)
	c.Write([]byte{5, 1, 0})
	expect(t, c, 5, 0)
	c.Write(ipv4Request(1, echo))
	expect(t, c, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	c.Write([]byte("ping"))
	expect(t, c, 'p', 'i', 'n', 'g')
}

func TestUDPNotSupportedWithoutDialer(t *testing.T) {
	srv := startServer(t, Options{})
	c := dial(t, srv)
	c.Write([]byte{5, 1, 0})
	expect(t, c, 5, 0)
	c.Write(ipv4Request(3, "127.0.0.1:0"))
	expect(t, c, 5, 7)
}

func TestUDPAssociate(t *testing.T) {
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()

	srv := startServer(t, Options{UDP: netDialer{}})
	c := dial(t, srv)
	c.Write([]byte{5, 1, 0})
	expect(t, c, 5, 0)
	c.Write(ipv4Request(3, "127.0.0.1:0"))
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[1] != 0 || rep[3] != 1 {
		t.Fatalf("associate reply % x err=%v", rep, err)
	}
	relay := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:]))}

	uc, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))

	ea := echo.LocalAddr().(*net.UDPAddr)
	hdr := udpHeader(ea.IP.String(), ea.Port)
	if _, err := uc.Write(append(append([]byte(nil), hdr...), "datagram"...)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	host, port, payload, ok := parseUDP(buf[:n])
	if !ok || host != ea.IP.String() || port != ea.Port || string(payload) != "datagram" {
		t.Fatalf("reply: host=%s port=%d payload=%q ok=%v", host, port, payload, ok)
	}
}

func TestUDPHeaderRoundTrip(t *testing.T) {
	for _, host := range []string{"192.0.2.7", "2001:db8::5", "example.com"} {
		h := udpHeader(host, 5353)
		got, port, payload, ok := parseUDP(append(h, "x"...))
		if !ok || got != host || port != 5353 || string(payload) != "x" {
			t.Errorf("%s: got host=%s port=%d payload=%q ok=%v", host, got, port, payload, ok)
		}
	}
	if _, _, _, ok := parseUDP([]byte{0, 0, 1, 1, 1, 2, 3, 4, 0, 1}); ok {
		t.Error("fragmented datagrams must be dropped")
	}
	if _, _, _, ok := parseUDP([]byte{0, 0, 0, 1, 1, 2}); ok {
		t.Error("truncated datagrams must be dropped")
	}
}
