package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeOut struct {
	err   error
	calls int
}

func (f *fakeOut) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func TestGroupFallbackSkipsDownMember(t *testing.T) {
	bad, good := &fakeOut{err: errors.New("boom")}, &fakeOut{}
	g := &Group{Members: []Outbound{bad, good}, Strategy: "fallback"}
	for i := 0; i < 3; i++ {
		c, err := g.DialContext(context.Background(), "tcp", "example.com:80")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if bad.calls != 1 {
		t.Fatalf("failed member should be skipped while marked down, got %d calls", bad.calls)
	}
	if good.calls != 3 {
		t.Fatalf("good member calls = %d", good.calls)
	}
}

func TestGroupRoundRobin(t *testing.T) {
	a, b := &fakeOut{}, &fakeOut{}
	g := &Group{Members: []Outbound{a, b}, Strategy: "roundrobin"}
	for i := 0; i < 4; i++ {
		c, err := g.DialContext(context.Background(), "tcp", "example.com:80")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if a.calls != 2 || b.calls != 2 {
		t.Fatalf("calls a=%d b=%d", a.calls, b.calls)
	}
}

func TestGroupAllFail(t *testing.T) {
	boom := errors.New("boom")
	g := &Group{Members: []Outbound{&fakeOut{err: boom}, &fakeOut{err: boom}}}
	_, err := g.DialContext(context.Background(), "tcp", "example.com:80")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	// everything is marked down now, but the group must still try (last resort)
	if _, err := g.DialContext(context.Background(), "tcp", "example.com:80"); !errors.Is(err, boom) {
		t.Fatalf("second dial err = %v", err)
	}
}

func TestGroupUDPSkipsMembersWithoutUDP(t *testing.T) {
	g := &Group{Members: []Outbound{&fakeOut{}}}
	if _, err := g.DialUDP(context.Background(), "1.1.1.1:53"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v", err)
	}
	if g.st[0].fails != 0 {
		t.Fatal("a member without UDP support must not be marked unhealthy")
	}
}
