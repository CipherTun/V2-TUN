package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strings"
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
	go b.Close()
	return a, nil
}

type fakeUDPOut struct{ fakeOut }

func (f *fakeUDPOut) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	a, b := net.Pipe()
	go b.Close()
	return a, nil
}

func TestFailoverOrderAndStickiness(t *testing.T) {
	bad1 := &fakeOut{err: errors.New("down")}
	good := &fakeOut{}
	good2 := &fakeOut{}
	f := &Failover{Outs: []Outbound{bad1, good, good2}}
	ctx := context.Background()

	c, err := f.DialContext(ctx, "tcp", "x:1")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if f.Current() != 1 || bad1.calls != 1 || good.calls != 1 || good2.calls != 0 {
		t.Fatalf("current=%d calls=%d/%d/%d", f.Current(), bad1.calls, good.calls, good2.calls)
	}

	// the next connection starts with the outbound that worked
	c, err = f.DialContext(ctx, "tcp", "x:1")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if bad1.calls != 1 || good.calls != 2 {
		t.Fatalf("calls=%d/%d", bad1.calls, good.calls)
	}
}

func TestFailoverAllDown(t *testing.T) {
	f := &Failover{Outs: []Outbound{&fakeOut{err: errors.New("one down")}, &fakeOut{err: errors.New("two down")}}}
	_, err := f.DialContext(context.Background(), "tcp", "x:1")
	if err == nil || !strings.Contains(err.Error(), "outbound 1") || !strings.Contains(err.Error(), "outbound 2") {
		t.Fatalf("error should name every outbound: %v", err)
	}
	if _, err := (&Failover{}).DialContext(context.Background(), "tcp", "x:1"); err == nil {
		t.Fatal("no outbounds must fail")
	}
}

func TestSupportsUDP(t *testing.T) {
	if SupportsUDP(&Failover{Outs: []Outbound{&fakeOut{}}}) {
		t.Fatal("no UDP outbound inside")
	}
	if !SupportsUDP(&Failover{Outs: []Outbound{&fakeOut{}, &fakeUDPOut{}}}) {
		t.Fatal("one UDP outbound inside")
	}
	if _, err := (&Failover{Outs: []Outbound{&fakeOut{}}}).DialUDP(context.Background(), "1.2.3.4:5"); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("got %v", err)
	}
}

func TestParseHostKeyPin(t *testing.T) {
	sum := sha256.Sum256([]byte("a host key blob"))
	forms := []string{
		"SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
		"SHA256:" + base64.StdEncoding.EncodeToString(sum[:]),
		hex.EncodeToString(sum[:]),
	}
	for _, p := range forms {
		b, ok := parsePin(p)
		if !ok || string(b) != string(sum[:]) || !ValidHostKeyPin(p) {
			t.Errorf("%q was not parsed", p)
		}
	}
	for _, p := range []string{"", "SHA256:", "SHA256:AAAA", "zz", hex.EncodeToString(sum[:8])} {
		if ValidHostKeyPin(p) {
			t.Errorf("%q must not be a valid pin", p)
		}
	}
}
