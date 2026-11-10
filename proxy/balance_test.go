package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
)

// tagOut is an outbound that records which one served a dial.
type tagOut struct {
	id     int
	fail   bool
	served *[]int
}

func (o tagOut) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if o.fail {
		return nil, errors.New("down")
	}
	*o.served = append(*o.served, o.id)
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func balancer(mode string, served *[]int, fail ...bool) *Failover {
	f := &Failover{Balance: mode}
	for i := 0; i < 3; i++ {
		f.Outs = append(f.Outs, tagOut{id: i, fail: len(fail) > i && fail[i], served: served})
	}
	return f
}

func dialN(t *testing.T, f *Failover, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		c, err := f.DialContext(context.Background(), "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
	}
}

func TestBalanceRoundRobin(t *testing.T) {
	var served []int
	dialN(t, balancer("roundrobin", &served), 6)
	want := []int{0, 1, 2, 0, 1, 2}
	if len(served) != len(want) {
		t.Fatalf("served %v, want %v", served, want)
	}
	for i := range want {
		if served[i] != want[i] {
			t.Fatalf("served %v, want %v", served, want)
		}
	}
}

func TestBalanceRandomUsesEveryOutbound(t *testing.T) {
	var served []int
	dialN(t, balancer("random", &served), 90)
	seen := map[int]bool{}
	for _, id := range served {
		seen[id] = true
	}
	if len(seen) != 3 {
		t.Fatalf("random balance used only %v of 3 outbounds", seen)
	}
}

// A failing outbound is skipped: the connection goes to the next one.
func TestBalanceSkipsAFailingOutbound(t *testing.T) {
	var served []int
	dialN(t, balancer("roundrobin", &served, true), 6)
	for _, id := range served {
		if id == 0 {
			t.Fatalf("the failing outbound served a dial: %v", served)
		}
	}
	if len(served) != 6 {
		t.Fatalf("served %d of 6 dials: %v", len(served), served)
	}
}

func TestValidBalance(t *testing.T) {
	for _, m := range []string{"", "roundrobin", "random"} {
		if !ValidBalance(m) {
			t.Errorf("%q must be valid", m)
		}
	}
	if ValidBalance("fastest") {
		t.Error(`"fastest" must be invalid`)
	}
}
