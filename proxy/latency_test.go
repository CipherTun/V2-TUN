package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestLatencyRankPutsDeadLast(t *testing.T) {
	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close() // nothing listens here any more: the connect is refused

	f := &Failover{Outs: []Outbound{&fakeOut{}, &fakeOut{}, &fakeOut{}}}
	// 0 is dead, 1 answers, 2 cannot be probed
	f.profile(context.Background(), []string{deadAddr, live.Addr().String(), ""}, nil)

	want := []int{1, 2, 0}
	if len(f.rank) != 3 {
		t.Fatalf("rank %v", f.rank)
	}
	for i, w := range want {
		if f.rank[i] != w {
			t.Fatalf("rank %v, want %v", f.rank, want)
		}
	}

	// the outbound in use stays first, the others follow in rank order
	f.cur = 0
	if got := f.order(); got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("order with cur=0: %v", got)
	}
	f.cur = 1
	if got := f.order(); got[0] != 1 || got[1] != 2 || got[2] != 0 {
		t.Fatalf("order with cur=1: %v", got)
	}
}

func TestOrderWithoutRankIsUnchanged(t *testing.T) {
	f := &Failover{Outs: []Outbound{&fakeOut{}, &fakeOut{}, &fakeOut{}}}
	f.cur = 1
	if got := f.order(); got[0] != 1 || got[1] != 2 || got[2] != 0 {
		t.Fatalf("order: %v", got)
	}
}

func TestStartLatencyEngineValidates(t *testing.T) {
	f := &Failover{Outs: []Outbound{&fakeOut{}}}
	if err := f.StartLatencyEngine(context.Background(), time.Second, nil, nil); err == nil {
		t.Error("a missing probe address list must be rejected")
	}
	if err := f.StartLatencyEngine(context.Background(), 0, []string{"x:1"}, nil); err == nil {
		t.Error("a zero interval must be rejected")
	}
	if err := f.StartLatencyEngine(context.Background(), time.Hour, []string{""}, nil); err != nil {
		t.Fatal(err)
	}
	f.Close() // stops the engine
	f.mu.Lock()
	stopped := f.stop == nil
	f.mu.Unlock()
	if !stopped {
		t.Error("Close must stop the latency engine")
	}
}
