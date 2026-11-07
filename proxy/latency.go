package proxy

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"io.surprise.vpn/transport"
)

const (
	latencyProbeTimeout = 2500 * time.Millisecond
	// latencyUnprobed ranks an outbound that cannot be probed with a TCP
	// connect (QUIC or other UDP based) behind every server that answered and
	// ahead of every server that did not.
	latencyUnprobed = time.Hour
)

// StartLatencyEngine re-measures, every interval, how fast each outbound's
// server accepts a TCP connection and re-ranks the failover order: the
// outbound that is in use stays first until it fails, after that the fastest
// server is tried first and servers that did not answer go last. Outs keeps
// its order, so Current and Client.ActiveOutbound still index the config list.
//
// addrs[i] is the host:port to probe for Outs[i]; "" means it cannot be probed
// (hysteria, quic). rs resolves host names (nil uses the system resolver). The
// engine stops with ctx or Close; calling it again replaces the previous run.
func (f *Failover) StartLatencyEngine(ctx context.Context, every time.Duration, addrs []string, rs *net.Resolver) error {
	if every <= 0 {
		return fmt.Errorf("failover: latency interval must be positive")
	}
	if len(addrs) != len(f.Outs) {
		return fmt.Errorf("failover: %d probe addresses for %d outbounds", len(addrs), len(f.Outs))
	}
	ctx, cancel := context.WithCancel(ctx)
	f.mu.Lock()
	if f.stop != nil {
		f.stop()
	}
	f.stop = cancel
	f.mu.Unlock()

	probes := append([]string(nil), addrs...)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				f.profile(ctx, probes, rs)
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

// profile probes every address at once and stores the new ranking.
func (f *Failover) profile(ctx context.Context, addrs []string, rs *net.Resolver) {
	type result struct {
		rtt   time.Duration
		alive bool
	}
	res := make([]result, len(addrs))
	d := &transport.TCP{Timeout: latencyProbeTimeout, Resolver: rs}

	var wg sync.WaitGroup
	for i, a := range addrs {
		if a == "" {
			res[i] = result{rtt: latencyUnprobed, alive: true}
			continue
		}
		wg.Add(1)
		go func(i int, a string) {
			defer wg.Done()
			t0 := time.Now()
			c, err := d.DialContext(ctx, "tcp", a)
			if err != nil {
				return
			}
			c.Close()
			res[i] = result{rtt: time.Since(t0), alive: true}
		}(i, a)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	idx := make([]int, len(addrs))
	for i := range idx {
		idx[i] = i
	}
	// stable: servers with equal results keep their configured order
	sort.SliceStable(idx, func(x, y int) bool {
		a, b := res[idx[x]], res[idx[y]]
		if a.alive != b.alive {
			return a.alive
		}
		return a.rtt < b.rtt
	})
	f.mu.Lock()
	f.rank = idx
	f.mu.Unlock()
}
