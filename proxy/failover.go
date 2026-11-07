package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Failover tries several outbounds in order (a second server, another bug
// host or payload, another protocol) and remembers the one that worked last,
// so the next connection starts there. Each attempt is limited to PerTry.
type Failover struct {
	Outs   []Outbound
	PerTry time.Duration // limit for each outbound's attempt (default 12s)

	mu   sync.Mutex
	cur  int
	rank []int              // latency ranking (indexes into Outs) set by StartLatencyEngine; nil => list order
	stop context.CancelFunc // stops the latency engine
}

var (
	_ Outbound    = (*Failover)(nil)
	_ UDPOutbound = (*Failover)(nil)
)

func (f *Failover) perTry() time.Duration {
	if f.PerTry > 0 {
		return f.PerTry
	}
	return 12 * time.Second
}

// Current is the index of the outbound that worked last (0 is the first).
func (f *Failover) Current() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

// order is the sequence in which outbounds are tried: the one that worked last
// first, then the rest in list order, or in latency order when a ranking exists.
func (f *Failover) order() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.Outs)
	idx := make([]int, n)
	if n > 0 && len(f.rank) == n {
		pos := 0
		for i, r := range f.rank {
			if r == f.cur {
				pos = i
				break
			}
		}
		for i := range idx {
			idx[i] = f.rank[(pos+i)%n]
		}
		return idx
	}
	for i := range idx {
		idx[i] = (f.cur + i) % n
	}
	return idx
}

func (f *Failover) attempt(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	cx, cancel := context.WithTimeout(ctx, f.perTry())
	defer cancel()
	return dial(cx)
}

func (f *Failover) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	var errs []error
	for _, i := range f.order() {
		out := f.Outs[i]
		c, err := f.attempt(ctx, func(cx context.Context) (net.Conn, error) { return out.DialContext(cx, network, target) })
		if err == nil {
			f.mu.Lock()
			f.cur = i
			f.mu.Unlock()
			return c, nil
		}
		errs = append(errs, fmt.Errorf("outbound %d: %w", i+1, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, errors.New("failover: no outbounds")
	}
	return nil, errors.Join(errs...)
}

// DialUDP tries the outbounds that can relay UDP, in the same order.
func (f *Failover) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	var errs []error
	for _, i := range f.order() {
		u, ok := f.Outs[i].(UDPOutbound)
		if !ok {
			continue
		}
		c, err := f.attempt(ctx, func(cx context.Context) (net.Conn, error) { return u.DialUDP(cx, target) })
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("outbound %d: %w", i+1, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == 0 {
		return nil, ErrNotImplemented
	}
	return nil, errors.Join(errs...)
}

// Close closes every outbound that holds long-lived resources and stops the
// latency engine if one is running.
func (f *Failover) Close() error {
	f.mu.Lock()
	stop := f.stop
	f.stop = nil
	f.mu.Unlock()
	if stop != nil {
		stop()
	}
	for _, o := range f.Outs {
		if c, ok := o.(io.Closer); ok {
			c.Close()
		}
	}
	return nil
}

// SupportsUDP reports whether o can relay UDP itself (a Failover can if any of
// its outbounds can), so that callers know when to fall back to udpgw.
func SupportsUDP(o Outbound) bool {
	if f, ok := o.(*Failover); ok {
		for _, x := range f.Outs {
			if SupportsUDP(x) {
				return true
			}
		}
		return false
	}
	_, ok := o.(UDPOutbound)
	return ok
}
