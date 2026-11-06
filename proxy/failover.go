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

	mu  sync.Mutex
	cur int
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

func (f *Failover) order() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := make([]int, len(f.Outs))
	for i := range idx {
		idx[i] = (f.cur + i) % len(f.Outs)
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

// Close closes every outbound that holds long-lived resources.
func (f *Failover) Close() error {
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
