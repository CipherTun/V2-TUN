package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Group is an outbound that picks among several outbounds.
//
// Strategies: "fallback" (first healthy member, in order), "roundrobin",
// "random" and "latency" (lowest smoothed dial time first; untried members go
// first so they get measured). A member whose dial fails is skipped for a
// while (20s per consecutive failure, at most 5 min) but is still tried as a
// last resort, so a group never refuses to dial just because everything
// looks down.
type Group struct {
	Members        []Outbound
	Names          []string // optional, for error messages
	Strategy       string
	AttemptTimeout time.Duration // per member dial, default 10s

	mu sync.Mutex
	st []groupState
	rr int
}

type groupState struct {
	fails     int
	downUntil time.Time
	ewma      time.Duration
}

func (g *Group) name(i int) string {
	if i < len(g.Names) && g.Names[i] != "" {
		return g.Names[i]
	}
	return fmt.Sprintf("#%d", i+1)
}

func (g *Group) order() []int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.st) != len(g.Members) {
		g.st = make([]groupState, len(g.Members))
	}
	now := time.Now()
	var up, down []int
	for i := range g.Members {
		if g.st[i].downUntil.After(now) {
			down = append(down, i)
		} else {
			up = append(up, i)
		}
	}
	switch strings.ToLower(g.Strategy) {
	case "roundrobin", "round-robin":
		if len(up) > 0 {
			k := g.rr % len(up)
			g.rr++
			rot := make([]int, 0, len(up))
			rot = append(rot, up[k:]...)
			rot = append(rot, up[:k]...)
			up = rot
		}
	case "random":
		rand.Shuffle(len(up), func(i, j int) { up[i], up[j] = up[j], up[i] })
	case "latency", "urltest":
		sort.SliceStable(up, func(a, b int) bool { return g.st[up[a]].ewma < g.st[up[b]].ewma })
	}
	return append(up, down...)
}

func (g *Group) record(i int, d time.Duration, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := &g.st[i]
	if err != nil {
		s.fails++
		back := time.Duration(s.fails) * 20 * time.Second
		if back > 5*time.Minute {
			back = 5 * time.Minute
		}
		s.downUntil = time.Now().Add(back)
		return
	}
	s.fails = 0
	s.downUntil = time.Time{}
	if s.ewma == 0 {
		s.ewma = d
	} else {
		s.ewma = (s.ewma*7 + d) / 8
	}
}

func (g *Group) try(ctx context.Context, dial func(context.Context, Outbound) (net.Conn, error)) (net.Conn, error) {
	to := g.AttemptTimeout
	if to <= 0 {
		to = 10 * time.Second
	}
	var errs []error
	for _, i := range g.order() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		actx, cancel := context.WithTimeout(ctx, to)
		t0 := time.Now()
		c, err := dial(actx, g.Members[i])
		cancel()
		if err == nil {
			g.record(i, time.Since(t0), nil)
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !errors.Is(err, ErrNotImplemented) { // "no UDP" is not a health problem
			g.record(i, 0, err)
		}
		errs = append(errs, fmt.Errorf("%s: %w", g.name(i), err))
	}
	if len(errs) == 0 {
		return nil, errors.New("group: no outbounds")
	}
	return nil, errors.Join(errs...)
}

func (g *Group) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	return g.try(ctx, func(c context.Context, m Outbound) (net.Conn, error) {
		return m.DialContext(c, network, target)
	})
}

// DialUDP tries the members that can relay UDP.
func (g *Group) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	return g.try(ctx, func(c context.Context, m Outbound) (net.Conn, error) {
		u, ok := m.(UDPOutbound)
		if !ok {
			return nil, ErrNotImplemented
		}
		return u.DialUDP(c, target)
	})
}

// Close closes members that hold long-lived connections.
func (g *Group) Close() error {
	for _, m := range g.Members {
		if cl, ok := m.(io.Closer); ok {
			cl.Close()
		}
	}
	return nil
}
