// Package logx is the logging backbone of the library. Every package takes a
// logger with L("component"); all of them share one handler that keeps the most
// recent entries in memory and, when the app registers a sink with SetSink,
// forwards each entry to it as one line of JSON.
//
// Logs live in the app only: nothing is ever written to a file here.
//
// It sits in an internal package because proxy, tun, socks and transport are
// imported by the root package and so cannot import it.
package logx

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ringSize is how many recent entries are kept in memory.
const ringSize = 1000

// queueSize is how many entries can wait for the sink before new ones are
// dropped from the live feed (they are still kept in the ring).
const queueSize = 512

// Entry is one log line as the app sees it.
type Entry struct {
	Seq       int64             `json:"seq"`
	TimeMs    int64             `json:"t"`
	Level     string            `json:"level"` // debug|info|warn|error
	Component string            `json:"c,omitempty"`
	Msg       string            `json:"msg"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

var (
	levelVar slog.LevelVar // zero value is Info

	mu   sync.Mutex
	ring []Entry
	next int
	full bool
	seq  int64

	sink       atomic.Pointer[func(string)]
	queue      = make(chan string, queueSize)
	workerOnce sync.Once
	dropped    atomic.Int64
)

// L returns the logger of one component ("tun", "socks", "failover", ...).
// Loggers made before SetSink or SetLevel pick the changes up too.
func L(component string) *slog.Logger {
	return slog.New(&handler{}).With("c", component)
}

// ParseLevel turns "debug", "info", "warn" or "error" into a level; anything
// else is info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "trace":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// SetLevel changes the minimum level that is recorded, at any time.
func SetLevel(l slog.Level) { levelVar.Set(l) }

// SetSink registers f to receive every recorded entry as one line of JSON (an
// Entry). f runs on its own goroutine, never on the path that logged, so a
// slow app cannot slow the tunnel; when it falls behind, entries are dropped
// from the live feed (see Dropped) but stay available through Recent. nil
// removes the sink.
func SetSink(f func(string)) {
	if f == nil {
		sink.Store(nil)
		return
	}
	sink.Store(&f)
	workerOnce.Do(func() {
		go func() {
			for line := range queue {
				deliver(line)
			}
		}()
	})
}

func deliver(line string) {
	defer func() { _ = recover() }() // a failing app callback must not kill the worker
	if p := sink.Load(); p != nil {
		(*p)(line)
	}
}

// Dropped is how many entries the live feed had to drop because the sink was
// too slow.
func Dropped() int64 { return dropped.Load() }

// Recent returns the newest n entries, oldest first (n <= 0 returns all that
// are kept).
func Recent(n int) []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, 0, ringSize)
	if full {
		out = append(out, ring[next:]...)
	}
	out = append(out, ring[:next]...)
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// RecentJSON is Recent as a JSON array.
func RecentJSON(n int) string {
	b, err := json.Marshal(Recent(n))
	if err != nil {
		return "[]"
	}
	return string(b)
}

// Clear forgets the kept entries.
func Clear() {
	mu.Lock()
	ring, next, full = nil, 0, false
	mu.Unlock()
}

func push(e Entry) {
	mu.Lock()
	seq++
	e.Seq = seq
	if ring == nil {
		ring = make([]Entry, ringSize)
	}
	ring[next] = e
	next = (next + 1) % ringSize
	if next == 0 {
		full = true
	}
	mu.Unlock()

	if sink.Load() == nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	select {
	case queue <- string(b):
	default:
		dropped.Add(1)
	}
}

// secretKeys are attribute names whose values are never recorded.
var secretKeys = map[string]bool{
	"password": true, "pass": true, "uuid": true, "privatekey": true,
	"passphrase": true, "auth": true, "token": true, "seed": true,
}

func isSecret(key string) bool {
	k := strings.ToLower(key)
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	return secretKeys[k]
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}

// handler is the one slog.Handler behind every logger from L.
type handler struct {
	attrs  []slog.Attr // from With, keys already carry the group prefix
	prefix string      // group prefix, "a.b."
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= levelVar.Level()
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	e := Entry{TimeMs: t.UnixMilli(), Level: levelName(r.Level), Msg: r.Message}
	attrs := make(map[string]string, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		collect(attrs, "", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		collect(attrs, h.prefix, a)
		return true
	})
	if c, ok := attrs["c"]; ok {
		e.Component = c
		delete(attrs, "c")
	}
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	push(e)
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	if len(as) == 0 {
		return h
	}
	nh := &handler{prefix: h.prefix, attrs: make([]slog.Attr, 0, len(h.attrs)+len(as))}
	nh.attrs = append(nh.attrs, h.attrs...)
	for _, a := range as {
		a.Key = h.prefix + a.Key
		nh.attrs = append(nh.attrs, a)
	}
	return nh
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &handler{attrs: h.attrs, prefix: h.prefix + name + "."}
}

// collect flattens one attribute into m, hiding secrets.
func collect(m map[string]string, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, ga := range a.Value.Group() {
			collect(m, p, ga)
		}
		return
	}
	key := prefix + a.Key
	if a.Key == "" {
		return
	}
	if isSecret(key) {
		m[key] = "***"
		return
	}
	m[key] = a.Value.String()
}
