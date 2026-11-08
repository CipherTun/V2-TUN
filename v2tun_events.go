package v2tun

import (
	"sync"
	"time"
)

// Faults are actionable errors (a dial that failed on every outbound, for
// example) pushed to the app, separate from the log. Register a handler with
// SetFaultHandler; the handler runs on its own goroutine, never on the dial
// path. Repeats of the same message within 10 seconds, and anything more
// often than once a second, are dropped so a dead network does not flood the
// app.
var faults struct {
	mu     sync.Mutex
	fn     func(string)
	last   string
	lastAt time.Time // last message of any kind
	sameAt time.Time // last time `last` was sent
}

// SetFaultHandler registers f to receive faults; nil removes the handler.
func SetFaultHandler(f func(string)) {
	faults.mu.Lock()
	faults.fn = f
	faults.mu.Unlock()
}

func reportFault(err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	now := time.Now()
	faults.mu.Lock()
	fn := faults.fn
	if fn == nil || now.Sub(faults.lastAt) < time.Second ||
		(msg == faults.last && now.Sub(faults.sameAt) < 10*time.Second) {
		faults.mu.Unlock()
		return
	}
	faults.last, faults.lastAt, faults.sameAt = msg, now, now
	faults.mu.Unlock()
	go fn(msg)
}
