package logx

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Limiter keeps an event that repeats very fast (a dead network makes every
// connection fail) from flooding the log and the app. The zero value is ready
// to use; keep one per kind of event, as a package variable.
//
// The first event goes through, the next ones within the interval are counted,
// and the count is attached as "suppressed" to the next entry that goes through.
type Limiter struct {
	mu      sync.Mutex
	at      time.Time
	skipped int
}

func (l *Limiter) allow(every time.Duration) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !l.at.IsZero() && now.Sub(l.at) < every {
		l.skipped++
		return false, 0
	}
	n := l.skipped
	l.skipped = 0
	l.at = now
	return true, n
}

// Log writes the entry unless one went through less than every ago.
func (l *Limiter) Log(lg *slog.Logger, level slog.Level, every time.Duration, msg string, args ...any) {
	ctx := context.Background()
	if !lg.Enabled(ctx, level) {
		return
	}
	ok, n := l.allow(every)
	if !ok {
		return
	}
	if n > 0 {
		args = append(args, "suppressed", n)
	}
	lg.Log(ctx, level, msg, args...)
}

// Warn is Log at warn level.
func (l *Limiter) Warn(lg *slog.Logger, every time.Duration, msg string, args ...any) {
	l.Log(lg, slog.LevelWarn, every, msg, args...)
}

// Error is Log at error level.
func (l *Limiter) Error(lg *slog.Logger, every time.Duration, msg string, args ...any) {
	l.Log(lg, slog.LevelError, every, msg, args...)
}
