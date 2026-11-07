package transport

import (
	"errors"
	"io"
	"net"
	"time"
)

// TimeoutConn closes the connection when no data has moved in either
// direction for the idle period. Every successful Read or Write restarts the
// timer, so a long upload to a server that sends nothing back is not cut off.
// A Read that is blocked when the timer fires returns io.EOF (or the error of
// the closed connection), like any connection that was closed.
type TimeoutConn struct {
	net.Conn
	idle  time.Duration
	timer *time.Timer
}

// NewTimeoutConn wraps c. An idle period of zero or less returns c unchanged.
func NewTimeoutConn(c net.Conn, idle time.Duration) net.Conn {
	if idle <= 0 {
		return c
	}
	t := &TimeoutConn{Conn: c, idle: idle}
	t.timer = time.AfterFunc(idle, func() { c.Close() })
	return t
}

func (t *TimeoutConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.timer.Reset(t.idle)
	}
	if err != nil && errors.Is(err, net.ErrClosed) {
		return n, io.EOF
	}
	return n, err
}

func (t *TimeoutConn) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.timer.Reset(t.idle)
	}
	return n, err
}

func (t *TimeoutConn) Close() error {
	t.timer.Stop()
	return t.Conn.Close()
}
