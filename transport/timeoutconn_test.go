package transport

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTimeoutConnClosesWhenIdle(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	tc := NewTimeoutConn(a, 100*time.Millisecond)
	defer tc.Close()

	start := time.Now()
	buf := make([]byte, 1)
	if _, err := tc.Read(buf); err == nil {
		t.Fatal("an idle connection must be closed")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v to notice the idle connection", time.Since(start))
	}
}

func TestTimeoutConnActivityKeepsItOpen(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go io.Copy(io.Discard, b)

	tc := NewTimeoutConn(a, 400*time.Millisecond)
	defer tc.Close()

	// 6 writes, 100 ms apart: longer than the idle period in total, but every
	// write restarts it.
	for i := 0; i < 6; i++ {
		time.Sleep(100 * time.Millisecond)
		if _, err := tc.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
}

func TestTimeoutConnZeroDisables(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if NewTimeoutConn(a, 0) != a {
		t.Fatal("a zero idle period must return the connection unchanged")
	}
}
