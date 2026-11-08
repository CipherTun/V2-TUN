package logx

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordsAndHidesSecrets(t *testing.T) {
	Clear()
	SetLevel(slog.LevelDebug)
	defer SetLevel(slog.LevelInfo)

	L("test").Info("hello", "password", "hunter2", "n", 3)

	es := Recent(0)
	if len(es) != 1 {
		t.Fatalf("got %d entries, want 1", len(es))
	}
	e := es[0]
	if e.Component != "test" || e.Msg != "hello" || e.Level != "info" {
		t.Fatalf("unexpected entry %+v", e)
	}
	if e.Attrs["password"] != "***" || e.Attrs["n"] != "3" {
		t.Fatalf("unexpected attrs %v", e.Attrs)
	}
	if _, ok := e.Attrs["c"]; ok {
		t.Fatalf("component leaked into attrs: %v", e.Attrs)
	}
}

func TestLevelFilter(t *testing.T) {
	Clear()
	SetLevel(slog.LevelWarn)
	defer SetLevel(slog.LevelInfo)

	l := L("test")
	l.Info("quiet")
	l.Debug("quieter")
	l.Warn("loud")

	es := Recent(0)
	if len(es) != 1 || es[0].Msg != "loud" {
		t.Fatalf("got %+v, want only the warning", es)
	}
}

func TestRingKeepsTheNewest(t *testing.T) {
	Clear()
	l := L("test")
	for i := 0; i < ringSize+10; i++ {
		l.Info("m")
	}
	es := Recent(0)
	if len(es) != ringSize {
		t.Fatalf("got %d entries, want %d", len(es), ringSize)
	}
	for i := 1; i < len(es); i++ {
		if es[i].Seq != es[i-1].Seq+1 {
			t.Fatalf("entries out of order at %d", i)
		}
	}
	if got := Recent(5); len(got) != 5 || got[4].Seq != es[len(es)-1].Seq {
		t.Fatalf("Recent(5) returned %d entries", len(got))
	}
}

func TestSinkGetsJSON(t *testing.T) {
	var mu sync.Mutex
	var got []string
	SetSink(func(s string) {
		mu.Lock()
		got = append(got, s)
		mu.Unlock()
	})
	defer SetSink(nil)

	L("sinktest").Info("ping", "k", "v")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("the sink received nothing")
	}
	if !strings.Contains(got[0], `"msg":"ping"`) || !strings.Contains(got[0], `"c":"sinktest"`) {
		t.Fatalf("unexpected line %s", got[0])
	}
}

func TestGroupsAndWith(t *testing.T) {
	Clear()
	l := L("test").With("conn", 7).WithGroup("dst")
	l.Info("dial", "host", "example.com")

	e := Recent(1)[0]
	if e.Attrs["conn"] != "7" || e.Attrs["dst.host"] != "example.com" {
		t.Fatalf("unexpected attrs %v", e.Attrs)
	}
}
