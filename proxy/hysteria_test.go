package proxy

import (
	"bytes"
	"testing"
)

func TestVarint(t *testing.T) {
	for _, v := range []uint64{0, 1, 63, 64, 1025, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<40 + 5} {
		b := appendVarint(nil, v)
		got, n := parseVarint(b)
		if got != v || n != len(b) {
			t.Fatalf("%d: parseVarint gave %d (%d bytes of %d)", v, got, n, len(b))
		}
		r, err := readVarint(bytes.NewReader(b))
		if err != nil || r != v {
			t.Fatalf("%d: readVarint gave %d, %v", v, r, err)
		}
	}
	// 0x401 (the Hysteria 2 TCPRequest id) is two bytes: 0x44 0x01
	if b := appendVarint(nil, 0x401); !bytes.Equal(b, []byte{0x44, 0x01}) {
		t.Fatalf("0x401 encoded as % x", b)
	}
	if _, n := parseVarint([]byte{0x44}); n != 0 {
		t.Fatal("a truncated varint must be reported")
	}
}

func TestHy2Codec(t *testing.T) {
	msg := hy2Encode(0x01020304, "example.com:53", 7, 1, 3, []byte("hello"))
	sess, pkt, fid, fcnt, data, ok := hy2Decode(msg)
	if !ok || sess != 0x01020304 || pkt != 7 || fid != 1 || fcnt != 3 || string(data) != "hello" {
		t.Fatalf("decoded %v %v %v %v %q %v", sess, pkt, fid, fcnt, data, ok)
	}
	if _, _, _, _, _, ok := hy2Decode(msg[:5]); ok {
		t.Fatal("a truncated message must be rejected")
	}
	if _, _, _, _, d, ok := hy2Decode(hy2Encode(1, "1.2.3.4:5", 0, 0, 1, nil)); !ok || len(d) != 0 {
		t.Fatal("an empty payload must decode")
	}
}

func TestHy1Codec(t *testing.T) {
	msg := hy1Encode(0x0a0b0c0d, "example.com:53", 9, 2, 4, []byte("world"))
	sess, pkt, fid, fcnt, data, ok := hy1Decode(msg)
	if !ok || sess != 0x0a0b0c0d || pkt != 9 || fid != 2 || fcnt != 4 || string(data) != "world" {
		t.Fatalf("decoded %v %v %v %v %q %v", sess, pkt, fid, fcnt, data, ok)
	}
	if _, _, _, _, _, ok := hy1Decode(msg[:10]); ok {
		t.Fatal("a truncated message must be rejected")
	}
}

func newTestFlow() *hyFlow {
	m := &hyMux{flows: map[uint32]*hyFlow{}}
	return m.add(7, "1.2.3.4:53", nil)
}

func TestFlowReassemblesFragments(t *testing.T) {
	f := newTestFlow()
	f.deliver(1, 1, 2, []byte("world")) // fragments may arrive out of order
	f.deliver(1, 0, 2, []byte("hello "))
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != "hello world" {
		t.Fatalf("reassembled %q, %v", buf[:n], err)
	}
}

func TestFlowPassesSingleAndDropsBadFragments(t *testing.T) {
	f := newTestFlow()
	f.deliver(5, 3, 2, []byte("x")) // fragment id beyond the count: ignored
	f.deliver(6, 0, 1, []byte("whole"))
	buf := make([]byte, 64)
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != "whole" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}

func TestFlowCloseEndsRead(t *testing.T) {
	f := newTestFlow()
	called := false
	f.onClose = func() { called = true }
	f.Close()
	f.Close() // idempotent
	if _, err := f.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read after Close must fail")
	}
	if !called {
		t.Fatal("onClose was not called")
	}
}
