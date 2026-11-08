package transport

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func grpcFrame(msg []byte) []byte {
	return append(append([]byte{0}, binary.BigEndian.AppendUint32(nil, uint32(len(msg)))...), msg...)
}

func readGRPCFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint32(h[1:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestGunWriteFraming(t *testing.T) {
	for _, multi := range []bool{false, true} {
		a, b := net.Pipe()
		c := &gunConn{Conn: a, br: bufio.NewReader(a), multi: multi}
		go c.Write([]byte("hello"))
		msg := readGRPCFrame(t, b)
		want := hunk([]byte("hello"))
		if multi {
			want = hunk(want) // MultiHunk{Hunk{hello}}
		}
		if string(msg) != string(want) {
			t.Errorf("multi=%v: message % x; want % x", multi, msg, want)
		}
		got, err := parseHunks(msg, multi)
		if err != nil || string(got) != "hello" {
			t.Errorf("multi=%v: parseHunks = %q, %v", multi, got, err)
		}
		a.Close()
		b.Close()
	}
}

func TestGunReadMultiHunk(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &gunConn{Conn: a, br: bufio.NewReader(a), multi: true}
	// one gRPC message holding two hunks: field 1 of MultiHunk, twice
	msg := append(hunk(hunk([]byte("ab"))), hunk(hunk([]byte("cde")))...)
	go b.Write(grpcFrame(msg))
	buf := make([]byte, 16)
	n, err := io.ReadFull(c, buf[:5])
	if err != nil || string(buf[:n]) != "abcde" {
		t.Fatalf("Read = %q, %v; want abcde", buf[:n], err)
	}
}

func TestParseHunksRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{{0x12, 0x01, 'x'}, {0x0a, 0x05, 'x'}, {0x0a}} {
		if _, err := parseHunks(in, false); err == nil {
			t.Errorf("parseHunks(% x) accepted garbage", in)
		}
	}
}
