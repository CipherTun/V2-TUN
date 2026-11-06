package transport

import (
	"bytes"
	"net"
	"testing"
)

func TestRecordConnHandsOutOneRecordAtATime(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewRecordConn(a)
	r1 := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 'a', 'b', 'c'}
	r2 := []byte{0x17, 0x03, 0x03, 0x00, 0x02, 'x', 'y'}
	go b.Write(append(append([]byte(nil), r1...), r2...)) // both records arrive in one segment

	buf := make([]byte, 64)
	n, err := rc.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], r1) {
		t.Fatalf("first read = %x err=%v, want exactly the first record", buf[:n], err)
	}
	n, err = rc.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], r2) {
		t.Fatalf("second read = %x err=%v", buf[:n], err)
	}
}

func TestRecordConnSmallReadsStayInsideRecord(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewRecordConn(a)
	rec := []byte{0x17, 0x03, 0x03, 0x00, 0x03, 'a', 'b', 'c'}
	go b.Write(append(append([]byte(nil), rec...), 'Z'))
	var got []byte
	for len(got) < len(rec) {
		buf := make([]byte, 3)
		n, err := rc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, rec) {
		t.Fatalf("got %x", got)
	}
}

func TestRecordConnDetach(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rc := NewRecordConn(a)
	rec := []byte{0x17, 0x03, 0x03, 0x00, 0x01, 'q'}
	go b.Write(append(append([]byte(nil), rec...), []byte("RAW-AFTER")...))
	buf := make([]byte, 64)
	if n, err := rc.Read(buf); err != nil || !bytes.Equal(buf[:n], rec) {
		t.Fatalf("record read = %x err=%v", buf[:n], err)
	}
	rc.Detach()
	n, err := rc.Read(buf)
	if err != nil || string(buf[:n]) != "RAW-AFTER" {
		t.Fatalf("after detach got %q err=%v, want the buffered raw bytes", buf[:n], err)
	}
}
