package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func obfsPair(t *testing.T) (a, b net.PacketConn) {
	t.Helper()
	var err error
	if a, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if b, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func testObfs(t *testing.T, wrap func(net.PacketConn, []byte) net.PacketConn, saltLen int) {
	key := []byte("secret")
	msg := []byte("hello obfuscated world")

	// the wire format is salt + XORed payload, not the plain message
	a, b := obfsPair(t)
	if _, err := wrap(a, key).WriteTo(msg, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	raw := make([]byte, 2048)
	n, _, err := b.ReadFrom(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n != saltLen+len(msg) || bytes.Contains(raw[:n], msg) {
		t.Fatalf("unexpected wire packet: %d bytes", n)
	}

	// both ends wrapped: the message comes back intact
	a, b = obfsPair(t)
	if _, err := wrap(a, key).WriteTo(msg, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	rb := wrap(b, key)
	rb.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, _, err = rb.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("round trip returned %q", buf[:n])
	}

	// a different key does not recover the message
	a, b = obfsPair(t)
	if _, err := wrap(a, key).WriteTo(msg, b.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	rb = wrap(b, []byte("another key"))
	rb.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = rb.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(buf[:n], msg) {
		t.Fatal("a wrong key must not de-obfuscate the packet")
	}
}

func TestSalamander(t *testing.T) { testObfs(t, NewSalamander, 8) }
func TestXPlus(t *testing.T)      { testObfs(t, NewXPlus, 16) }
