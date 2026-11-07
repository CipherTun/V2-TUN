package tun

import "testing"

// A plain `go test` runs only the seeds; `go test -fuzz=FuzzSniff` explores
// further. Sniffing reads the first bytes of untrusted connections.
func FuzzSniff(f *testing.F) {
	for _, s := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
		[]byte("SSH-2.0-OpenSSH_9.0\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		{0x16, 0x03, 0x01},
		{},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		SniffDomain(b)
		SniffProtocol(b)
	})
}
