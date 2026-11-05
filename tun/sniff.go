package tun

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "}

func looksHTTP(b []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

// SniffDomain extracts the TLS SNI or HTTP Host from the first client bytes.
func SniffDomain(b []byte) string {
	if len(b) > 5 && b[0] == 0x16 && b[1] == 0x03 {
		return sniffSNI(b)
	}
	return sniffHost(b)
}

// SniffProtocol names the protocol of the first client bytes: "tls", "http",
// "bittorrent", "ssh", or "" when unknown. Routing rules can match it.
func SniffProtocol(b []byte) string {
	switch {
	case len(b) > 5 && b[0] == 0x16 && b[1] == 0x03:
		return "tls"
	case len(b) >= 20 && b[0] == 0x13 && string(b[1:20]) == "BitTorrent protocol":
		return "bittorrent"
	case looksHTTP(b):
		return "http"
	case bytes.HasPrefix(b, []byte("SSH-")):
		return "ssh"
	}
	return ""
}

// readFirst collects the first client bytes for sniffing. One Read is not
// enough: a modern ClientHello (post-quantum key share) spans several TCP
// segments and the SNI can sit in a later one, so keep reading until the TLS
// record or the HTTP header block is complete, or the deadline passes.
func readFirst(c net.Conn, wait time.Duration) ([]byte, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, err
		}
		if !needMore(buf) {
			return buf, nil
		}
	}
}

func needMore(b []byte) bool {
	switch {
	case len(b) > 0 && len(b) < 5 && b[0] == 0x16:
		return true
	case len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03:
		want := 5 + (int(b[3])<<8 | int(b[4]))
		return len(b) < want && len(b) < 16389
	case looksHTTP(b):
		return len(b) < 8192 && !bytes.Contains(b, []byte("\r\n\r\n"))
	}
	return false
}

func sniffHost(b []byte) string {
	if !looksHTTP(b) {
		return ""
	}
	for _, line := range strings.Split(string(b), "\r\n") {
		if len(line) > 6 && strings.EqualFold(line[:5], "host:") {
			h := strings.TrimSpace(line[5:])
			if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
				h = h[:i]
			}
			return h
		}
	}
	return ""
}

func sniffSNI(b []byte) string {
	p := 5 + 4 + 2 + 32 // record hdr, handshake hdr, version, random
	if len(b) < p+1 || b[5] != 1 {
		return ""
	}
	skip := func(lenBytes int) bool {
		if len(b) < p+lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(b[p+i])
		}
		p += lenBytes + n
		return len(b) >= p
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, ciphers, compression
		return ""
	}
	if len(b) < p+2 {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	for p+4 <= end && p+4 <= len(b) {
		typ, n := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if typ == 0 && p+5 <= len(b) {
			l := int(binary.BigEndian.Uint16(b[p+3:]))
			if p+5+l <= len(b) {
				return string(b[p+5 : p+5+l])
			}
			return ""
		}
		p += n
	}
	return ""
}
