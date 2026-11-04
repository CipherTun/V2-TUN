package tun

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// SniffDomain extracts the TLS SNI or HTTP Host from the first client bytes.
func SniffDomain(b []byte) string {
	if len(b) > 5 && b[0] == 0x16 && b[1] == 0x03 {
		return sniffSNI(b)
	}
	return sniffHost(b)
}

func sniffHost(b []byte) string {
	for _, m := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT "} {
		if bytes.HasPrefix(b, []byte(m)) {
			for _, line := range strings.Split(string(b), "\r\n") {
				if len(line) > 6 && strings.EqualFold(line[:5], "host:") {
					h := strings.TrimSpace(line[5:])
					if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
						h = h[:i]
					}
					return h
				}
			}
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
