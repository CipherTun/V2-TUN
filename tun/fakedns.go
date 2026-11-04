package tun

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

// FakeDNS answers A queries with addresses from 198.18.0.0/15 and remembers
// the domain, so routing rules and the proxy server see the real hostname
// even though the app only connects to an IP.
type FakeDNS struct {
	mu       sync.Mutex
	byDomain map[string]uint32
	byIdx    map[uint32]string
	next     uint32
}

const fakeSize = 1 << 17 // /15

func NewFakeDNS() *FakeDNS {
	return &FakeDNS{byDomain: map[string]uint32{}, byIdx: map[uint32]string{}, next: 2}
}

func (f *FakeDNS) alloc(domain string) net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx, ok := f.byDomain[domain]
	if !ok {
		idx = f.next
		f.next++
		if f.next >= fakeSize-1 {
			f.next = 2
		}
		if old, used := f.byIdx[idx]; used {
			delete(f.byDomain, old)
		}
		f.byDomain[domain], f.byIdx[idx] = idx, domain
	}
	return net.IPv4(198, 18, byte(idx>>8), byte(idx))
}

// Lookup maps a fake address back to its domain.
func (f *FakeDNS) Lookup(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil || v4[0] != 198 || (v4[1] != 18 && v4[1] != 19) {
		return "", false
	}
	idx := uint32(v4[1]-18)<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.byIdx[idx]
	return d, ok
}

// Handle returns a response for A/AAAA queries; ok=false means "forward it".
func (f *FakeDNS) Handle(q []byte) (resp []byte, ok bool) {
	if len(q) < 17 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil, false
	}
	p := 12
	var labels []string
	for p < len(q) && q[p] != 0 {
		n := int(q[p])
		if n&0xC0 != 0 || p+1+n > len(q) {
			return nil, false
		}
		labels = append(labels, string(q[p+1:p+1+n]))
		p += 1 + n
	}
	if p+5 > len(q) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(q[p+1:])
	question := q[12 : p+5]
	if qtype != 1 && qtype != 28 {
		return nil, false
	}
	r := append([]byte(nil), q[:2]...) // id
	r = append(r, 0x81, 0x80, 0, 1)    // response, RD+RA, 1 question
	if qtype == 1 {
		ip := f.alloc(strings.ToLower(strings.Join(labels, ".")))
		r = append(r, 0, 1, 0, 0, 0, 0) // 1 answer
		r = append(r, question...)
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		r = append(r, ip.To4()...)
	} else { // AAAA: empty answer so apps stay on IPv4
		r = append(r, 0, 0, 0, 0, 0, 0)
		r = append(r, question...)
	}
	return r, true
}
