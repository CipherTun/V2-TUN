package tun

import (
	"fmt"
	"testing"
)

// Addresses must stay unique and map back correctly past 65536 domains.
func TestFakeDNSNoCollisionBeyond64k(t *testing.T) {
	f := NewFakeDNS()
	seen := map[string]string{}
	for i := 0; i < 70000; i++ {
		domain := fmt.Sprintf("h%d.example.com", i)
		ip := f.alloc(domain)
		if prev, dup := seen[ip.String()]; dup {
			t.Fatalf("%s handed out for both %s and %s", ip, prev, domain)
		}
		seen[ip.String()] = domain
		got, ok := f.Lookup(ip)
		if !ok || got != domain {
			t.Fatalf("lookup %s: got %q ok=%v, want %q", ip, got, ok, domain)
		}
	}
}

func TestFakeDNSAnswersA(t *testing.T) {
	f := NewFakeDNS()
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	resp, ok := f.Handle(q)
	if !ok {
		t.Fatal("A query not answered")
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatal("response id does not match query id")
	}
	ip := net4(resp[len(resp)-4:])
	if d, found := f.Lookup(ip); !found || d != "example.com" {
		t.Fatalf("lookup %s: got %q found=%v", ip, d, found)
	}
}
