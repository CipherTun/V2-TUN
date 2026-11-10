package transport

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseDNSServers(t *testing.T) {
	got := parseDNSServers("1.1.1.1, tls://dns.google 8.8.4.4:5353,2001:4860:4860::8888 ,tls://[2606:4700:4700::1111]:853, ")
	want := []dnsServer{
		{addr: "1.1.1.1:53"},
		{addr: "dns.google:853", name: "dns.google", tls: true},
		{addr: "8.8.4.4:5353"},
		{addr: "[2001:4860:4860::8888]:53"},
		{addr: "[2606:4700:4700::1111]:853", name: "2606:4700:4700::1111", tls: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d servers (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("server %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if NewResolver("  ,, ") != nil {
		t.Error("a list with no usable entry must give no resolver")
	}
}

// fakeDNS answers every A query with 192.0.2.7 and everything else with an
// empty answer.
func fakeDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			msg := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionAvailable: true},
				Questions: []dnsmessage.Question{q},
			}
			if q.Type == dnsmessage.TypeA {
				msg.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}},
				}}
			}
			out, err := msg.Pack()
			if err != nil {
				continue
			}
			pc.WriteTo(out, from)
		}
	}()
	return pc.LocalAddr().String()
}

// The first server refuses the query (nothing listens there); the resolver
// moves on to the second one and the lookup still succeeds.
func TestResolverFallsBackToTheNextServer(t *testing.T) {
	good := fakeDNS(t)
	r := NewResolver("127.0.0.1:1," + good)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ips, err := r.LookupHost(ctx, "fallback.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		if ip == "192.0.2.7" {
			return
		}
	}
	t.Fatalf("got %v, want 192.0.2.7", ips)
}
