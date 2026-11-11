package transport

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// dohAnswer builds the answer to a DNS query: 192.0.2.7 for an A query, an
// empty answer for anything else. The query is parsed by hand to keep the test
// free of DNS libraries.
func dohAnswer(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	end := i + 1 + 4 // root label, qtype, qclass
	if end > len(q) {
		return nil
	}
	qtype := int(q[end-4])<<8 | int(q[end-3])
	a := append([]byte(nil), q[:end]...)
	a[2], a[3] = 0x81, 0x80 // response, recursion desired and available
	a[4], a[5] = 0, 1       // one question
	a[6], a[7] = 0, 0
	a[8], a[9], a[10], a[11] = 0, 0, 0, 0
	if qtype == 1 {
		a[7] = 1
		a = append(a, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7)
	}
	return a
}

func dohTestServer(t *testing.T, hits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		q, _ := io.ReadAll(r.Body)
		ans := dohAnswer(q)
		if ans == nil {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(ans)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestParseDoHEntries(t *testing.T) {
	got := parseDNSServers("https://1.1.1.1/dns-query, HTTPS://dns.google ,https://[2606:4700:4700::1111]:443/x, https://, 8.8.8.8")
	if len(got) != 4 {
		t.Fatalf("got %d servers, want 4", len(got))
	}
	if got[0].doh == nil || got[0].doh.url != "https://1.1.1.1/dns-query" {
		t.Errorf("entry 0: %+v", got[0])
	}
	if got[1].doh == nil || got[1].doh.url != "https://dns.google/dns-query" {
		t.Errorf("a missing path must default to /dns-query: %+v", got[1])
	}
	if got[2].doh == nil || got[2].addr != "[2606:4700:4700::1111]:443" {
		t.Errorf("entry 2: %+v", got[2])
	}
	if got[3].addr != "8.8.8.8:53" || got[3].doh != nil {
		t.Errorf("entry 3: %+v", got[3])
	}
	if NewResolver("https://1.1.1.1/dns-query") == nil {
		t.Error("a single DoH entry must give a resolver")
	}
}

func TestResolverDoH(t *testing.T) {
	hits := 0
	srv := dohTestServer(t, &hits)
	p := &dnsPool{servers: []dnsServer{{addr: "test", doh: &dohEndpoint{url: srv.URL, hc: srv.Client()}}}}
	r := &net.Resolver{PreferGo: true, Dial: p.dial}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.7" {
		t.Fatalf("addresses = %v", addrs)
	}
	if hits == 0 {
		t.Fatal("the DoH server was never asked")
	}
}

// When plain DNS is dead (nothing answers on the first server), the resolver
// falls over to the DoH entry and the lookup still succeeds.
func TestResolverFallsBackToDoH(t *testing.T) {
	srv := dohTestServer(t, nil)
	// A bound but silent UDP socket: queries are sent and never answered.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	p := &dnsPool{servers: []dnsServer{
		{addr: silent.LocalAddr().String()},
		{addr: "test", doh: &dohEndpoint{url: srv.URL, hc: srv.Client()}},
	}}
	r := &net.Resolver{PreferGo: true, Dial: p.dial}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.7" {
		t.Fatalf("addresses = %v", addrs)
	}
}

// A DoH server that answers with an error counts as a failed server.
func TestDoHErrorMovesOn(t *testing.T) {
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	good := dohTestServer(t, nil)
	p := &dnsPool{servers: []dnsServer{
		{addr: "bad", doh: &dohEndpoint{url: bad.URL, hc: bad.Client()}},
		{addr: "good", doh: &dohEndpoint{url: good.URL, hc: good.Client()}},
	}}
	r := &net.Resolver{PreferGo: true, Dial: p.dial}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.7" {
		t.Fatalf("addresses = %v", addrs)
	}
}
