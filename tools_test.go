package v2tun

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"io.surprise.vpn/route"
)

// failoverDeadPort returns a TCP port nobody listens on.
func failoverDeadPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestBackupsTakeOverAndStick(t *testing.T) {
	cases := []struct {
		name string
		want int // ActiveOutbound once the live backup answered
		set  func(cfg *Config, dead, live Config)
	}{
		{"first backup", 1, func(cfg *Config, dead, live Config) { cfg.Backups = []Config{live} }},
		{"second backup after a dead one", 2, func(cfg *Config, dead, live Config) { cfg.Backups = []Config{dead, live} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "", "") })
			live := Config{Protocol: "socks5", Server: h, Port: p}
			dead := Config{Protocol: "socks5", Server: "127.0.0.1", Port: failoverDeadPort(t)}
			cfg := &Config{Protocol: "socks5", Server: "127.0.0.1", Port: failoverDeadPort(t)}
			tc.set(cfg, dead, live)
			cl, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			if cl.ActiveOutbound() != 0 {
				t.Fatalf("active before any connection: %d", cl.ActiveOutbound())
			}
			pxEcho(t, cl, "target.example:80")
			if got := cl.ActiveOutbound(); got != tc.want {
				t.Fatalf("active outbound %d, want %d", got, tc.want)
			}
		})
	}
}

func TestBackupsValidation(t *testing.T) {
	sub := func(port int) Config { return Config{Protocol: "socks5", Server: "127.0.0.1", Port: port} }
	bad := map[string]func(c *Config){
		"backups of backups": func(c *Config) {
			in := sub(2)
			in.Backups = []Config{sub(3)}
			c.Backups = []Config{in}
		},
		"an invalid backup": func(c *Config) {
			in := sub(2)
			in.Protocol = "nonsense"
			c.Backups = []Config{in}
		},
		"routing in a backup": func(c *Config) {
			in := sub(2)
			in.Routing = &route.Config{}
			c.Backups = []Config{in}
		},
		"udpgw in a backup": func(c *Config) {
			in := sub(2)
			in.UDPGW = "127.0.0.1:7300"
			c.Backups = []Config{in}
		},
		"directDns in a backup": func(c *Config) {
			in := sub(2)
			in.DirectDNS = "9.9.9.9:53"
			c.Backups = []Config{in}
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1}
			mutate(cfg)
			if cl, err := New(cfg); err == nil {
				cl.Close()
				t.Fatal("New must reject this config")
			}
		})
	}
}

func TestScanFindsTheWorkingValue(t *testing.T) {
	h, p := pxServeOnce(t, func(c net.Conn) { pxSocks5(c, "", "") })
	// 127.0.0.2 does not answer on the listener's port
	res := Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.2", Port: p},
		"server", []string{h, "127.0.0.2"}, "target.example:80", 2, 5*time.Second)
	if len(res) != 2 {
		t.Fatalf("%d results", len(res))
	}
	if !res[0].OK || res[0].Value != h {
		t.Fatalf("the listening address should work: %+v", res[0])
	}
	if res[1].OK || res[1].Error == "" {
		t.Fatalf("the other address should fail: %+v", res[1])
	}
}

func TestScanRejectsUnknownField(t *testing.T) {
	res := Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1},
		"nope", []string{"a"}, "x:1", 1, time.Second)
	if len(res) != 1 || res[0].OK || res[0].Error == "" {
		t.Fatalf("%+v", res)
	}
	res = Scan(context.Background(), &Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1},
		"payload.host", []string{"a"}, "x:1", 1, time.Second)
	if len(res) != 1 || res[0].OK || !strings.Contains(res[0].Error, "no payload") {
		t.Fatalf("scanning payload.host without a payload: %+v", res)
	}
}

func TestPreviewPayload(t *testing.T) {
	out, err := PreviewPayload(&Config{Protocol: "ssh", Server: "origin.example", Port: 80,
		Payload: &PayloadConfig{Template: sshWSPayload, Host: "bug.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"origin.example:80", "GET / HTTP/1.1", "Host: bug.example.com", "Upgrade: websocket",
		"expects 1 HTTP reply", "every status below 400 is accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview lacks %q:\n%s", want, out)
		}
	}
	out, err = PreviewPayload(&Config{Protocol: "ssh", Server: "origin.example", Port: 22,
		Payload: &PayloadConfig{Template: "CONNECT [host_port] HTTP/1.1[crlf][crlf]GET / HTTP/1.1[crlf]Upgrade: websocket[crlf][crlf]",
			Proxy: "1.2.3.4:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "the proxy 1.2.3.4:8080") || !strings.Contains(out, "expects 2 HTTP reply") {
		t.Errorf("proxy preview:\n%s", out)
	}
	out, err = PreviewPayload(&Config{Protocol: "ssh", Server: "origin.example", Port: 22,
		Payload: &PayloadConfig{Template: "GET / HTTP/1.1[crlf][delay=300]Host: bug.example.com[crlf][crlf]"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "segment 2") || !strings.Contains(out, "then waits 300 ms") {
		t.Errorf("a delay must show up in the preview:\n%s", out)
	}
	if _, err := PreviewPayload(&Config{Server: "x", Port: 1}); err == nil {
		t.Fatal("no payload must be reported")
	}
}

func TestSpeedTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1<<20))
	}))
	defer srv.Close()
	// route everything direct: the test needs the tunnel plumbing, not a server
	cl, err := New(&Config{Protocol: "socks5", Server: "127.0.0.1", Port: 1,
		Routing: &route.Config{Default: route.Direct}})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	n, bps, err := cl.SpeedTest(context.Background(), srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1<<20 || bps <= 0 {
		t.Fatalf("got %d bytes at %f bit/s", n, bps)
	}
}

// The SSH host key pin tests live in hostkey_test.go.
