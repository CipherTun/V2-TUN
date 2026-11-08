package v2tun

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestSplitEarlyData(t *testing.T) {
	cases := []struct {
		in   string
		path string
		ed   int
	}{
		{"/ws", "/ws", 0},
		{"/ws?ed=2048", "/ws", 2048},
		{"/ws?a=1&ed=2560&b=2", "/ws?a=1&b=2", 2560},
		{"/ws?ed=0", "/ws?ed=0", 0},
		{"/ws?ed=x", "/ws?ed=x", 0},
		{"/ws?red=5", "/ws?red=5", 0},
	}
	for _, c := range cases {
		p, ed := splitEarlyData(c.in)
		if p != c.path || ed != c.ed {
			t.Errorf("splitEarlyData(%q) = %q, %d; want %q, %d", c.in, p, ed, c.path, c.ed)
		}
	}
}

func TestParseLinkGRPCMulti(t *testing.T) {
	cfg, _, err := ParseLink("vless://11111111-1111-1111-1111-111111111111@h.example:443?type=grpc&serviceName=svc&mode=multi&security=tls#n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GRPCMulti || cfg.GRPCService != "svc" {
		t.Errorf("multi=%v service=%q; want multi svc", cfg.GRPCMulti, cfg.GRPCService)
	}
	cfg, _, err = ParseLink("vless://11111111-1111-1111-1111-111111111111@h.example:443?type=grpc&serviceName=svc&mode=gun&security=tls")
	if err != nil || cfg.GRPCMulti {
		t.Errorf("mode=gun: multi=%v err=%v; want gun", cfg.GRPCMulti, err)
	}
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"n","add":"h.example","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"grpc","type":"multi","path":"svc","tls":"tls"}`))
	cfg, _, err = ParseLink("vmess://" + vm)
	if err != nil || !cfg.GRPCMulti || cfg.GRPCService != "svc" {
		t.Errorf("vmess grpc multi: %+v, %v", cfg, err)
	}
}

func TestParseLinkXHTTPExtra(t *testing.T) {
	extra := `{"xPaddingBytes":"200-400","scMaxEachPostBytes":"500000-900000","scMinPostsIntervalMs":50,` +
		`"headers":{"X-Test":"1"},"downloadSettings":{"address":"dl.example","port":8443,"network":"xhttp","security":"tls",` +
		`"tlsSettings":{"serverName":"dl.example","alpn":["h2"],"fingerprint":"chrome"},` +
		`"xhttpSettings":{"host":"dl.example","path":"/dl","mode":"auto"}}}`
	link := "vless://11111111-1111-1111-1111-111111111111@up.example:443?type=xhttp&mode=packet-up&path=%2Fup&security=tls&extra=" + url.QueryEscape(extra)
	cfg, _, err := ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.XHTTP
	if o == nil || o.XPaddingBytes != [2]int{200, 400} || o.ScMaxEachPostBytes != 500000 || o.ScMinPostsIntervalMs != 50 {
		t.Fatalf("options = %+v", o)
	}
	if cfg.WS.Headers["X-Test"] != "1" {
		t.Errorf("headers = %v", cfg.WS.Headers)
	}
	dl := o.Download
	if dl == nil || dl.Server != "dl.example" || dl.Port != 8443 || !dl.TLS.Enabled || dl.TLS.SNI != "dl.example" ||
		dl.TLS.Fingerprint != "chrome" || dl.Host != "dl.example" || dl.Path != "/dl" {
		t.Fatalf("download = %+v", dl)
	}
}

func TestParseLinkXHTTPExtraErrors(t *testing.T) {
	for _, extra := range []string{
		`{not json`,
		`{"downloadSettings":{"network":"ws"}}`,
		`{"downloadSettings":{"security":"reality","realitySettings":{}}}`,
		`{"downloadSettings":{"security":"weird"}}`,
	} {
		link := "vless://11111111-1111-1111-1111-111111111111@h.example:443?type=xhttp&security=tls&extra=" + url.QueryEscape(extra)
		if _, _, err := ParseLink(link); err == nil {
			t.Errorf("extra %s was accepted", extra)
		}
	}
}

func TestXHTTPDownloadRejectsStreamOne(t *testing.T) {
	cfg := &Config{Protocol: "vless", UUID: "11111111-1111-1111-1111-111111111111", Server: "h.example", Port: 443,
		Network: "xhttp", XHTTPMode: "stream-one", TLS: TLSConfig{Enabled: true},
		XHTTP: &XHTTPOptions{Download: &XHTTPDownloadConfig{Server: "dl.example", TLS: TLSConfig{Enabled: true}}}}
	if _, _, err := buildOutbound(cfg, nil); err == nil {
		t.Fatal("stream-one with download settings was accepted")
	}
}

func TestBuildOutboundWSEarlyDataFromPath(t *testing.T) {
	cfg := &Config{Protocol: "vless", UUID: "11111111-1111-1111-1111-111111111111", Server: "h.example", Port: 80,
		Network: "ws", WS: WSConfig{Path: "/ws?ed=2048"}}
	if _, _, err := buildOutbound(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
