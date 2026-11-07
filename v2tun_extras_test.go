package v2tun

import (
	"encoding/json"
	"testing"

	"io.surprise.vpn/proxy"
)

func TestSSHNextBuildsDoubleHop(t *testing.T) {
	cfg := &Config{Protocol: "ssh", Server: "jump.example", Port: 22, Username: "u", Password: "p"}

	// without sshNext it stays a plain single SSH outbound
	out, _, err := buildOutbound(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.(*proxy.SSH); !ok {
		t.Fatalf("single hop: got %T", out)
	}

	cfg.Advanced.SSHNext = &SSHHop{Server: "target.example:22", Username: "u2", Password: "p2"}
	out, _, err = buildOutbound(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	dh, ok := out.(*proxy.DoubleHop)
	if !ok {
		t.Fatalf("double hop: got %T", out)
	}
	if dh.Jump.Server != "jump.example:22" || dh.Target.Server != "target.example:22" {
		t.Fatalf("hops: %q then %q", dh.Jump.Server, dh.Target.Server)
	}
	if dh.Target.Dialer != dh.Jump {
		t.Fatal("the target must be dialed through the jump host")
	}
}

func TestSSHNextValidation(t *testing.T) {
	cfg := &Config{Protocol: "ssh", Server: "jump.example", Port: 22, Username: "u", Password: "p"}
	cfg.Advanced.SSHNext = &SSHHop{Server: "no-port"}
	if _, _, err := buildOutbound(cfg, nil); err == nil {
		t.Error("sshNext.server without a port must be rejected")
	}
	cfg.Advanced.SSHNext = &SSHHop{Server: "target.example:22", HostKey: "not-a-pin"}
	if _, _, err := buildOutbound(cfg, nil); err == nil {
		t.Error("a malformed sshNext.hostKey must be rejected")
	}
}

func TestProbeAddr(t *testing.T) {
	c := &Config{Protocol: "ssh", Server: "a.example", Port: 22}
	if got := probeAddr(c); got != "a.example:22" {
		t.Errorf("server: %q", got)
	}
	c.Payload = &PayloadConfig{Template: "@connect", Proxy: "10.0.0.1:8080"}
	if got := probeAddr(c); got != "10.0.0.1:8080" {
		t.Errorf("payload proxy: %q", got)
	}
	if got := probeAddr(&Config{Protocol: "hysteria2", Server: "h.example", Port: 443}); got != "" {
		t.Errorf("hysteria cannot be probed over TCP: %q", got)
	}
	if got := probeAddr(&Config{Protocol: "vless", Network: "quic", Server: "q.example", Port: 443}); got != "" {
		t.Errorf("quic cannot be probed over TCP: %q", got)
	}
}

func TestNewConfigKeysParse(t *testing.T) {
	var cfg Config
	err := json.Unmarshal([]byte(`{
		"protocol": "ssh", "server": "jump.example", "port": 22,
		"idleTimeoutSec": 45, "latencySortSec": 30,
		"ws": {"pingSec": 20},
		"advanced": {"sshNext": {"server": "target.example:22", "username": "u", "password": "p"}}
	}`), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdleTimeoutSec != 45 || cfg.LatencySortSec != 30 || cfg.WS.PingSec != 20 {
		t.Fatalf("got idle=%d latency=%d ping=%d", cfg.IdleTimeoutSec, cfg.LatencySortSec, cfg.WS.PingSec)
	}
	if cfg.Advanced.SSHNext == nil || cfg.Advanced.SSHNext.Server != "target.example:22" {
		t.Fatalf("sshNext: %+v", cfg.Advanced.SSHNext)
	}
}
