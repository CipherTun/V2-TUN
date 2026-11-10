package v2tun

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"io.surprise.vpn/payload"
	"io.surprise.vpn/transport"
)

// ProbeStage is the result of one step of ProbeStages.
type ProbeStage struct {
	Name   string `json:"name"` // config, dns, tcp, payload, tls, banner, transport, tunnel
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"`
	Detail string `json:"detail,omitempty"` // one readable line
	Raw    string `json:"raw,omitempty"`    // what the server sent, as received
	Error  string `json:"error,omitempty"`
}

// ProbeReport is what ProbeStages returns. The stages stop at the first one
// that fails; Summary says which and what it usually means.
type ProbeReport struct {
	Stages  []ProbeStage `json:"stages"`
	OK      bool         `json:"ok"`
	Summary string       `json:"summary"`
}

// ProbeStages tests a config one layer at a time and reports each: DNS, the TCP
// connection, the payload and the server's raw reply, TLS (version, certificate,
// whether it verifies), the SSH banner, and finally a real request through the
// whole chain. It never touches a running tunnel and opens its own connections,
// one per stage group, so a server with a connection limit sees a few extra.
// The TLS stage uses Go's TLS, not the uTLS fingerprint. Backups are not tried.
func ProbeStages(ctx context.Context, cfg *Config) *ProbeReport {
	r := &ProbeReport{}
	add := func(name string, t0 time.Time, detail, raw string, err error) bool {
		st := ProbeStage{Name: name, OK: err == nil, Ms: time.Since(t0).Milliseconds(), Detail: detail, Raw: raw}
		if err != nil {
			st.Error = err.Error()
		}
		r.Stages = append(r.Stages, st)
		return err == nil
	}
	done := func() *ProbeReport {
		r.OK = true
		for _, s := range r.Stages {
			if !s.OK {
				r.OK = false
				r.Summary = fmt.Sprintf("Failed at %s: %s. %s", s.Name, s.Error, diagHint(s.Name))
				return r
			}
		}
		r.Summary = "Every stage passed."
		return r
	}

	if cfg.Server == "" || cfg.Port == 0 {
		add("config", time.Now(), "", "", errors.New("server and port are required"))
		return done()
	}
	dnsAddr := cfg.DirectDNS
	if dnsAddr == "" {
		dnsAddr = "1.1.1.1:53"
	}
	res := transport.NewResolver(dnsAddr)
	to := time.Duration(cfg.TimeoutSec) * time.Second
	if to == 0 {
		to = 15 * time.Second
	}
	net_ := strings.ToLower(cfg.Network)
	proto := strings.ToLower(cfg.Protocol)
	udp := proto == "hysteria" || proto == "hysteria1" || proto == "hy" || proto == "hysteria2" || proto == "hy2" ||
		net_ == "quic" || net_ == "kcp" || net_ == "mkcp"

	if udp {
		add("transport", time.Now(), "UDP based: the connection steps are covered by the tunnel check below", "", nil)
	} else {
		target := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
		connectAddr := target
		if p := cfg.Payload; p != nil && p.Proxy != "" {
			connectAddr = p.Proxy // the TCP connection goes to the remote proxy
		}
		host, port, err := net.SplitHostPort(connectAddr)
		if err != nil {
			add("config", time.Now(), "", "", fmt.Errorf("bad address %q: %w", connectAddr, err))
			return done()
		}

		ip := host
		if net.ParseIP(host) == nil {
			t0 := time.Now()
			sctx, cancel := context.WithTimeout(ctx, to)
			addrs, err := res.LookupIPAddr(sctx, host)
			cancel()
			if err == nil && len(addrs) == 0 {
				err = errors.New("no address found")
			}
			if err != nil {
				add("dns", t0, "", "", err)
				return done()
			}
			pick := addrs[0].IP
			var all []string
			for _, a := range addrs {
				all = append(all, a.IP.String())
				if pick.To4() == nil && a.IP.To4() != nil {
					pick = a.IP
				}
			}
			ip = pick.String()
			add("dns", t0, host+" resolves to "+strings.Join(all, ", "), "", nil)
		}

		t0 := time.Now()
		sctx, cancel := context.WithTimeout(ctx, to)
		c, err := (&transport.TCP{Timeout: to, Resolver: res}).DialContext(sctx, "tcp", net.JoinHostPort(ip, port))
		cancel()
		if !add("tcp", t0, "connected to "+net.JoinHostPort(ip, port), "", err) {
			return done()
		}
		var conn net.Conn = c
		defer func() { conn.Close() }()

		var pl *transport.Payload
		post := false
		if p := cfg.Payload; p != nil && p.Template != "" {
			var perr error
			pl, perr = diagPayloadLayer(cfg, net_, res)
			if perr != nil {
				add("payload", time.Now(), "", "", perr)
				return done()
			}
			post = p.Stage == "post-tls"
		}
		runPayload := func() bool {
			t0 := time.Now()
			sctx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			read := payloadExpectsReply(net_, cfg.Payload)
			wait := 8 * time.Second
			if to < wait {
				wait = to
			}
			raw, code, err := pl.ProbeSend(sctx, conn, target, read, wait)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					err = fmt.Errorf("the server did not answer the payload within %s", wait)
				}
				return add("payload", t0, "", raw, err)
			}
			if !read {
				return add("payload", t0, "payload sent; this config reads no reply", "", nil)
			}
			if !pl.Accepts(code) {
				return add("payload", t0, "", raw, fmt.Errorf("the reply has status %d, which the tunnel refuses (400 and above); list it in payload.acceptStatus if the server tunnels anyway", code))
			}
			return add("payload", t0, fmt.Sprintf("reply status %d accepted", code), raw, nil)
		}

		if pl != nil && !post && !runPayload() {
			return done()
		}
		switch {
		case cfg.Reality != nil:
			add("tls", time.Now(), "REALITY is not probed on its own; the tunnel check below covers it", "", nil)
		case cfg.TLS.Enabled:
			t0 := time.Now()
			tc, detail, err := diagTLS(ctx, cfg, net_, to, conn)
			if !add("tls", t0, detail, "", err) {
				return done()
			}
			conn = tc
		}
		if pl != nil && post && !runPayload() {
			return done()
		}

		if proto == "ssh" && (net_ == "" || net_ == "tcp") {
			t0 := time.Now()
			wait := 6 * time.Second
			if to < wait {
				wait = to
			}
			text, first, err := diagBanner(conn, wait)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					err = fmt.Errorf("no SSH banner within %s (first bytes: %s)", wait, diagPrintable(first))
				}
			} else if !strings.HasPrefix(text, "SSH-") {
				err = fmt.Errorf("the server's first bytes are not an SSH banner: %s", diagPrintable(first))
			}
			if !add("banner", t0, text, "", err) {
				return done()
			}
		}
		conn.Close() // the tunnel check below opens its own connection
	}

	t0 := time.Now()
	detail, err := diagTunnel(ctx, cfg, res)
	add("tunnel", t0, detail, "", err)
	return done()
}

// diagHint says what a failed stage usually means.
func diagHint(stage string) string {
	switch stage {
	case "config":
		return "The config itself is unusable."
	case "dns":
		return "The server name does not resolve: check the host name and the direct DNS."
	case "tcp":
		return "No TCP connection to the server: wrong port, server down, or the network blocks it."
	case "payload":
		return "The server did not accept the payload: check the payload, the host in it, and the port."
	case "tls":
		return "The TLS handshake or certificate check failed: check the SNI, the port, and whether the server speaks TLS there."
	case "banner":
		return "Nothing SSH came back after the earlier steps: the payload, TLS or WebSocket framing in front of SSH is probably wrong."
	case "tunnel":
		return "The connection opens but the tunnel does not work: for SSH this is the login or the server refusing forwarding; the log has the detail."
	}
	return ""
}

// diagALPN is the ALPN the real chain would offer.
func diagALPN(cfg *Config, net_ string) []string {
	if len(cfg.TLS.ALPN) > 0 {
		return cfg.TLS.ALPN
	}
	switch net_ {
	case "h2", "grpc", "xhttp", "splithttp":
		return []string{"h2"}
	case "ws", "websocket", "httpupgrade":
		return []string{"http/1.1"}
	}
	return nil
}

// diagPayloadLayer builds the payload layer the way baseChain does.
func diagPayloadLayer(cfg *Config, net_ string, res *net.Resolver) (*transport.Payload, error) {
	p := cfg.Payload
	tpl, err := payload.CompileCompat(p.Template)
	if err != nil {
		return nil, err
	}
	psni := cfg.TLS.SNI
	if cfg.Reality != nil && cfg.Reality.ServerName != "" {
		psni = cfg.Reality.ServerName
	}
	return &transport.Payload{Template: tpl, Host: p.Host, Method: p.Method, UserAgent: p.UserAgent,
		SNI: psni, Vars: p.Vars, ExpectResponse: payloadExpectsReply(net_, p), Responses: p.ExpectResponses,
		ViaProxy: p.Proxy != "", Resolver: res, AcceptStatus: p.AcceptStatus,
		SkipBody: p.SkipBody == nil || *p.SkipBody,
		AutoWS:   strings.EqualFold(cfg.Protocol, "ssh") && (net_ == "" || net_ == "tcp")}, nil
}

// diagTLS runs the handshake the config asks for and describes the result. A
// certificate that does not verify fails the stage unless allowInsecure is set.
func diagTLS(ctx context.Context, cfg *Config, net_ string, to time.Duration, conn net.Conn) (net.Conn, string, error) {
	sni := cfg.TLS.SNI
	if sni == "" {
		sni = cfg.Server
	}
	tc := tls.Client(conn, &tls.Config{ServerName: sni, NextProtos: diagALPN(cfg, net_), InsecureSkipVerify: true})
	sctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	if err := tc.HandshakeContext(sctx); err != nil {
		return conn, "", fmt.Errorf("TLS handshake with SNI %q failed: %w", sni, err)
	}
	st := tc.ConnectionState()
	detail := fmt.Sprintf("%s, SNI %q", tls.VersionName(st.Version), sni)
	if st.NegotiatedProtocol != "" {
		detail += ", ALPN " + st.NegotiatedProtocol
	}
	if len(st.PeerCertificates) == 0 {
		return tc, detail, errors.New("the server sent no certificate")
	}
	c0 := st.PeerCertificates[0]
	names := c0.DNSNames
	if len(names) > 3 {
		names = names[:3]
	}
	detail += fmt.Sprintf(", certificate %q from %q valid until %s", c0.Subject.CommonName, c0.Issuer.CommonName, c0.NotAfter.Format("2006-01-02"))
	if len(names) > 0 {
		detail += " for " + strings.Join(names, ", ")
	}
	name := sni
	if cfg.TLS.VerifyName != "" {
		name = cfg.TLS.VerifyName
	}
	pool := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		pool.AddCert(c)
	}
	if _, err := c0.Verify(x509.VerifyOptions{DNSName: name, Intermediates: pool}); err != nil {
		if cfg.TLS.AllowInsecure {
			return tc, detail + "; does not verify for " + name + " (ignored, allowInsecure is on)", nil
		}
		return tc, detail, fmt.Errorf("the certificate does not verify for %q (%v); fix the SNI or set tls.allowInsecure", name, err)
	}
	if cfg.TLS.Fingerprint != "" {
		detail += "; the probe uses Go's TLS, not the " + cfg.TLS.Fingerprint + " fingerprint"
	}
	return tc, detail + "; verifies for " + name, nil
}

// diagBanner reads the server's first line (an SSH banner), unwrapping one
// WebSocket frame when the stream is framed. It returns the text and the raw
// bytes it read.
func diagBanner(c net.Conn, wait time.Duration) (string, []byte, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	one := make([]byte, 1)
	framed := false
	for len(buf) < 300 {
		n, err := c.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if len(buf) == 2 && (buf[0] == 0x81 || buf[0] == 0x82) && buf[1] < 126 {
				framed = true
			}
			if framed {
				if len(buf) >= 2+int(buf[1]) {
					return strings.TrimSpace(string(buf[2:])), buf, nil
				}
			} else if one[0] == '\n' {
				return strings.TrimSpace(string(buf)), buf, nil
			}
		}
		if err != nil {
			return "", buf, err
		}
	}
	return "", buf, errors.New("no end of line in the first 300 bytes")
}

// diagPrintable shows the first bytes of a reply as hex and text.
func diagPrintable(b []byte) string {
	if len(b) == 0 {
		return "nothing received"
	}
	if len(b) > 24 {
		b = b[:24]
	}
	var hx, tx strings.Builder
	for i, c := range b {
		if i > 0 {
			hx.WriteByte(' ')
		}
		fmt.Fprintf(&hx, "%02x", c)
		if c >= 0x20 && c < 0x7f {
			tx.WriteByte(c)
		} else {
			tx.WriteByte('.')
		}
	}
	return hx.String() + " (" + tx.String() + ")"
}

// diagTunnel builds the whole chain from the config and fetches a small page
// through it, like the app's traffic check does.
func diagTunnel(ctx context.Context, cfg *Config, res *net.Resolver) (string, error) {
	out, _, err := buildOutbound(cfg, res)
	if err != nil {
		return "", err
	}
	if cl, ok := out.(io.Closer); ok {
		defer cl.Close()
	}
	tctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	conn, err := out.DialContext(tctx, "tcp", "cp.cloudflare.com:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, "GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n"); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("the tunnel opened but no reply came back: %w", err)
	}
	return "reply through the tunnel: " + strings.TrimSpace(line), nil
}
