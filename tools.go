package v2tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"io.surprise.vpn/payload"
)

// ProbeResult is the outcome of one probe or one scanned value.
type ProbeResult struct {
	Value  string `json:"value,omitempty"` // the value tried (scan only)
	OK     bool   `json:"ok"`
	Millis int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
}

// Probe builds a client from cfg and checks that it works. A target that is
// an http:// or https:// URL is fetched through the tunnel (proving that data
// flows); anything else is a host:port that is only dialed (proving that the
// tunnel comes up: payload accepted, login done).
func Probe(ctx context.Context, cfg *Config, target string) ProbeResult {
	t0 := time.Now()
	ms := func() int64 { return time.Since(t0).Milliseconds() }
	c, err := New(cfg)
	if err != nil {
		return ProbeResult{Error: err.Error()}
	}
	defer c.Close()
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if _, err := c.Ping(ctx, target); err != nil {
			return ProbeResult{Millis: ms(), Error: err.Error()}
		}
		return ProbeResult{OK: true, Millis: ms()}
	}
	conn, err := c.DialContext(ctx, "tcp", target)
	if err != nil {
		return ProbeResult{Millis: ms(), Error: err.Error()}
	}
	conn.Close()
	return ProbeResult{OK: true, Millis: ms()}
}

// withField returns a copy of cfg with one value replaced. Fields: server,
// tls.sni (also the REALITY server name), ws.host, payload.host, payload.proxy.
func withField(cfg *Config, field, value string) (*Config, error) {
	c := *cfg
	switch strings.ToLower(field) {
	case "server":
		c.Server = value
	case "tls.sni":
		c.TLS.SNI = value
		if c.Reality != nil {
			r := *c.Reality
			r.ServerName = value
			c.Reality = &r
		}
	case "ws.host":
		c.WS.Host = value
	case "payload.host", "payload.proxy":
		if c.Payload == nil {
			return nil, errors.New("v2tun: the config has no payload to scan")
		}
		p := *c.Payload
		if strings.EqualFold(field, "payload.host") {
			p.Host = value
		} else {
			p.Proxy = value
		}
		c.Payload = &p
	default:
		return nil, fmt.Errorf("v2tun: unknown scan field %q (server, tls.sni, ws.host, payload.host, payload.proxy)", field)
	}
	return &c, nil
}

// Scan probes cfg once per value, with that value in field, a few at a time.
// Use it to find which bug host, SNI or proxy a network lets through. The
// results are in the order of values.
func Scan(ctx context.Context, cfg *Config, field string, values []string, target string, concurrency int, perTry time.Duration) []ProbeResult {
	if concurrency <= 0 {
		concurrency = 3
	}
	if perTry <= 0 {
		perTry = 15 * time.Second
	}
	res := make([]ProbeResult, len(values))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, v := range values {
		i, v := i, v
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := withField(cfg, field, v)
			if err != nil {
				res[i] = ProbeResult{Value: v, Error: err.Error()}
				return
			}
			cx, cancel := context.WithTimeout(ctx, perTry)
			defer cancel()
			r := Probe(cx, c, target)
			r.Value = v
			res[i] = r
		}()
	}
	wg.Wait()
	return res
}

var previewRequestLine = regexp.MustCompile(`(?m)^[A-Za-z]+ \S+ HTTP/1\.[01]\r?$`)

// PreviewPayload shows what the payload of cfg would send, segment by segment
// (with the pause after each one), where it would go, and whether and how its
// HTTP replies are checked. Nothing is sent.
func PreviewPayload(cfg *Config) (string, error) {
	p := cfg.Payload
	if p == nil || p.Template == "" {
		return "", errors.New("v2tun: no payload configured")
	}
	tpl, err := payload.CompileCompat(p.Template)
	if err != nil {
		return "", err
	}
	sni := cfg.TLS.SNI
	if cfg.Reality != nil && cfg.Reality.ServerName != "" {
		sni = cfg.Reality.ServerName
	}
	host := cfg.Server
	if p.Host != "" {
		host = p.Host
	}
	segs := tpl.Render(payload.Context{Host: host, Port: cfg.Port, Server: cfg.Server, ServerPort: cfg.Port,
		IP: cfg.Server, SNI: sni, Method: p.Method, UserAgent: p.UserAgent, Vars: p.Vars})

	var b strings.Builder
	dest := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
	if p.Proxy != "" {
		fmt.Fprintf(&b, "TCP connection to the proxy %s; the payload names %s\n", p.Proxy, dest)
	} else {
		fmt.Fprintf(&b, "TCP connection to %s\n", dest)
	}
	stage := p.Stage
	if stage == "" {
		stage = "pre-tls"
	}
	fmt.Fprintf(&b, "stage: %s\n", stage)
	var all []byte
	for i, s := range segs {
		fmt.Fprintf(&b, "segment %d (%d bytes): %s\n", i+1, len(s.Data), strconv.Quote(string(s.Data)))
		if s.Delay > 0 {
			fmt.Fprintf(&b, "  then waits %d ms\n", s.Delay/time.Millisecond)
		}
		all = append(all, s.Data...)
	}
	if payloadExpectsReply(strings.ToLower(cfg.Network), p) {
		n := p.ExpectResponses
		if n <= 0 {
			n = len(previewRequestLine.FindAll(all, -1))
			if n < 1 {
				n = 1
			}
			if n > 4 {
				n = 4
			}
		}
		fmt.Fprintf(&b, "expects %d HTTP reply(ies); every status below 400 is accepted\n", n)
	} else {
		b.WriteString("expects no HTTP reply\n")
	}
	return b.String(), nil
}

// SpeedTest downloads rawURL through the tunnel for up to d and returns the
// bytes received and the average speed in bits per second. An empty URL uses
// Cloudflare's speed test endpoint.
func (c *Client) SpeedTest(ctx context.Context, rawURL string, d time.Duration) (int64, float64, error) {
	if rawURL == "" {
		rawURL = "https://speed.cloudflare.com/__down?bytes=50000000"
	}
	if d <= 0 {
		d = 10 * time.Second
	}
	cx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	hc := &http.Client{Transport: &http.Transport{DialContext: c.DialContext, DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(cx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, 0, err
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body) // ends at EOF or when the time is up
	el := time.Since(t0).Seconds()
	if n == 0 || el <= 0 {
		return 0, 0, errors.New("v2tun: no data received")
	}
	return n, float64(n) * 8 / el, nil
}
