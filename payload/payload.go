// Package payload is the built-in payload engine of v2-tun.
// It compiles HTTP-Injector / HTTP-Custom style templates into timed segments.
//
// Tags are case-insensitive, may be nested ([b64=[host]:[port]]) and unknown
// tags are kept as literal text. A tag may carry a multiplier: [crlf*2].
// Write a literal bracket as \[ and \]. Plain text understands \r \n \t \0 \\
// and \xHH.
//
// Line endings and whitespace
//
//	[crlf] [cr] [lf] [lfcr] [tab] [space]
//
// Target and request values
//
//	[host]                 payload host (bug host) if set, else the server host
//	[port] [host_port]     server port, [host]:port (IPv6 gets brackets)
//	[server]               the real server host, never replaced by the payload host
//	[server_port]          the real server port
//	[server_host_port]     the real server host:port (IPv6 gets brackets)
//	[ip] [ip_port]         resolved address of the real server (also behind a
//	                       remote proxy, where the connection itself goes to the proxy)
//	[sni]                  TLS SNI (falls back to [host])
//	[method] [protocol]    configured method (default GET), HTTP/1.1
//	[get] [post] [put] [head] [options] [delete] [patch] [connect] [trace]
//	[netData] [raw] [realData]   request line: "<method|CONNECT> [host_port] HTTP/1.1"
//	[ua]                   configured User-Agent (a mobile Chrome one by default)
//	[rand_ua]              random browser User-Agent per connection
//	[ws_key]               random Sec-WebSocket-Key
//
// Timing and splitting
//
//	[split] [instant_split]       send what came before now as its own TCP segment
//	[delay=MS]                    split and wait (500, 500ms, 1.5s; default 1s)
//	[delay_split] [split_delay]   same as [delay]; [delay_split=300] sets the time
//
// Random, rotating and generated values
//
//	[random=a|b|c]         random pick per connection
//	[rotate=a|b|c]         round-robin pick (each tag keeps its own counter)
//	[rand_int=10-99]       random integer in range
//	[rand_hex=N] [rand_str=N] [rand_alpha=N] [rand_num=N]   N random characters
//	[rand_ip]              random public-looking IPv4 address
//	[uuid]                 random UUID v4
//	[timestamp] [timestamp_ms]   unix time
//	[date] [date=iso] [date=unix]   HTTP date, RFC 3339, unix seconds
//
// Encoding and text helpers
//
//	[b64=text] [b64url=text] [urlenc=text] [hex=text]
//	[upper=text] [lower=text]
//	[basic=user:pass]      "Basic <base64>" for Authorization headers
//	[bytes=16 03 01]       raw bytes from hex (spaces, commas, 0x allowed)
//	[var=name]             value from PayloadConfig.vars
//
// Blocks
//
//	[repeat=N]text[/repeat]   repeat text N times (N <= 1000, blocks may nest)
//
// There are no built-in presets: the payload is exactly what the user writes.
// [host] is the bug host when one is set; use [server], [server_port] or
// [server_host_port] where the request must name the real SSH/proxy target
// (for example "CONNECT [server_host_port] HTTP/1.1" through a remote proxy
// while "Host: [host]" carries the bug host).
package payload

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	maxParts  = 100000
	maxDepth  = 8
	maxDelay  = 60 * time.Second
	defaultUA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"
)

var userAgents = []string{
	defaultUA,
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"okhttp/4.12.0",
}

// Context holds per-connection values for tag substitution.
type Context struct {
	Host       string // [host]: the payload host (bug host) if set, else the server host
	Port       int
	Server     string // [server]: the real server host; falls back to Host
	ServerPort int    // [server_port]; falls back to Port
	IP         string // resolved address of the real server; falls back to Server
	SNI        string // falls back to Host
	Method     string
	Protocol   string
	UserAgent  string
	Vars       map[string]string
}

// Segment is one write to the wire followed by an optional pause.
type Segment struct {
	Data  []byte
	Delay time.Duration
}

type part struct {
	tag  string // empty => literal text
	arg  string
	text string
	n    int         // multiplier for [crlf*2]
	subs []*Template // compiled arguments (options for random/rotate)
	ctr  *atomic.Uint64
}

// Template is a compiled payload.
type Template struct {
	parts []part
}

var simpleTags = map[string]bool{
	"crlf": true, "cr": true, "lf": true, "lfcr": true, "tab": true, "space": true,
	"host": true, "port": true, "host_port": true, "ip": true, "ip_port": true, "sni": true,
	"server": true, "server_port": true, "server_host_port": true,
	"method": true, "protocol": true, "ua": true, "rand_ua": true, "random_ua": true,
	"netdata": true, "raw": true, "realdata": true,
	"get": true, "post": true, "put": true, "head": true, "options": true,
	"delete": true, "patch": true, "connect": true, "trace": true,
	"split": true, "instant_split": true,
	"ws_key": true, "uuid": true, "timestamp": true, "timestamp_ms": true, "rand_ip": true,
}

// Compile parses a payload template.
func Compile(tpl string) (*Template, error) {
	// Presets were removed. A bare "@name" would otherwise be sent to the
	// server as literal text, so refuse it with a clear reason.
	if t := strings.TrimSpace(tpl); strings.HasPrefix(t, "@") && !strings.ContainsAny(t, "[] \t\r\n\\") {
		return nil, fmt.Errorf("payload: presets (%s) are not supported; write the payload yourself", t)
	}
	return compile(tpl, 0)
}

// Validate reports whether tpl compiles.
func Validate(tpl string) error {
	_, err := Compile(tpl)
	return err
}

func compile(tpl string, depth int) (*Template, error) {
	if depth > maxDepth {
		return nil, errors.New("payload: tags nested too deeply")
	}
	t := &Template{}
	for len(tpl) > 0 {
		i := indexTag(tpl)
		if i < 0 {
			t.parts = append(t.parts, part{text: tpl})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{text: tpl[:i]})
		}
		j := matchBracket(tpl, i)
		if j < 0 {
			return nil, fmt.Errorf("payload: unclosed tag near %q", clip(tpl[i:]))
		}
		body := tpl[i+1 : j]
		tpl = tpl[j+1:]

		name, arg, hasArg := strings.Cut(body, "=")
		name = asciiLower(strings.TrimSpace(name))
		n := 1
		if k := strings.IndexByte(name, '*'); k > 0 {
			c, err := strconv.Atoi(name[k+1:])
			if err != nil || c < 0 || c > 100 {
				return nil, fmt.Errorf("payload: bad multiplier in [%s]", body)
			}
			name, n = name[:k], c
		}

		if name == "repeat" {
			cnt, err := strconv.Atoi(strings.TrimSpace(arg))
			if err != nil || cnt < 0 || cnt > 1000 {
				return nil, fmt.Errorf("payload: bad repeat count %q", arg)
			}
			end := findRepeatEnd(tpl)
			if end < 0 {
				return nil, errors.New("payload: [repeat] without [/repeat]")
			}
			sub, err := compile(tpl[:end], depth+1)
			if err != nil {
				return nil, err
			}
			tpl = tpl[end+len("[/repeat]"):]
			for k := 0; k < cnt; k++ {
				t.parts = append(t.parts, sub.parts...)
				if len(t.parts) > maxParts {
					return nil, errors.New("payload: template expands too large")
				}
			}
			continue
		}

		p, ok, err := makePart(name, arg, hasArg, n, depth)
		if err != nil {
			return nil, err
		}
		if !ok { // unknown tag: keep as literal text
			t.parts = append(t.parts, part{text: "[" + body + "]"})
			continue
		}
		t.parts = append(t.parts, p)
		if len(t.parts) > maxParts {
			return nil, errors.New("payload: template expands too large")
		}
	}
	return t, nil
}

func makePart(name, arg string, hasArg bool, n, depth int) (part, bool, error) {
	p := part{tag: name, arg: arg, n: n}
	if simpleTags[name] {
		return p, true, nil
	}
	switch name {
	case "delay", "delay_split", "split_delay":
		if _, err := parseDelay(arg, time.Second); err != nil {
			return p, false, err
		}
		return p, true, nil
	case "rand_int", "random_int":
		p.tag = "rand_int"
		if _, _, err := parseRange(arg); err != nil {
			return p, false, fmt.Errorf("payload: bad range %q", arg)
		}
		return p, true, nil
	case "rand_hex", "rand_str", "rand_alpha", "rand_num":
		c, err := strconv.Atoi(strings.TrimSpace(arg))
		if err != nil || c < 0 || c > 4096 {
			return p, false, fmt.Errorf("payload: bad length %q for [%s]", arg, name)
		}
		return p, true, nil
	case "random", "rotate":
		for _, o := range splitTop(arg, '|') {
			sub, err := compile(o, depth+1)
			if err != nil {
				return p, false, err
			}
			p.subs = append(p.subs, sub)
		}
		if name == "rotate" {
			p.ctr = new(atomic.Uint64)
		}
		return p, true, nil
	case "b64", "b64url", "urlenc", "hex", "upper", "lower", "basic":
		sub, err := compile(arg, depth+1)
		if err != nil {
			return p, false, err
		}
		p.subs = []*Template{sub}
		return p, true, nil
	case "bytes":
		if _, err := decodeHexArg(arg); err != nil {
			return p, false, fmt.Errorf("payload: bad hex in [bytes=%s]", arg)
		}
		return p, true, nil
	case "var", "date":
		return p, true, nil
	}
	return p, false, nil
}

// ---- rendering ----

type renderer struct {
	c         Context
	netMethod string
	segs      []Segment
	cur       []byte
	textOnly  bool // nested argument: ignore splits and delays
}

func (r *renderer) flush(d time.Duration) {
	if len(r.cur) > 0 || d > 0 {
		r.segs = append(r.segs, Segment{Data: r.cur, Delay: d})
		r.cur = nil
	}
}

func (r *renderer) w(s string) { r.cur = append(r.cur, s...) }

func (r *renderer) text(t *Template) string {
	s := &renderer{c: r.c, netMethod: r.netMethod, textOnly: true}
	t.emit(s)
	return string(s.cur)
}

func (t *Template) emit(r *renderer) {
	for i := range t.parts {
		p := &t.parts[i]
		if p.tag == "" {
			r.cur = append(r.cur, unescape(p.text)...)
			continue
		}
		r.tag(p)
	}
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func hostPort(host string, port int) string {
	if port == 0 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (r *renderer) tag(p *part) {
	c := &r.c
	rep := func(s string) {
		for k := 0; k < p.n; k++ {
			r.w(s)
		}
	}
	switch p.tag {
	case "crlf":
		rep("\r\n")
	case "cr":
		rep("\r")
	case "lf":
		rep("\n")
	case "lfcr":
		rep("\n\r")
	case "tab":
		rep("\t")
	case "space":
		rep(" ")
	case "host":
		r.w(c.Host)
	case "port":
		r.w(strconv.Itoa(c.Port))
	case "host_port":
		r.w(hostPort(c.Host, c.Port))
	case "server":
		r.w(c.Server)
	case "server_port":
		r.w(strconv.Itoa(c.ServerPort))
	case "server_host_port":
		r.w(hostPort(c.Server, c.ServerPort))
	case "ip":
		r.w(orStr(c.IP, c.Server))
	case "ip_port":
		r.w(hostPort(orStr(c.IP, c.Server), c.ServerPort))
	case "sni":
		r.w(orStr(c.SNI, c.Host))
	case "method":
		r.w(c.Method)
	case "protocol":
		r.w(c.Protocol)
	case "get", "post", "put", "head", "options", "delete", "patch", "connect", "trace":
		r.w(strings.ToUpper(p.tag))
	case "netdata", "raw", "realdata":
		r.w(r.netMethod + " " + hostPort(c.Host, c.Port) + " " + c.Protocol)
	case "ua":
		r.w(c.UserAgent)
	case "rand_ua", "random_ua":
		r.w(userAgents[mrand.Intn(len(userAgents))])
	case "ws_key":
		b := make([]byte, 16)
		rand.Read(b)
		r.w(base64.StdEncoding.EncodeToString(b))
	case "uuid":
		r.w(newUUID())
	case "timestamp":
		r.w(strconv.FormatInt(time.Now().Unix(), 10))
	case "timestamp_ms":
		r.w(strconv.FormatInt(time.Now().UnixMilli(), 10))
	case "date":
		now := time.Now()
		switch asciiLower(strings.TrimSpace(p.arg)) {
		case "unix":
			r.w(strconv.FormatInt(now.Unix(), 10))
		case "iso", "rfc3339":
			r.w(now.UTC().Format(time.RFC3339))
		default:
			r.w(now.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
		}
	case "rand_ip":
		r.w(fmt.Sprintf("%d.%d.%d.%d", 1+mrand.Intn(222), mrand.Intn(256), mrand.Intn(256), 1+mrand.Intn(254)))
	case "split", "instant_split":
		if !r.textOnly {
			r.flush(0)
		}
	case "delay", "delay_split", "split_delay":
		if !r.textOnly {
			d, _ := parseDelay(p.arg, time.Second)
			r.flush(d)
		}
	case "random":
		if len(p.subs) > 0 {
			r.w(r.text(p.subs[mrand.Intn(len(p.subs))]))
		}
	case "rotate":
		if len(p.subs) > 0 {
			k := p.ctr.Add(1) - 1
			r.w(r.text(p.subs[int(k%uint64(len(p.subs)))]))
		}
	case "rand_int":
		lo, hi, _ := parseRange(p.arg)
		r.w(strconv.Itoa(lo + mrand.Intn(hi-lo+1)))
	case "rand_hex":
		n, _ := strconv.Atoi(strings.TrimSpace(p.arg))
		r.w(randFrom("0123456789abcdef", n))
	case "rand_str":
		n, _ := strconv.Atoi(strings.TrimSpace(p.arg))
		r.w(randFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n))
	case "rand_alpha":
		n, _ := strconv.Atoi(strings.TrimSpace(p.arg))
		r.w(randFrom("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", n))
	case "rand_num":
		n, _ := strconv.Atoi(strings.TrimSpace(p.arg))
		r.w(randFrom("0123456789", n))
	case "b64":
		r.w(base64.StdEncoding.EncodeToString([]byte(r.text(p.subs[0]))))
	case "b64url":
		r.w(base64.RawURLEncoding.EncodeToString([]byte(r.text(p.subs[0]))))
	case "urlenc":
		r.w(url.QueryEscape(r.text(p.subs[0])))
	case "hex":
		r.w(hex.EncodeToString([]byte(r.text(p.subs[0]))))
	case "upper":
		r.w(strings.ToUpper(r.text(p.subs[0])))
	case "lower":
		r.w(strings.ToLower(r.text(p.subs[0])))
	case "basic":
		r.w("Basic " + base64.StdEncoding.EncodeToString([]byte(r.text(p.subs[0]))))
	case "bytes":
		b, _ := decodeHexArg(p.arg)
		r.cur = append(r.cur, b...)
	case "var":
		r.w(c.Vars[strings.TrimSpace(p.arg)])
	}
}

// Render expands the template into segments.
func (t *Template) Render(c Context) []Segment {
	netMethod := c.Method
	if netMethod == "" {
		netMethod = "CONNECT"
	}
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.Server == "" {
		c.Server = c.Host
	}
	if c.ServerPort == 0 {
		c.ServerPort = c.Port
	}
	if c.Protocol == "" {
		c.Protocol = "HTTP/1.1"
	}
	if c.UserAgent == "" {
		c.UserAgent = defaultUA
	}
	r := &renderer{c: c, netMethod: netMethod}
	t.emit(r)
	r.flush(0)
	return r.segs
}

// Preview renders the template and describes the result in readable form.
func (t *Template) Preview(c Context) string { return Describe(t.Render(c)) }

// Describe turns segments into text with visible control characters and
// markers where the payload is split or paused.
func Describe(segs []Segment) string {
	var b strings.Builder
	for i, s := range segs {
		for _, ch := range s.Data {
			switch {
			case ch == '\r':
				b.WriteString("\\r")
			case ch == '\n':
				b.WriteString("\\n\n")
			case ch < 0x20 || ch > 0x7e:
				fmt.Fprintf(&b, "\\x%02x", ch)
			default:
				b.WriteByte(ch)
			}
		}
		switch {
		case s.Delay > 0:
			fmt.Fprintf(&b, "\n--- wait %dms ---\n", s.Delay/time.Millisecond)
		case i < len(segs)-1:
			b.WriteString("\n--- split ---\n")
		}
	}
	return b.String()
}

// SendContext writes rendered segments to w honoring delays and ctx.
func SendContext(ctx context.Context, w io.Writer, segs []Segment) error {
	for _, s := range segs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(s.Data) > 0 {
			if _, err := w.Write(s.Data); err != nil {
				return err
			}
		}
		if s.Delay > 0 {
			tm := time.NewTimer(s.Delay)
			select {
			case <-tm.C:
			case <-ctx.Done():
				tm.Stop()
				return ctx.Err()
			}
		}
	}
	return nil
}

// Send writes rendered segments to w honoring delays.
func Send(w io.Writer, segs []Segment) error {
	return SendContext(context.Background(), w, segs)
}

// ReadHTTPHeaders consumes a response header block (up to \r\n\r\n)
// byte by byte so no tunnel data is swallowed, and returns the status code.
func ReadHTTPHeaders(r io.Reader) (int, error) {
	code, _, err := ReadHTTPReply(r)
	return code, err
}

// ReadHTTPReply is ReadHTTPHeaders that also returns the header block as it
// was received (status line and headers, ending with the blank line).
func ReadHTTPReply(r io.Reader) (int, string, error) {
	var buf []byte
	b := make([]byte, 1)
	for len(buf) < 16384 {
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, "", err
		}
		buf = append(buf, b[0])
		if n := len(buf); n >= 4 && string(buf[n-4:]) == "\r\n\r\n" {
			line, _, _ := strings.Cut(string(buf), "\r\n")
			f := strings.Fields(line)
			if len(f) < 2 {
				return 0, "", fmt.Errorf("payload: bad status line %q", line)
			}
			code, err := strconv.Atoi(f[1])
			return code, string(buf), err
		}
	}
	return 0, "", fmt.Errorf("payload: response headers too large")
}

// ---- helpers ----

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func clip(s string) string {
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}

// indexTag finds the next unescaped '['.
func indexTag(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '[':
			return i
		}
	}
	return -1
}

// matchBracket returns the index of the ']' closing the '[' at s[i], honoring
// nesting and backslash escapes.
func matchBracket(s string, i int) int {
	depth := 0
	for k := i; k < len(s); k++ {
		switch s[k] {
		case '\\':
			k++
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return k
			}
		}
	}
	return -1
}

// splitTop splits s on sep outside nested brackets and escapes.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func findRepeatEnd(s string) int {
	low := asciiLower(s)
	depth, pos := 1, 0
	for {
		o := strings.Index(low[pos:], "[repeat")
		c := strings.Index(low[pos:], "[/repeat]")
		if c < 0 {
			return -1
		}
		if o >= 0 && o < c {
			depth++
			pos += o + len("[repeat")
			continue
		}
		depth--
		if depth == 0 {
			return pos + c
		}
		pos += c + len("[/repeat]")
	}
}

func unescape(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case '0':
			b.WriteByte(0)
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteString("\\x")
		case '\\', '[', ']':
			b.WriteByte(s[i])
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func parseDelay(s string, def time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	var d time.Duration
	if ms, err := strconv.Atoi(s); err == nil {
		d = time.Duration(ms) * time.Millisecond
	} else if pd, err := time.ParseDuration(s); err == nil {
		d = pd
	} else {
		return 0, fmt.Errorf("payload: bad delay %q", s)
	}
	if d < 0 {
		d = 0
	}
	if d > maxDelay {
		d = maxDelay
	}
	return d, nil
}

func parseRange(s string) (int, int, error) {
	s = strings.TrimSpace(s)
	lo, hi := s, s
	if sep := strings.IndexAny(s, "-,:"); sep > 0 {
		lo, hi = s[:sep], s[sep+1:]
	}
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, err
	}
	b, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, err
	}
	if b < a {
		a, b = b, a
	}
	return a, b, nil
}

func decodeHexArg(s string) ([]byte, error) {
	r := strings.NewReplacer(" ", "", ",", "", "0x", "", "0X", "", "\\x", "", ":", "", "\n", "", "\r", "")
	return hex.DecodeString(r.Replace(s))
}

func randFrom(set string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = set[mrand.Intn(len(set))]
	}
	return string(b)
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
