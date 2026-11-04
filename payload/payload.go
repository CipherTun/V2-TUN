// Package payload is the built-in payload engine of v2-tun.
// It compiles HTTP-Injector style templates into timed segments.
//
// Supported tags:
//   [crlf] [cr] [lf]            line endings (literal \r \n also work)
//   [host] [port] [host_port]   target values
//   [method] [protocol] [ua]    HTTP helpers
//   [split]                     send what came before now (new TCP segment)
//   [delay=MS]                  split and wait MS milliseconds
//   [random=a|b|c]              random pick per connection
//   [rotate=a|b|c]              round-robin pick per connection
//   [repeat=N]text[/repeat]     repeat text N times
package payload

import (
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Context holds per-connection values for tag substitution.
type Context struct {
	Host      string
	Port      int
	Method    string
	Protocol  string
	UserAgent string
}

// Segment is one write to the wire followed by an optional pause.
type Segment struct {
	Data  []byte
	Delay time.Duration
}

type part struct {
	tag  string // empty => literal
	arg  string
	text string
}

// Template is a compiled payload.
type Template struct {
	parts  []part
	rotate atomic.Uint64
}

// Compile parses a payload template.
func Compile(tpl string) (*Template, error) {
	t := &Template{}
	for len(tpl) > 0 {
		i := strings.IndexByte(tpl, '[')
		if i < 0 {
			t.parts = append(t.parts, part{text: tpl})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, part{text: tpl[:i]})
		}
		j := strings.IndexByte(tpl[i:], ']')
		if j < 0 {
			return nil, fmt.Errorf("payload: unclosed tag near %q", tpl[i:])
		}
		body := tpl[i+1 : i+j]
		tag, arg, _ := strings.Cut(body, "=")
		tpl = tpl[i+j+1:]
		tag = strings.ToLower(strings.TrimSpace(tag))
		switch tag {
		case "crlf", "cr", "lf", "host", "port", "host_port", "method",
			"protocol", "ua", "split", "delay", "random", "rotate":
			t.parts = append(t.parts, part{tag: tag, arg: arg})
		case "repeat":
			end := strings.Index(tpl, "[/repeat]")
			if end < 0 {
				return nil, fmt.Errorf("payload: [repeat] without [/repeat]")
			}
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 || n > 1000 {
				return nil, fmt.Errorf("payload: bad repeat count %q", arg)
			}
			inner := tpl[:end]
			tpl = tpl[end+len("[/repeat]"):]
			sub, err := Compile(inner)
			if err != nil {
				return nil, err
			}
			for k := 0; k < n; k++ {
				t.parts = append(t.parts, sub.parts...)
			}
		default:
			// Unknown tag: keep as literal text.
			t.parts = append(t.parts, part{text: "[" + body + "]"})
		}
	}
	return t, nil
}

func unescape(s string) string {
	r := strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t")
	return r.Replace(s)
}

// Render expands the template into segments.
func (t *Template) Render(c Context) []Segment {
	if c.Method == "" {
		c.Method = "GET"
	}
	if c.Protocol == "" {
		c.Protocol = "HTTP/1.1"
	}
	var segs []Segment
	var cur strings.Builder
	flush := func(d time.Duration) {
		if cur.Len() > 0 || d > 0 {
			segs = append(segs, Segment{Data: []byte(cur.String()), Delay: d})
			cur.Reset()
		}
	}
	for _, p := range t.parts {
		switch p.tag {
		case "":
			cur.WriteString(unescape(p.text))
		case "crlf":
			cur.WriteString("\r\n")
		case "cr":
			cur.WriteString("\r")
		case "lf":
			cur.WriteString("\n")
		case "host":
			cur.WriteString(c.Host)
		case "port":
			cur.WriteString(strconv.Itoa(c.Port))
		case "host_port":
			cur.WriteString(fmt.Sprintf("%s:%d", c.Host, c.Port))
		case "method":
			cur.WriteString(c.Method)
		case "protocol":
			cur.WriteString(c.Protocol)
		case "ua":
			cur.WriteString(c.UserAgent)
		case "split":
			flush(0)
		case "delay":
			ms, _ := strconv.Atoi(p.arg)
			flush(time.Duration(ms) * time.Millisecond)
		case "random":
			opts := strings.Split(p.arg, "|")
			cur.WriteString(unescape(opts[rand.Intn(len(opts))]))
		case "rotate":
			opts := strings.Split(p.arg, "|")
			n := t.rotate.Add(1) - 1
			cur.WriteString(unescape(opts[int(n%uint64(len(opts)))]))
		}
	}
	flush(0)
	return segs
}

// Send writes rendered segments to w honoring delays.
func Send(w io.Writer, segs []Segment) error {
	for _, s := range segs {
		if len(s.Data) > 0 {
			if _, err := w.Write(s.Data); err != nil {
				return err
			}
		}
		if s.Delay > 0 {
			time.Sleep(s.Delay)
		}
	}
	return nil
}

// ReadHTTPHeaders consumes a response header block (up to \r\n\r\n)
// byte by byte so no tunnel data is swallowed, and returns the status code.
func ReadHTTPHeaders(r io.Reader) (int, error) {
	var buf []byte
	b := make([]byte, 1)
	for len(buf) < 16384 {
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		buf = append(buf, b[0])
		if n := len(buf); n >= 4 && string(buf[n-4:]) == "\r\n\r\n" {
			line, _, _ := strings.Cut(string(buf), "\r\n")
			f := strings.Fields(line)
			if len(f) < 2 {
				return 0, fmt.Errorf("payload: bad status line %q", line)
			}
			return strconv.Atoi(f[1])
		}
	}
	return 0, fmt.Errorf("payload: response headers too large")
}
