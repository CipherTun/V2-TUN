package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"io.surprise.vpn/payload"
)

// ProbeSend sends the payload over c exactly as DialContext would (same tag
// values, same WebSocket handshake headers) and, when read is true, returns the
// raw replies it got (one per request line in the payload, ending at a 101) and
// the status of the last one. wait limits each read. addr is the real target
// ("host:port"), as DialContext receives it. It is meant for diagnostics: the
// raw reply is returned even when reading it failed halfway.
func (d *Payload) ProbeSend(ctx context.Context, c net.Conn, addr string, read bool, wait time.Duration) (string, int, error) {
	h, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	server := h
	ip := d.serverIP(ctx, c, server)
	if d.Host != "" {
		h = d.Host
	}
	segs := d.Template.Render(payload.Context{Host: h, Port: port, Server: server, ServerPort: port, IP: ip,
		SNI: d.SNI, Method: d.Method, UserAgent: d.UserAgent, Vars: d.Vars})
	if d.AutoWS && wantsWebSocket(segs) {
		segs = withWebSocketHeaders(segs)
	}
	if err := payload.SendContext(ctx, c, segs); err != nil {
		return "", 0, err
	}
	if !read {
		return "", 0, nil
	}
	n := d.Responses
	if n <= 0 {
		n = countRequests(segs)
	}
	methods := requestMethods(segs)
	var all strings.Builder
	code := 0
	for i := 0; i < n; i++ {
		head, err := probeReadHead(c, wait)
		all.WriteString(head)
		if err != nil {
			return all.String(), code, err
		}
		code = probeStatus(head)
		if code == 101 {
			break
		}
		isConnect := i < len(methods) && methods[i] == "CONNECT"
		if d.SkipBody && !isConnect && code >= 200 && code != 204 && code != 304 {
			if cl := contentLength(head); cl > 0 && cl <= maxSkippedBody {
				c.SetReadDeadline(time.Now().Add(wait))
				_, err := io.CopyN(io.Discard, c, cl)
				c.SetReadDeadline(time.Time{})
				if err != nil {
					return all.String(), code, err
				}
			}
		}
	}
	return all.String(), code, nil
}

// Accepts reports whether a reply with this status lets the tunnel start (see
// the Payload type: below 400, or listed in AcceptStatus).
func (d *Payload) Accepts(code int) bool { return d.accepts(code) }

// probeReadHead reads one header block byte by byte, so no tunnel data that
// follows it is swallowed, and returns what it read even when it failed.
func probeReadHead(c net.Conn, wait time.Duration) (string, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	var buf []byte
	one := make([]byte, 1)
	for len(buf) < 16384 {
		n, err := c.Read(one)
		if n > 0 {
			buf = append(buf, one[0])
			if l := len(buf); l >= 4 && string(buf[l-4:]) == "\r\n\r\n" {
				return string(buf), nil
			}
		}
		if err != nil {
			return string(buf), err
		}
	}
	return string(buf), errors.New("reply headers too large")
}

// probeStatus returns the status code of a reply's first line, or 0.
func probeStatus(head string) int {
	line, _, _ := strings.Cut(head, "\r\n")
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}
