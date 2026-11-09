package transport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"io.surprise.vpn/payload"
)

// autoWSWait is how long a freshly upgraded SSH stream may stay silent before
// it is judged without having seen any bytes. An SSH server speaks first, so in
// practice the first bytes arrive at once.
const autoWSWait = 1500 * time.Millisecond

// wantsWebSocket reports whether the rendered payload asks for a WebSocket
// upgrade ("Upgrade: websocket" in any letter case).
func wantsWebSocket(segs []payload.Segment) bool {
	var all []byte
	for _, s := range segs {
		all = append(all, s.Data...)
	}
	return bytes.Contains(bytes.ToLower(all), []byte("upgrade: websocket"))
}

// withWebSocketHeaders adds the handshake headers a real WebSocket server
// insists on (Sec-WebSocket-Key, Sec-WebSocket-Version and Connection: Upgrade)
// to the upgrade request in the payload, when the payload leaves them out.
// A server that only pretends to speak WebSocket ignores them. Headers the
// payload already has are left alone, and so is every request that is not the
// upgrade request (a CONNECT or a decoy line in front of it). The headers go in
// right before the blank line that ends the request, also when the payload is
// split into several segments.
func withWebSocketHeaders(segs []payload.Segment) []payload.Segment {
	var all []byte
	for _, s := range segs {
		all = append(all, s.Data...)
	}
	low := bytes.ToLower(all)
	i := bytes.Index(low, []byte("upgrade: websocket"))
	if i < 0 {
		return segs
	}
	start := 0
	if j := bytes.LastIndex(low[:i], []byte("\r\n\r\n")); j >= 0 {
		start = j + 4
	}
	e := bytes.Index(low[i:], []byte("\r\n\r\n"))
	if e < 0 {
		return segs
	}
	end := i + e + 2 // after the CRLF of the last header, before the blank line
	block := low[start:end]
	var add []byte
	if !bytes.Contains(block, []byte("\nsec-websocket-key:")) {
		k := make([]byte, 16)
		if _, err := rand.Read(k); err != nil {
			return segs
		}
		add = append(add, "Sec-WebSocket-Key: "+base64.StdEncoding.EncodeToString(k)+"\r\n"...)
	}
	if !bytes.Contains(block, []byte("\nsec-websocket-version:")) {
		add = append(add, "Sec-WebSocket-Version: 13\r\n"...)
	}
	if !bytes.Contains(block, []byte("\nconnection:")) {
		add = append(add, "Connection: Upgrade\r\n"...)
	}
	if len(add) == 0 {
		return segs
	}
	out := make([]payload.Segment, len(segs))
	copy(out, segs)
	pos := 0
	for k := range out {
		n := len(out[k].Data)
		if end <= pos+n {
			d := make([]byte, 0, n+len(add))
			d = append(d, out[k].Data[:end-pos]...)
			d = append(d, add...)
			d = append(d, out[k].Data[end-pos:]...)
			out[k].Data = d
			return out
		}
		pos += n
	}
	return segs
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// autoWebSocket decides, right after the server accepted an upgrade request,
// whether the stream that follows is plain or WebSocket-framed, the way HTTP
// Custom and HTTP Injector do, so the user never has to say which.
//
// The server's first bytes tell: a plain tunnel starts with the SSH banner
// ("SSH-2.0-..."), a framed one with an unmasked server frame header (0x81 or
// 0x82, a data frame, or 0x89, a ping). A server that stays silent for
// autoWSWait is judged by its reply instead: accepted says the reply carried
// Sec-WebSocket-Accept, which only a real WebSocket handshake has, so the
// stream is framed; without it the stream is plain. The returned conn holds
// whatever was read while looking, so nothing is lost.
func autoWebSocket(c net.Conn, accepted bool) net.Conn {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(autoWSWait))
	b, err := br.Peek(2)
	c.SetReadDeadline(time.Time{})
	switch {
	case len(b) >= 2 && err == nil:
		if (b[0] == 0x81 || b[0] == 0x82 || b[0] == 0x89) && b[1]&0x80 == 0 {
			return &wsConn{Conn: c, br: br} // framed: mask what we send, unwrap what we get
		}
	case len(b) == 0 && isTimeout(err) && accepted:
		return &wsConn{Conn: c, br: br} // silent, but a real WebSocket handshake
	}
	return &bufConn{Conn: c, br: br} // plain
}
