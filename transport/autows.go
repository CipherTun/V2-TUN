package transport

import (
	"bufio"
	"bytes"
	"net"
	"time"

	"io.surprise.vpn/payload"
)

// autoWSWait is how long a freshly upgraded SSH stream may stay silent before
// it is taken to be a plain (unframed) tunnel. An SSH server speaks first, so
// in practice the first bytes arrive at once.
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

// autoWebSocket decides, right after the server accepted an upgrade request,
// whether the stream that follows is plain or WebSocket-framed, the way HTTP
// Custom and HTTP Injector do, so the user never has to say which.
//
// The server's first bytes tell: a plain tunnel starts with the SSH banner
// ("SSH-2.0-..."), a framed one with an unmasked server frame header (0x81 or
// 0x82, a data frame, or 0x89, a ping). A server that stays silent for
// autoWSWait is treated as plain. The returned conn holds whatever was read
// while looking, so nothing is lost.
func autoWebSocket(c net.Conn) net.Conn {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(autoWSWait))
	b, err := br.Peek(2)
	c.SetReadDeadline(time.Time{})
	if len(b) >= 2 && err == nil && (b[0] == 0x81 || b[0] == 0x82 || b[0] == 0x89) && b[1]&0x80 == 0 {
		return &wsConn{Conn: c, br: br} // framed: mask what we send, unwrap what we get
	}
	return &bufConn{Conn: c, br: br} // plain
}
