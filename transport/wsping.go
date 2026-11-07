package transport

import "time"

// startPingSec starts the ping keepalive when sec is positive.
func (c *wsConn) startPingSec(sec int) {
	if sec > 0 {
		c.startPing(time.Duration(sec) * time.Second)
	}
}

// startPing sends a masked WebSocket Ping frame (opcode 0x9, payload "PING")
// every interval. CDNs and carrier NATs see traffic and keep the idle tunnel
// open; the server answers with a Pong, which Read ignores. It goes through
// writeFrame, so it never interleaves with a data frame. The loop ends with
// the first failed write, which is what a closed connection produces.
func (c *wsConn) startPing(every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for range t.C {
			if err := c.writeFrame(0x9, []byte("PING")); err != nil {
				return
			}
		}
	}()
}
