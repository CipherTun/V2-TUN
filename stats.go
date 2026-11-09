package v2tun

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

var upBytes, downBytes atomic.Int64

// Traffic returns total bytes sent and received through all tunnels.
func Traffic() (up, down int64) { return upBytes.Load(), downBytes.Load() }

// ResetTraffic zeroes the counters.
func ResetTraffic() { upBytes.Store(0); downBytes.Store(0) }

type countConn struct{ net.Conn }

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	downBytes.Add(int64(n))
	return n, err
}

func (c countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	upBytes.Add(int64(n))
	return n, err
}

// Ping measures the time to a good response (default generate_204) through
// the tunnel. Redirects (301, 302, ...) are followed, up to the net/http
// default of 10, and the answer at the end must be a success (2xx such as 200
// or 204). Any 4xx or 5xx answer, and any failure to get an answer at all,
// is an error.
func (c *Client) Ping(ctx context.Context, rawURL string) (time.Duration, error) {
	if rawURL == "" {
		rawURL = "http://www.gstatic.com/generate_204"
	}
	hc := &http.Client{
		Transport: &http.Transport{DialContext: c.DialContext, DisableKeepAlives: true},
		Timeout:   15 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("ping: status %d", resp.StatusCode)
	}
	return time.Since(t0), nil
}
