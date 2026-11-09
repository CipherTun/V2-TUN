package v2tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"io.surprise.vpn/internal/logx"
)

var checkLog = logx.L("check")

// checkTargets are well-known connectivity endpoints. Any HTTP answer from
// one of them (200, 204, a redirect, a moved-permanently, even an error page)
// proves that data flows through the tunnel and the far side is alive, so the
// status and the body are not compared. Only a failure to get an answer at
// all (dial error, timeout, reset, TLS/protocol error) counts as dead or
// offline.
var checkTargets = []string{
	"http://cp.cloudflare.com/generate_204",
	"http://connectivitycheck.gstatic.com/generate_204",
	"http://www.msftconnecttest.com/connecttest.txt",
}

// CheckTunnel proves that data really flows: it fetches a small well-known
// page through the outbound (the whole dial chain and protocol, every backup
// if need be) and returns how long that took. Routing rules are ignored on
// purpose, otherwise a rule sending the test host direct would make a dead
// tunnel look healthy. The request does not count as tunnel traffic and does
// not show in Connections.
//
// It succeeds when any one of the targets answers with any HTTP response, and
// fails with the reason of every attempt otherwise. ctx limits the whole check.
func (c *Client) CheckTunnel(ctx context.Context) (time.Duration, error) {
	var why []string
	for _, u := range checkTargets {
		if ctx.Err() != nil {
			break
		}
		d, err := c.checkOne(ctx, u)
		if err == nil {
			checkLog.Debug("tunnel check passed", "url", u, "ms", d.Milliseconds())
			return d, nil
		}
		why = append(why, strings.ReplaceAll(err.Error(), "\n", " "))
	}
	if len(why) == 0 {
		return 0, ctx.Err()
	}
	err := fmt.Errorf("no traffic passes through the tunnel (%s)", strings.Join(why, "; "))
	checkLog.Warn("tunnel check failed", "err", err)
	return 0, err
}

func (c *Client) checkOne(ctx context.Context, url string) (time.Duration, error) {
	cx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return c.out.DialContext(dctx, network, addr)
			},
			DisableKeepAlives: true,
		},
		// a redirect already proves the path is alive; do not follow it, the
		// next hop could be a portal host that is slow or unreachable
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(cx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// any status counts: getting a response at all means the tunnel is up
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	return time.Since(t0), nil
}
