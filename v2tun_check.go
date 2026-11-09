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

// checkTarget is a well-known connectivity endpoint and what a real answer
// from it looks like. A captive portal or a carrier's "no balance" page also
// answers (often 200 or a redirect), so the exact status, and for the last
// target the body, have to match.
type checkTarget struct {
	url    string
	status int
	body   string // must appear in the body when not empty
}

var checkTargets = []checkTarget{
	{"http://cp.cloudflare.com/generate_204", http.StatusNoContent, ""},
	{"http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, ""},
	{"http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test"},
}

// CheckTunnel proves that data really flows: it fetches a small well-known
// page through the outbound (the whole dial chain and protocol, every backup
// if need be) and returns how long that took. Routing rules are ignored on
// purpose, otherwise a rule sending the test host direct would make a dead
// tunnel look healthy. The request does not count as tunnel traffic and does
// not show in Connections.
//
// It succeeds when any one of the targets answers as expected, and fails with
// the reason of every attempt otherwise. ctx limits the whole check.
func (c *Client) CheckTunnel(ctx context.Context) (time.Duration, error) {
	var why []string
	for _, t := range checkTargets {
		if ctx.Err() != nil {
			break
		}
		d, err := c.checkOne(ctx, t)
		if err == nil {
			checkLog.Debug("tunnel check passed", "url", t.url, "ms", d.Milliseconds())
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

func (c *Client) checkOne(ctx context.Context, t checkTarget) (time.Duration, error) {
	cx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				return c.out.DialContext(dctx, network, addr)
			},
			DisableKeepAlives: true,
		},
		// a redirect is what a captive portal answers: do not follow it
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(cx, http.MethodGet, t.url, nil)
	if err != nil {
		return 0, err
	}
	t0 := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != t.status {
		return 0, fmt.Errorf("GET %s answered %d, expected %d", t.url, resp.StatusCode, t.status)
	}
	if t.body != "" && !strings.Contains(string(body), t.body) {
		return 0, fmt.Errorf("GET %s answered with an unexpected page", t.url)
	}
	return time.Since(t0), nil
}
