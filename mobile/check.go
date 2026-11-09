package mobile

import (
	"context"
	"time"
)

// CheckTunnel proves that traffic really passes through the running tunnel: it
// fetches a small well-known page through the outbound (ignoring routing
// rules) and returns the round trip in milliseconds. It returns an error that
// says why when nothing passes, and when nothing is running. Call it after
// Start/StartTunEx/StartEx before showing "connected", and now and then while
// connected. seconds limits the whole check (<= 0 means 20).
func CheckTunnel(seconds int) (int64, error) {
	c, err := running()
	if err != nil {
		return 0, err
	}
	if seconds <= 0 {
		seconds = 20
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	d, err := c.CheckTunnel(ctx)
	if err != nil {
		return 0, err
	}
	return d.Milliseconds(), nil
}
