package v2tun

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnInfo describes one live tunneled connection (see Client.Connections).
type ConnInfo struct {
	ID        int64  `json:"id"`
	Network   string `json:"network"` // "tcp" or "udp"
	Target    string `json:"target"`  // host:port as the app asked for it
	Via       string `json:"via"`     // "proxy" or "direct", after routing
	StartedMs int64  `json:"startedMs"`
	Up        int64  `json:"up"`   // bytes sent on this connection
	Down      int64  `json:"down"` // bytes received on this connection
}

// connTable is the registry of live connections. The zero value is ready to use.
type connTable struct {
	mu   sync.Mutex
	next int64
	m    map[int64]*trackedConn
}

type trackedConn struct {
	net.Conn
	t        *connTable
	id       int64
	network  string
	target   string
	via      string
	started  time.Time
	up, down atomic.Int64
	once     sync.Once
}

// track registers conn and returns the wrapper that unregisters it on Close.
func (t *connTable) track(conn net.Conn, network, target, via string) net.Conn {
	tc := &trackedConn{Conn: conn, t: t, network: network, target: target, via: via, started: time.Now()}
	t.mu.Lock()
	if t.m == nil {
		t.m = make(map[int64]*trackedConn)
	}
	t.next++
	tc.id = t.next
	t.m[tc.id] = tc
	t.mu.Unlock()
	return tc
}

func (c *trackedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.down.Add(int64(n))
	return n, err
}

func (c *trackedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.up.Add(int64(n))
	return n, err
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.m, c.id)
		c.t.mu.Unlock()
	})
	return c.Conn.Close()
}

// Connections lists the live tunneled connections, oldest first.
func (c *Client) Connections() []ConnInfo {
	c.conns.mu.Lock()
	out := make([]ConnInfo, 0, len(c.conns.m))
	for _, tc := range c.conns.m {
		out = append(out, ConnInfo{ID: tc.id, Network: tc.network, Target: tc.target, Via: tc.via,
			StartedMs: tc.started.UnixMilli(), Up: tc.up.Load(), Down: tc.down.Load()})
	}
	c.conns.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CloseConn closes one live connection by the ID that Connections reports.
// It returns false when there is no such connection (it already ended).
func (c *Client) CloseConn(id int64) bool {
	c.conns.mu.Lock()
	tc := c.conns.m[id]
	c.conns.mu.Unlock()
	if tc == nil {
		return false
	}
	tc.Close()
	return true
}

// CloseConns closes every live tunneled connection and returns how many there were.
func (c *Client) CloseConns() int {
	c.conns.mu.Lock()
	list := make([]*trackedConn, 0, len(c.conns.m))
	for _, tc := range c.conns.m {
		list = append(list, tc)
	}
	c.conns.mu.Unlock()
	for _, tc := range list {
		tc.Close()
	}
	return len(list)
}
