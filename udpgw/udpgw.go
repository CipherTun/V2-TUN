// Package udpgw is a client for BadVPN's udpgw: UDP datagrams are carried over
// one TCP stream (usually through SSH to 127.0.0.1:7300 on the server).
package udpgw

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	flagKeepalive = 1
	flagIPv6      = 8
)

type Client struct {
	// Dial opens the TCP stream to the udpgw server (through the tunnel).
	Dial func(ctx context.Context) (net.Conn, error)

	mu    sync.Mutex
	conn  net.Conn
	flows map[uint16]*flow
	next  uint16
	wmu   sync.Mutex
}

func (c *Client) connect(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return err
	}
	c.conn = conn
	c.flows = map[uint16]*flow{}
	go c.readLoop(conn)
	go func() { // keepalive so idle tunnels aren't reaped
		for {
			time.Sleep(20 * time.Second)
			c.mu.Lock()
			alive := c.conn == conn
			c.mu.Unlock()
			if !alive || c.send(conn, []byte{flagKeepalive, 0, 0}) != nil {
				return
			}
		}
	}()
	return nil
}

func (c *Client) send(conn net.Conn, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := conn.Write(append(binary.LittleEndian.AppendUint16(nil, uint16(len(payload))), payload...))
	return err
}

func (c *Client) readLoop(conn net.Conn) {
	defer func() {
		conn.Close()
		c.mu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		for _, f := range c.flows {
			f.fail(io.EOF)
		}
		c.flows = nil
		c.mu.Unlock()
	}()
	for {
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		pkt := make([]byte, binary.LittleEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, pkt); err != nil {
			return
		}
		if len(pkt) < 3 || pkt[0]&flagKeepalive != 0 {
			continue
		}
		alen := 6
		if pkt[0]&flagIPv6 != 0 {
			alen = 18
		}
		if len(pkt) < 3+alen {
			continue
		}
		id := binary.LittleEndian.Uint16(pkt[1:3])
		c.mu.Lock()
		f := c.flows[id]
		c.mu.Unlock()
		if f != nil {
			select {
			case f.rq <- pkt[3+alen:]:
			default: // drop when the reader is slow, like real UDP
			}
		}
	}
}

// DialUDP opens a flow to target (an IP:port; udpgw cannot resolve names).
func (c *Client) DialUDP(ctx context.Context, target string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("udpgw: target must be an IP address")
	}
	port, _ := strconv.Atoi(ps)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	for {
		c.next++
		if _, used := c.flows[c.next]; !used {
			break
		}
	}
	f := &flow{c: c, conn: c.conn, id: c.next, rq: make(chan []byte, 128), done: make(chan struct{}), ip: ip, port: uint16(port)}
	c.flows[f.id] = f
	return f, nil
}

type flow struct {
	c    *Client
	conn net.Conn
	id   uint16
	ip   net.IP
	port uint16
	rq   chan []byte
	done chan struct{}
	once sync.Once
}

func (f *flow) fail(error) { f.once.Do(func() { close(f.done) }) }

func (f *flow) Write(p []byte) (int, error) {
	var h []byte
	if v4 := f.ip.To4(); v4 != nil {
		h = append([]byte{0}, 0, 0)
		h = append(h, v4...)
	} else {
		h = append([]byte{flagIPv6}, 0, 0)
		h = append(h, f.ip.To16()...)
	}
	binary.LittleEndian.PutUint16(h[1:3], f.id)
	h = binary.BigEndian.AppendUint16(h, f.port)
	h = append(h, p...)
	if len(h) > 65535 {
		return 0, errors.New("udpgw: datagram too large")
	}
	if err := f.c.send(f.conn, h); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *flow) Read(p []byte) (int, error) {
	select {
	case b := <-f.rq:
		return copy(p, b), nil
	case <-f.done:
		select {
		case b := <-f.rq:
			return copy(p, b), nil
		default:
			return 0, io.EOF
		}
	}
}

func (f *flow) Close() error {
	f.once.Do(func() { close(f.done) })
	f.c.mu.Lock()
	delete(f.c.flows, f.id)
	f.c.mu.Unlock()
	return nil
}

func (f *flow) LocalAddr() net.Addr              { return f.conn.LocalAddr() }
func (f *flow) RemoteAddr() net.Addr             { return &net.UDPAddr{IP: f.ip, Port: int(f.port)} }
func (f *flow) SetDeadline(time.Time) error      { return nil }
func (f *flow) SetReadDeadline(time.Time) error  { return nil }
func (f *flow) SetWriteDeadline(time.Time) error { return nil }
