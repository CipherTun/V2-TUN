// Package socks is a SOCKS5 server (CONNECT and UDP ASSOCIATE, optional
// username/password) that routes every connection through a v2tun dialer.
// Point tun2socks or any SOCKS-aware app at it.
package socks

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// UDPDialer opens a datagram conn (one Write/Read = one datagram). The v2tun
// Client implements it.
type UDPDialer interface {
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// Options configures ServeOpts.
type Options struct {
	// Username and Password enable RFC 1929 authentication when either is set.
	// Without them any app on the device that can reach the listener can use
	// the tunnel, so set them if the listener is not strictly private.
	Username string
	Password string
	// UDP enables UDP ASSOCIATE; nil answers "command not supported".
	UDP UDPDialer
}

const (
	udpIdle   = 60 * time.Second
	maxFlows  = 256
	cmdBind   = 2
	replyOK   = 0
	replyFail = 1
	replyDeny = 2
	replyHost = 4
	replyCmd  = 7
)

// Serve accepts connections until l is closed or ctx is done (CONNECT only, no auth).
func Serve(ctx context.Context, l net.Listener, d Dialer) error {
	return ServeOpts(ctx, l, d, Options{})
}

// ServeOpts is Serve with authentication and UDP ASSOCIATE support.
func ServeOpts(ctx context.Context, l net.Listener, d Dialer, o Options) error {
	go func() { <-ctx.Done(); l.Close() }()
	socksLog.Info("socks5 server started", "addr", l.Addr().String(),
		"auth", o.Username != "" || o.Password != "", "udp", o.UDP != nil)
	defer socksLog.Info("socks5 server stopped")
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			socksLog.Error("socks5 server cannot accept connections", "err", err)
			return err
		}
		go handle(ctx, c, d, &o)
	}
}

func reply(c net.Conn, code byte, bind net.Addr) {
	ip, port := net.IPv4zero, 0
	if ua, ok := bind.(*net.UDPAddr); ok && ua != nil {
		ip, port = ua.IP, ua.Port
	}
	b := []byte{5, code, 0}
	if v4 := ip.To4(); v4 != nil {
		b = append(b, 1)
		b = append(b, v4...)
	} else {
		b = append(b, 4)
		b = append(b, ip.To16()...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(port))
	c.Write(b)
}

func authenticate(c net.Conn, o *Options) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 {
		return false
	}
	user := make([]byte, h[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return false
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	ok := subtle.ConstantTimeCompare(user, []byte(o.Username)) == 1 &&
		subtle.ConstantTimeCompare(pass, []byte(o.Password)) == 1
	if !ok {
		authFailLim.Warn(socksLog, time.Second, "socks5 login rejected", "remote", c.RemoteAddr().String())
		c.Write([]byte{1, 1})
		return false
	}
	c.Write([]byte{1, 0})
	return true
}

func handle(ctx context.Context, c net.Conn, d Dialer, o *Options) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if o.Username != "" || o.Password != "" {
		if bytes.IndexByte(methods, 2) < 0 {
			socksLog.Debug("socks5 client does not offer password login", "remote", c.RemoteAddr().String())
			c.Write([]byte{5, 0xFF})
			return
		}
		c.Write([]byte{5, 2})
		if !authenticate(c, o) {
			return
		}
	} else {
		c.Write([]byte{5, 0})
	}
	var r [4]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[0] != 5 {
		return
	}
	host, err := readAddr(c, r[3])
	if err != nil {
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	switch r[1] {
	case 1:
		connect(ctx, c, d, net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:])))))
	case 3:
		if o.UDP == nil {
			socksLog.Debug("udp associate refused: udp is not enabled")
			reply(c, replyCmd, nil)
			return
		}
		associate(ctx, c, o.UDP)
	default:
		socksLog.Debug("socks5 command not supported", "cmd", r[1])
		reply(c, replyCmd, nil)
	}
}

func connect(ctx context.Context, c net.Conn, d Dialer, target string) {
	up, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		code := byte(replyHost)
		if strings.Contains(err.Error(), "blocked by routing rule") {
			code = replyDeny
			socksLog.Debug("connection blocked by a routing rule", "target", target)
		} else {
			connFailLim.Warn(socksLog, time.Second, "connection failed", "target", target, "err", err)
		}
		reply(c, code, nil)
		return
	}
	defer up.Close()
	socksLog.Debug("tcp open", "target", target)
	reply(c, replyOK, nil)
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// associate serves UDP ASSOCIATE: datagrams from the client's address are
// relayed through ud; the association ends when the control connection closes.
func associate(ctx context.Context, c net.Conn, ud UDPDialer) {
	lh, _, _ := net.SplitHostPort(c.LocalAddr().String())
	pc, err := net.ListenPacket("udp", net.JoinHostPort(lh, "0"))
	if err != nil {
		socksLog.Warn("could not open a udp port for an association", "err", err)
		reply(c, replyFail, nil)
		return
	}
	defer pc.Close()
	reply(c, replyOK, pc.LocalAddr())
	c.SetDeadline(time.Time{})
	peerIP := ""
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		peerIP = ta.IP.String()
	}
	socksLog.Debug("udp association opened", "remote", c.RemoteAddr().String())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { // the TCP control connection defines the association's lifetime
		io.Copy(io.Discard, c)
		cancel()
		pc.Close()
	}()
	a := &assoc{ctx: ctx, pc: pc, dial: ud, flows: map[string]*flow{}}
	defer a.closeAll()
	a.loop(peerIP)
}

type flow struct {
	conn net.Conn
	idle *time.Timer
}

type assoc struct {
	ctx    context.Context
	pc     net.PacketConn
	dial   UDPDialer
	mu     sync.Mutex
	client net.Addr
	flows  map[string]*flow
}

func (a *assoc) loop(peerIP string) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if ua, ok := from.(*net.UDPAddr); ok && peerIP != "" && ua.IP.String() != peerIP {
			continue // only the client that opened the association may use it
		}
		a.mu.Lock()
		if a.client == nil {
			a.client = from
		}
		client := a.client
		a.mu.Unlock()
		if from.String() != client.String() {
			continue
		}
		host, port, payload, ok := parseUDP(buf[:n])
		if !ok {
			continue
		}
		dst := net.JoinHostPort(host, strconv.Itoa(port))
		f := a.flow(dst, host, port)
		if f == nil {
			continue
		}
		f.idle.Reset(udpIdle)
		f.conn.Write(append([]byte(nil), payload...))
	}
}

func (a *assoc) flow(dst, host string, port int) *flow {
	a.mu.Lock()
	if f, ok := a.flows[dst]; ok {
		a.mu.Unlock()
		return f
	}
	full := len(a.flows) >= maxFlows
	a.mu.Unlock()
	if full {
		udpFailLim.Warn(socksLog, time.Second, "too many udp flows in one association", "max", maxFlows, "dst", dst)
		return nil
	}
	dctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	conn, err := a.dial.DialUDP(dctx, dst)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "blocked by routing rule") {
			socksLog.Debug("udp flow blocked by a routing rule", "dst", dst)
		} else {
			udpFailLim.Warn(socksLog, time.Second, "udp flow failed", "dst", dst, "err", err)
		}
		return nil
	}
	a.mu.Lock()
	if f, ok := a.flows[dst]; ok { // lost a race with another packet to the same target
		a.mu.Unlock()
		conn.Close()
		return f
	}
	f := &flow{conn: conn}
	f.idle = time.AfterFunc(udpIdle, func() { a.drop(dst) })
	a.flows[dst] = f
	a.mu.Unlock()
	socksLog.Debug("udp open", "dst", dst)
	go a.pump(f, dst, udpHeader(host, port))
	return f
}

func (a *assoc) pump(f *flow, dst string, hdr []byte) {
	buf := make([]byte, 65535)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			a.drop(dst)
			return
		}
		f.idle.Reset(udpIdle)
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if client == nil {
			continue
		}
		a.pc.WriteTo(append(append([]byte(nil), hdr...), buf[:n]...), client)
	}
}

func (a *assoc) drop(dst string) {
	a.mu.Lock()
	f := a.flows[dst]
	delete(a.flows, dst)
	a.mu.Unlock()
	if f != nil {
		f.idle.Stop()
		f.conn.Close()
	}
}

func (a *assoc) closeAll() {
	a.mu.Lock()
	var keys []string
	for k := range a.flows {
		keys = append(keys, k)
	}
	a.mu.Unlock()
	for _, k := range keys {
		a.drop(k)
	}
}

// udpHeader builds the SOCKS5 UDP request header (RSV, FRAG, ATYP, ADDR, PORT).
func udpHeader(host string, port int) []byte {
	b := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

// parseUDP decodes a SOCKS5 UDP datagram; fragmented datagrams are dropped.
func parseUDP(b []byte) (host string, port int, payload []byte, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return
	}
	p := 4
	switch b[3] {
	case 1:
		if len(b) < p+4+2 {
			return
		}
		host, p = net.IP(b[p:p+4]).String(), p+4
	case 4:
		if len(b) < p+16+2 {
			return
		}
		host, p = net.IP(b[p:p+16]).String(), p+16
	case 3:
		if len(b) < p+1 || len(b) < p+1+int(b[p])+2 {
			return
		}
		l := int(b[p])
		host, p = string(b[p+1:p+1+l]), p+1+l
	default:
		return
	}
	port = int(binary.BigEndian.Uint16(b[p:]))
	return host, port, b[p+2:], true
}

func readAddr(c net.Conn, typ byte) (string, error) {
	switch typ {
	case 1:
		b := make([]byte, 4)
		_, err := io.ReadFull(c, b)
		return net.IP(b).String(), err
	case 4:
		b := make([]byte, 16)
		_, err := io.ReadFull(c, b)
		return net.IP(b).String(), err
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		_, err := io.ReadFull(c, b)
		return string(b), err
	}
	return "", errors.New("socks: bad address type")
}
