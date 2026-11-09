// Package tun turns a TUN file descriptor (Android VpnService) into tunnel
// connections using gVisor's userspace TCP/IP stack.
//
// TCP goes straight through the v2tun Dialer. UDP goes through UDPDialer when
// set (native UDP relay or BadVPN udpgw). With Fake set, DNS A queries get
// fake addresses so domain routing works; with Sniff, TLS SNI / HTTP Host
// replace raw IPs for routing and for the proxy server, and the sniffed
// protocol is handed to the router (see route.WithProtocol).
//
// The descriptor stays owned by the caller: Start and Close never close it.
// Close returns only after the packet reader has stopped, so the caller can
// close the descriptor (which is what removes the VPN key from the Android
// status bar) right after it.
//
// Pin gVisor with: go get gvisor.dev/gvisor@go   (its API moves; adjust
// NewUDPConn/NewForwarder calls if your version differs).
package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"io.surprise.vpn/route"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type UDPDialer interface {
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

type Options struct {
	// FD is the TUN descriptor (ParcelFileDescriptor.getFd()). The caller keeps
	// ownership and must close it after Tun.Close returns; the stack never does.
	FD     int
	MTU    uint32 // default 1500
	DNS    string // "1.1.1.1:53": DNS as DNS-over-TCP through the tunnel; empty => relay as UDP
	Dialer Dialer
	UDP    UDPDialer // optional: enables full UDP relay
	Fake   *FakeDNS  // optional: fake-IP DNS
	Sniff  bool      // sniff TLS SNI / HTTP Host / protocol from the first bytes
}

type Tun struct {
	s      *stack.Stack
	nic    tcpip.NICID
	cancel context.CancelFunc
	once   sync.Once
}

func Start(o Options) (*Tun, error) {
	if o.MTU == 0 {
		o.MTU = 1500
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{o.FD}, MTU: o.MTU})
	if err != nil {
		return nil, fmt.Errorf("tun: fdbased: %w", err)
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	const nic = tcpip.NICID(1)
	if e := s.CreateNIC(nic, ep); e != nil {
		return nil, fmt.Errorf("tun: create nic: %v", e)
	}
	s.SetPromiscuousMode(nic, true) // accept packets for any destination
	s.SetSpoofing(nic, true)        // answer from any address
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
		{Destination: header.IPv6EmptySubnet, NIC: nic},
	})

	ctx, cancel := context.WithCancel(context.Background())
	t := &Tun{s: s, nic: nic, cancel: cancel}

	tf := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		e, err := r.CreateEndpoint(&wq)
		if err != nil {
			connFailLim.Warn(tunLog, time.Second, "could not accept a tcp connection",
				"dst", id.LocalAddress.String(), "err", fmt.Sprint(err))
			r.Complete(true)
			return
		}
		r.Complete(false)
		local := gonet.NewTCPConn(&wq, e)
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go relay(ctx, local, dst, o)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)

	// udp.ForwarderHandler is func(*ForwarderRequest) (handled bool): true means
	// this handler took the packet; false lets the stack answer with ICMP port
	// unreachable. Flows we cannot serve are dropped silently (true), not refused.
	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		e, err := r.CreateEndpoint(&wq)
		if err != nil {
			udpFailLim.Warn(tunLog, time.Second, "could not accept a udp flow",
				"dst", id.LocalAddress.String(), "err", fmt.Sprint(err))
			return false
		}
		c := gonet.NewUDPConn(&wq, e)
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		switch {
		case id.LocalPort == 53 && (o.DNS != "" || o.UDP == nil || o.Fake != nil):
			dns := o.DNS
			if dns == "" {
				dns = dst
			}
			go serveDNS(ctx, c, dns, o)
		case o.UDP != nil:
			go relayUDP(ctx, c, dst, o)
		default:
			tunLog.Debug("udp flow dropped: no udp relay", "dst", dst)
			c.Close() // no UDP support: drop
		}
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)

	tunLog.Info("tun stack started", "mtu", o.MTU, "dns", o.DNS, "fakeDns", o.Fake != nil,
		"sniff", o.Sniff, "udpRelay", o.UDP != nil)
	return t, nil
}

// Close stops the stack. It removes the NIC first: that stops the goroutine
// reading the TUN descriptor and waits for it, which Stack.Close alone does
// not do. When Close returns nothing touches the descriptor any more, so the
// caller can close it. Close is safe to call more than once.
func (t *Tun) Close() {
	t.once.Do(func() {
		t.cancel()
		t.s.RemoveNIC(t.nic)
		t.s.Close()
		tunLog.Info("tun stack stopped")
	})
}

// resolveDst swaps a fake address back to its domain.
func resolveDst(dst string, o Options) string {
	if o.Fake == nil {
		return dst
	}
	host, port, _ := net.SplitHostPort(dst)
	if ip := net.ParseIP(host); ip != nil {
		if d, ok := o.Fake.Lookup(ip); ok {
			return net.JoinHostPort(d, port)
		}
	}
	return dst
}

// closeWriter is a connection that can close just its sending side.
type closeWriter interface{ CloseWrite() error }

const (
	// halfCloseWait is how long a connection stays open for the reply after the
	// client stopped sending, when the far side was told about it (CloseWrite).
	halfCloseWait = 15 * time.Second
	// flushWait is the same when the far side cannot be told: just long enough
	// for a reply that is already on its way to reach the client.
	flushWait = 2 * time.Second
)

func relay(ctx context.Context, local net.Conn, dst string, o Options) {
	defer local.Close()
	dst = resolveDst(dst, o)
	host, port, _ := net.SplitHostPort(dst)
	var first []byte
	proto := ""
	if o.Sniff && net.ParseIP(host) != nil && port != "53" {
		// Clients speak first for TLS/HTTP; servers-first protocols just time out.
		b, err := readFirst(local, 300*time.Millisecond)
		if len(b) == 0 && err != nil && !isTimeout(err) {
			return
		}
		first = b
		if d := SniffDomain(first); d != "" {
			dst = net.JoinHostPort(d, port)
		}
		proto = SniffProtocol(first)
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	if proto != "" {
		dctx = route.WithProtocol(dctx, proto)
	}
	up, err := o.Dialer.DialContext(dctx, "tcp", dst)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "blocked by routing rule") {
			tunLog.Debug("connection blocked by a routing rule", "dst", dst, "proto", proto)
		} else {
			connFailLim.Warn(tunLog, time.Second, "connection failed", "dst", dst, "proto", proto, "err", err)
		}
		return
	}
	tunLog.Debug("tcp open", "dst", dst, "proto", proto)
	defer up.Close()
	if len(first) > 0 {
		if _, err := up.Write(first); err != nil {
			tunLog.Debug("could not send the first bytes", "dst", dst, "err", err)
			return
		}
	}
	done := make(chan int, 2)
	go func() { io.Copy(up, local); done <- 0 }() // client to server
	go func() { io.Copy(local, up); done <- 1 }() // server to client
	select {
	case which := <-done:
		if which == 0 {
			// The client stopped sending. That is how a client half-closes after its
			// request, and the reply may still be on its way: tear down at once and
			// the end of it would be cut off. Tell the server when that is possible.
			wait := flushWait
			if cw, ok := up.(closeWriter); ok && cw.CloseWrite() == nil {
				wait = halfCloseWait
			}
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case <-done:
			case <-t.C:
			case <-ctx.Done():
			}
		}
	case <-ctx.Done():
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func serveDNS(ctx context.Context, c net.Conn, server string, o Options) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		if o.Fake != nil {
			if resp, ok := o.Fake.Handle(q); ok {
				c.Write(resp)
				continue
			}
		}
		go func() {
			resp, err := dnsOverTCP(ctx, o.Dialer, server, q)
			if err != nil {
				dnsFailLim.Warn(tunLog, 5*time.Second, "dns query failed", "server", server, "err", err)
				return
			}
			c.Write(resp)
		}()
	}
}

func dnsOverTCP(ctx context.Context, d Dialer, server string, q []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, err := d.DialContext(cctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// A stalled server must not pin this goroutine: SetDeadline is a no-op on
	// some tunnel conns (mux streams), so close the conn when time is up.
	stall := time.AfterFunc(8*time.Second, func() { c.Close() })
	defer stall.Stop()
	if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, resp)
	return resp, err
}

func relayUDP(ctx context.Context, local net.Conn, dst string, o Options) {
	defer local.Close()
	dst = resolveDst(dst, o)
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	up, err := o.UDP.DialUDP(dctx, dst)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "blocked by routing rule") {
			tunLog.Debug("udp flow blocked by a routing rule", "dst", dst)
		} else {
			udpFailLim.Warn(tunLog, time.Second, "udp flow failed", "dst", dst, "err", err)
		}
		return
	}
	tunLog.Debug("udp open", "dst", dst)
	defer up.Close()
	const idleTO = 60 * time.Second
	idle := time.AfterFunc(idleTO, func() { local.Close(); up.Close() })
	defer idle.Stop()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := up.Read(buf)
			if err != nil {
				local.Close()
				return
			}
			idle.Reset(idleTO)
			local.Write(buf[:n])
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, err := local.Read(buf)
		if err != nil {
			return
		}
		idle.Reset(idleTO)
		if _, err := up.Write(buf[:n]); err != nil {
			return
		}
	}
}
