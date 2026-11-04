// Package tun turns a TUN file descriptor (Android VpnService) into tunnel
// connections using gVisor's userspace TCP/IP stack.
//
// TCP goes straight through the v2tun Dialer. UDP goes through UDPDialer when
// set (native UDP relay or BadVPN udpgw). With Fake set, DNS A queries get
// fake addresses so domain routing works; with Sniff, TLS SNI / HTTP Host
// replace raw IPs for routing and for the proxy server.
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
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type UDPDialer interface {
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

type Options struct {
	FD     int    // from ParcelFileDescriptor.detachFd()
	MTU    uint32 // default 1500
	DNS    string // "1.1.1.1:53": DNS as DNS-over-TCP through the tunnel; empty => relay as UDP
	Dialer Dialer
	UDP    UDPDialer // optional: enables full UDP relay
	Fake   *FakeDNS  // optional: fake-IP DNS
	Sniff  bool      // sniff TLS SNI / HTTP Host from the first bytes
}

type Tun struct {
	s      *stack.Stack
	cancel context.CancelFunc
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
	t := &Tun{s: s, cancel: cancel}

	tf := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		e, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		local := gonet.NewTCPConn(&wq, e)
		dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go relay(ctx, local, dst, o)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)

	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		e, err := r.CreateEndpoint(&wq)
		if err != nil {
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
			c.Close() // no UDP support: drop
		}
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	return t, nil
}

func (t *Tun) Close() {
	t.cancel()
	t.s.Close()
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

func relay(ctx context.Context, local net.Conn, dst string, o Options) {
	defer local.Close()
	dst = resolveDst(dst, o)
	host, port, _ := net.SplitHostPort(dst)
	var first []byte
	if o.Sniff && net.ParseIP(host) != nil && port != "53" {
		// Clients speak first for TLS/HTTP; servers-first protocols just time out.
		local.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 4096)
		n, err := local.Read(buf)
		local.SetReadDeadline(time.Time{})
		if n == 0 && err != nil && !isTimeout(err) {
			return
		}
		first = buf[:n]
		if d := SniffDomain(first); d != "" {
			dst = net.JoinHostPort(d, port)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	up, err := o.Dialer.DialContext(dctx, "tcp", dst)
	cancel()
	if err != nil {
		return
	}
	defer up.Close()
	if len(first) > 0 {
		if _, err := up.Write(first); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, local); done <- struct{}{} }()
	go func() { io.Copy(local, up); done <- struct{}{} }()
	select {
	case <-done:
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
			if resp, err := dnsOverTCP(ctx, o.Dialer, server, q); err == nil {
				c.Write(resp)
			}
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
		return
	}
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
