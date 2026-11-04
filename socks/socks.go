// Package socks is a minimal SOCKS5 (CONNECT, no-auth) server that routes
// every connection through a v2tun dialer. Point tun2socks at it for TUN mode.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Serve accepts connections until l is closed or ctx is done.
func Serve(ctx context.Context, l net.Listener, d Dialer) error {
	go func() { <-ctx.Done(); l.Close() }()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(ctx, c, d)
	}
}

func handle(ctx context.Context, c net.Conn, d Dialer) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	var r [4]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[0] != 5 {
		return
	}
	if r[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
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
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))
	up, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
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
