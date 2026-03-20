package main

import (
	"net"
	"sync/atomic"
	"time"
)

// MultiPacketConn multiplexes multiple net.PacketConns. Writes are distributed
// round-robin across the underlying conns; reads from all conns are merged into
// a single stream.
//
// It implements net.PacketConn. The merged read stream is fed through an
// internal channel; ReadFrom blocks until a packet arrives from any underlying
// conn.
type MultiPacketConn struct {
	conns   []net.PacketConn
	idx     atomic.Int64
	recvCh  chan recvResult
	closeCh chan struct{}
}

type recvResult struct {
	p    []byte
	addr net.Addr
}

// NewMultiPacketConn creates a MultiPacketConn that round-robins writes across
// conns and merges reads from all conns. conns must be non-empty.
func NewMultiPacketConn(conns []net.PacketConn) *MultiPacketConn {
	c := &MultiPacketConn{
		conns:   conns,
		recvCh:  make(chan recvResult, 64),
		closeCh: make(chan struct{}),
	}
	for _, conn := range conns {
		go c.readFrom(conn)
	}
	return c
}

// WriteTo sends p to addr using the next conn in round-robin order.
func (c *MultiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	i := int(c.idx.Add(1)-1) % len(c.conns)
	return c.conns[i].WriteTo(p, addr)
}

// ReadFrom blocks until a packet is received from any underlying conn.
func (c *MultiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r := <-c.recvCh:
		n := copy(p, r.p)
		return n, r.addr, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// Close closes all underlying conns and stops the background readers.
func (c *MultiPacketConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	var first error
	for _, conn := range c.conns {
		if err := conn.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *MultiPacketConn) LocalAddr() net.Addr          { return c.conns[0].LocalAddr() }
func (c *MultiPacketConn) SetDeadline(t time.Time) error { return nil }
func (c *MultiPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *MultiPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// readFrom forwards packets received from conn into the shared recvCh.
func (c *MultiPacketConn) readFrom(conn net.PacketConn) {
	var buf [4096]byte
	for {
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			return
		}
		p := make([]byte, n)
		copy(p, buf[:n])
		select {
		case c.recvCh <- recvResult{p, addr}:
		case <-c.closeCh:
			return
		}
	}
}
