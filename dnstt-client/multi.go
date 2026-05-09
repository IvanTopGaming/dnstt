package main

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MultiPacketConn multiplexes multiple net.PacketConns. Writes are distributed
// round-robin across the underlying conns; reads from all conns are merged into
// a single stream.
//
// It implements net.PacketConn. The merged read stream is fed through an
// internal channel; ReadFrom blocks until a packet arrives from any underlying
// conn, all readers exit, or Close is called.
type MultiPacketConn struct {
	conns       []net.PacketConn
	idx         atomic.Uint64
	recvCh      chan recvResult
	closeCh     chan struct{}
	closeOnce   sync.Once
	activeReads atomic.Int64
	readersWg   sync.WaitGroup
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
	c.activeReads.Store(int64(len(conns)))
	c.readersWg.Add(len(conns))
	for _, conn := range conns {
		go c.readFrom(conn)
	}
	return c
}

// WriteTo sends p to addr using the next conn in round-robin order. The
// modulo is performed in uint64 space, so the result fits in [0, len(conns))
// regardless of overflow.
func (c *MultiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	i := int(c.idx.Add(1) % uint64(len(c.conns)))
	return c.conns[i].WriteTo(p, addr)
}

// ReadFrom blocks until a packet is received from any underlying conn, all
// readers exit (returns io.EOF), or Close is called (returns net.ErrClosed
// or io.EOF, depending on which signal wins the select).
func (c *MultiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case r, ok := <-c.recvCh:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(p, r.p)
		return n, r.addr, nil
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// Close closes all underlying conns, stops the background readers, and waits
// for them to exit. Safe to call multiple times — subsequent calls return
// nil immediately. After Close returns, ReadFrom returns either net.ErrClosed
// or io.EOF (both indicate the conn is done).
func (c *MultiPacketConn) Close() error {
	var first error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		for _, conn := range c.conns {
			if err := conn.Close(); err != nil && first == nil {
				first = err
			}
		}
		c.readersWg.Wait()
	})
	return first
}

func (c *MultiPacketConn) LocalAddr() net.Addr { return c.conns[0].LocalAddr() }

// SetDeadline propagates the deadline to every underlying conn. Returns the
// first error encountered, but always tries every conn.
func (c *MultiPacketConn) SetDeadline(t time.Time) error {
	var first error
	for _, conn := range c.conns {
		if err := conn.SetDeadline(t); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *MultiPacketConn) SetReadDeadline(t time.Time) error {
	var first error
	for _, conn := range c.conns {
		if err := conn.SetReadDeadline(t); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *MultiPacketConn) SetWriteDeadline(t time.Time) error {
	var first error
	for _, conn := range c.conns {
		if err := conn.SetWriteDeadline(t); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// readFrom forwards packets received from conn into the shared recvCh. When
// every reader has exited, recvCh is closed so ReadFrom returns io.EOF.
// readersWg.Done runs last so Close's Wait synchronises with full reader
// exit including the recvCh close.
func (c *MultiPacketConn) readFrom(conn net.PacketConn) {
	defer func() {
		if c.activeReads.Add(-1) == 0 {
			// Last reader to exit closes recvCh; safe because no more
			// sends will happen.
			close(c.recvCh)
		}
		c.readersWg.Done()
	}()
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
