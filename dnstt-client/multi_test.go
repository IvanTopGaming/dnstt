package main

import (
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a minimal net.PacketConn for testing MultiPacketConn.
type fakeConn struct {
	writes atomic.Int64
	closed atomic.Bool
	// readCh, if set, supplies packets to ReadFrom; otherwise ReadFrom blocks
	// until Close is called.
	readCh chan []byte
	addr   net.Addr
	// Per-method counters.
	deadlineCalls      atomic.Int64
	readDeadlineCalls  atomic.Int64
	writeDeadlineCalls atomic.Int64
	// Per-method error knobs (returned by the corresponding Set*Deadline call
	// when non-nil).
	deadlineErr      error
	readDeadlineErr  error
	writeDeadlineErr error
}

func (f *fakeConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if f.closed.Load() {
		return 0, net.ErrClosed
	}
	f.writes.Add(1)
	return len(p), nil
}

func (f *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if f.readCh == nil {
		// Block until closed.
		for !f.closed.Load() {
			time.Sleep(5 * time.Millisecond)
		}
		return 0, nil, net.ErrClosed
	}
	pkt, ok := <-f.readCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, pkt)
	return n, f.addr, nil
}

func (f *fakeConn) Close() error        { f.closed.Store(true); return nil }
func (f *fakeConn) LocalAddr() net.Addr { return f.addr }

func (f *fakeConn) SetDeadline(t time.Time) error {
	f.deadlineCalls.Add(1)
	return f.deadlineErr
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	f.readDeadlineCalls.Add(1)
	return f.readDeadlineErr
}

func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	f.writeDeadlineCalls.Add(1)
	return f.writeDeadlineErr
}

func TestMultiPacketConn_IndexNoOverflow(t *testing.T) {
	c1, c2, c3 := &fakeConn{}, &fakeConn{}, &fakeConn{}
	m := NewMultiPacketConn([]net.PacketConn{c1, c2, c3})
	defer m.Close()

	// Pre-set idx near uint64 max so the next Add wraps.
	m.idx.Store(math.MaxUint64 - 5)

	for i := 0; i < 1000; i++ {
		if _, err := m.WriteTo([]byte{0xAA}, nil); err != nil {
			t.Fatalf("WriteTo at i=%d returned err: %v", i, err)
		}
	}
	total := c1.writes.Load() + c2.writes.Load() + c3.writes.Load()
	if total != 1000 {
		t.Fatalf("expected 1000 total writes, got %d (c1=%d c2=%d c3=%d)",
			total, c1.writes.Load(), c2.writes.Load(), c3.writes.Load())
	}
}

func TestMultiPacketConn_DeadlinePropagation(t *testing.T) {
	c1, c2 := &fakeConn{}, &fakeConn{}
	m := NewMultiPacketConn([]net.PacketConn{c1, c2})
	defer m.Close()

	if err := m.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if c1.deadlineCalls.Load() != 1 || c2.deadlineCalls.Load() != 1 {
		t.Fatalf("expected each conn to receive 1 SetDeadline call, got c1=%d c2=%d",
			c1.deadlineCalls.Load(), c2.deadlineCalls.Load())
	}
}

// TestMultiPacketConn_AllDeadlineMethodsPropagate locks in that all three
// Set*Deadline variants on MultiPacketConn dispatch to the matching method
// on every underlying conn — guards against a copy-paste drift in
// dnstt-client/multi.go where, e.g., SetReadDeadline accidentally calls
// conn.SetDeadline.
func TestMultiPacketConn_AllDeadlineMethodsPropagate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		call    func(m *MultiPacketConn) error
		counter func(c *fakeConn) int64
	}{
		{"SetDeadline", func(m *MultiPacketConn) error { return m.SetDeadline(time.Now()) },
			func(c *fakeConn) int64 { return c.deadlineCalls.Load() }},
		{"SetReadDeadline", func(m *MultiPacketConn) error { return m.SetReadDeadline(time.Now()) },
			func(c *fakeConn) int64 { return c.readDeadlineCalls.Load() }},
		{"SetWriteDeadline", func(m *MultiPacketConn) error { return m.SetWriteDeadline(time.Now()) },
			func(c *fakeConn) int64 { return c.writeDeadlineCalls.Load() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := &fakeConn{}, &fakeConn{}
			m := NewMultiPacketConn([]net.PacketConn{c1, c2})
			defer m.Close()
			if err := tc.call(m); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			// Each underlying conn must see exactly one call to the matching method.
			if got1, got2 := tc.counter(c1), tc.counter(c2); got1 != 1 || got2 != 1 {
				t.Fatalf("%s: expected (1,1) calls, got (%d,%d)", tc.name, got1, got2)
			}
			// Other counters on each conn must remain zero — proves we hit
			// the right method, not a sibling.
			for i, c := range []*fakeConn{c1, c2} {
				if tc.name != "SetDeadline" && c.deadlineCalls.Load() != 0 {
					t.Errorf("conn[%d] %s leaked into SetDeadline counter (%d)", i, tc.name, c.deadlineCalls.Load())
				}
				if tc.name != "SetReadDeadline" && c.readDeadlineCalls.Load() != 0 {
					t.Errorf("conn[%d] %s leaked into SetReadDeadline counter (%d)", i, tc.name, c.readDeadlineCalls.Load())
				}
				if tc.name != "SetWriteDeadline" && c.writeDeadlineCalls.Load() != 0 {
					t.Errorf("conn[%d] %s leaked into SetWriteDeadline counter (%d)", i, tc.name, c.writeDeadlineCalls.Load())
				}
			}
		})
	}
}

// TestMultiPacketConn_DeadlineFirstErrorReturned verifies that when one
// underlying conn returns an error, MultiPacketConn returns the first one
// AND still calls every conn (don't short-circuit). This locks in the
// audit-fix invariant for defect #4.
func TestMultiPacketConn_DeadlineFirstErrorReturned(t *testing.T) {
	errFirst := errors.New("first")
	errSecond := errors.New("second")

	// c1 errors, c2 errors with a different sentinel, c3 succeeds — only the
	// first error must propagate, but all three must be called.
	c1 := &fakeConn{deadlineErr: errFirst}
	c2 := &fakeConn{deadlineErr: errSecond}
	c3 := &fakeConn{}
	m := NewMultiPacketConn([]net.PacketConn{c1, c2, c3})
	defer m.Close()

	err := m.SetDeadline(time.Now())
	if !errors.Is(err, errFirst) {
		t.Fatalf("expected first error %v, got %v", errFirst, err)
	}
	if c1.deadlineCalls.Load() != 1 || c2.deadlineCalls.Load() != 1 || c3.deadlineCalls.Load() != 1 {
		t.Fatalf("expected each conn called exactly once; got c1=%d c2=%d c3=%d",
			c1.deadlineCalls.Load(), c2.deadlineCalls.Load(), c3.deadlineCalls.Load())
	}
}

func TestMultiPacketConn_AllReadersDie_ReadReturns(t *testing.T) {
	// Create conns with a closeable readCh; close all immediately so each
	// reader goroutine exits (ReadFrom returns ErrClosed).
	c1 := &fakeConn{readCh: make(chan []byte)}
	c2 := &fakeConn{readCh: make(chan []byte)}
	close(c1.readCh)
	close(c2.readCh)

	m := NewMultiPacketConn([]net.PacketConn{c1, c2})

	buf := make([]byte, 64)
	done := make(chan error, 1)
	go func() {
		_, _, err := m.ReadFrom(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF after readers exhausted, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not return after all readers exhausted")
	}
}

func TestMultiPacketConn_DoubleClose(t *testing.T) {
	c1, c2 := &fakeConn{}, &fakeConn{}
	m := NewMultiPacketConn([]net.PacketConn{c1, c2})

	if err := m.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMultiPacketConn_ConcurrentClose verifies Close is safe under
// concurrent calls. Run with -race to catch any data race or double-close
// panic.
func TestMultiPacketConn_ConcurrentClose(t *testing.T) {
	m := NewMultiPacketConn([]net.PacketConn{&fakeConn{}, &fakeConn{}})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Close()
		}()
	}
	wg.Wait()
}
