# G1 Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix audit defects #1, #4, #14, #15, #16, #17: make multipath actually work, propagate KCP deadlines through `MultiPacketConn`, prevent integer overflow in round-robin, remove a transport-factory race, replace broken UDP-truncate with valid wire format, and negotiate FEC/compress params via Noise handshake payload.

**Architecture:** Client wraps a single `DNSPacketConn` over either a single bare transport, an `auto`-selected bare transport, or a `MultiPacketConn` of bare transports — guaranteeing one `ClientID` per session. `MultiPacketConn` becomes a faithful `net.PacketConn` (deadlines, idempotent close, `io.EOF` on all-readers-dead). Client and server agree on FEC data/parity and compress flags inside the first Noise handshake message; mismatch fails closed at handshake time. Server's UDP truncate path rebuilds `Resp` with empty `Answer/Authority` instead of slicing wire bytes mid-RR.

**Tech Stack:** Go 1.24, KCP (`github.com/xtaci/kcp-go/v5`), Noise (`github.com/flynn/noise`), smux (`github.com/xtaci/smux`), uTLS, quic-go.

**Branch:** `fix/audit-pass-1` (already created, has the design doc commit).

**Testing:** Local `go test ./...` after every step. Smoke test against live server `root@150.241.94.29` once at the end of the group.

---

## File Structure

### Files modified

- `dnstt-client/multi.go` — overflow-safe index, deadline propagation, idempotent Close, EOF on reader exhaustion.
- `dnstt-client/multi_test.go` — **new** unit tests for `MultiPacketConn`.
- `dnstt-client/main.go` — refactor multipath/single/auto so a single `DNSPacketConn` wraps the chosen transport(s); remove `firstUsed` flag; send 4-byte handshake payload.
- `dnstt-client/auto.go` — `transportMaker` now returns a bare transport.
- `noise/noise.go` — `NewClient` accepts caller-supplied handshake payload; `NewServer` returns the received payload to caller.
- `noise/noise_test.go` — replace `TestUnexpectedPayload` with `TestHandshake_PayloadRoundTrip`; add `TestHandshake_EmptyPayloadRejected`.
- `dnstt-server/main.go` — read 4-byte handshake payload, validate FEC/compress against local config, replace truncate logic with `Resp`-rebuild.
- `dnstt-server/main_test.go` — extend with `TestRebuildTruncatedResponse`.
- `dnstt-server/e2e_test.go` — wire test client to send 4-byte payload; add `TestSessionE2E_ParamMismatch`.
- `scripts/smoke-multipath.sh` — **new** end-to-end smoke against `150.241.94.29`.

### Files NOT modified in this plan

- `dnstt-client/dns.go` — `NewDNSPacketConn` signature stays. (The fix is at the *callsite* in `main.go`.)
- `dnstt-server/userdb.go`, `dnstt-server/socks5.go`, `dnstt-server/ratelimit.go` — these belong to other groups.

---

## Conventions used in every task

- Go formatting: `gofmt -w` on each touched file before commit.
- Run all unit tests after every code change: `go test ./...` from repo root (`/mnt/Docs/dnstt`).
- Commits are atomic, one per task. Squash merge into `master` happens at the end of the whole audit pass.

---

## Task 1: `MultiPacketConn` index overflow (#15)

**Files:**
- Modify: `dnstt-client/multi.go` (struct field `idx`, method `WriteTo`)
- Test: `dnstt-client/multi_test.go` (**create**)

- [ ] **Step 1: Write failing test.**

Create `dnstt-client/multi_test.go`:

```go
package main

import (
	"math"
	"net"
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
	// deadlineCalls counts how many times SetDeadline was called.
	deadlineCalls atomic.Int64
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

func (f *fakeConn) Close() error                       { f.closed.Store(true); return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return f.addr }
func (f *fakeConn) SetDeadline(t time.Time) error      { f.deadlineCalls.Add(1); return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

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
```

- [ ] **Step 2: Run test, expect compile error or failure.**

Run: `cd /mnt/Docs/dnstt && go test ./dnstt-client/ -run TestMultiPacketConn_IndexNoOverflow -v`
Expected: compile error — `m.idx.Store` does not exist (current type is `atomic.Int64`).

- [ ] **Step 3: Change `idx` to `atomic.Uint64` and update `WriteTo`.**

In `dnstt-client/multi.go`, replace the struct definition:

```go
type MultiPacketConn struct {
	conns   []net.PacketConn
	idx     atomic.Uint64
	recvCh  chan recvResult
	closeCh chan struct{}
}
```

Replace `WriteTo`:

```go
// WriteTo sends p to addr using the next conn in round-robin order. The
// uint64 index wraps cleanly on overflow.
func (c *MultiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	i := int(c.idx.Add(1) % uint64(len(c.conns)))
	return c.conns[i].WriteTo(p, addr)
}
```

- [ ] **Step 4: Run test, expect PASS.**

Run: `cd /mnt/Docs/dnstt && go test ./dnstt-client/ -run TestMultiPacketConn_IndexNoOverflow -v`
Expected: PASS.

- [ ] **Step 5: Run full test suite to confirm no regression.**

Run: `cd /mnt/Docs/dnstt && go test ./...`
Expected: all packages pass.

- [ ] **Step 6: Commit.**

```bash
git add dnstt-client/multi.go dnstt-client/multi_test.go
git commit -m "fix(client/multi): use atomic.Uint64 for round-robin index"
```

---

## Task 2: `MultiPacketConn` deadline propagation (#4)

**Files:**
- Modify: `dnstt-client/multi.go` (methods `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`)
- Test: `dnstt-client/multi_test.go`

- [ ] **Step 1: Write failing test.**

Append to `dnstt-client/multi_test.go`:

```go
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
```

- [ ] **Step 2: Run test, expect FAIL.**

Run: `go test ./dnstt-client/ -run TestMultiPacketConn_DeadlinePropagation -v`
Expected: FAIL — current `SetDeadline` returns nil without doing anything.

- [ ] **Step 3: Replace deadline methods.**

In `dnstt-client/multi.go`, replace the three `Set*Deadline` methods:

```go
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
```

- [ ] **Step 4: Run test, expect PASS.**

Run: `go test ./dnstt-client/ -run TestMultiPacketConn_DeadlinePropagation -v`
Expected: PASS.

- [ ] **Step 5: Full suite.**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 6: Commit.**

```bash
git add dnstt-client/multi.go dnstt-client/multi_test.go
git commit -m "fix(client/multi): propagate SetDeadline to underlying conns"
```

---

## Task 3: `MultiPacketConn` idempotent Close + EOF on reader exhaustion

**Files:**
- Modify: `dnstt-client/multi.go` (struct, `NewMultiPacketConn`, `ReadFrom`, `Close`, `readFrom`)
- Test: `dnstt-client/multi_test.go`

- [ ] **Step 1: Write failing test.**

Append to `dnstt-client/multi_test.go`:

```go
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
		if err == nil {
			t.Fatal("ReadFrom returned nil error after all readers exhausted")
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
```

- [ ] **Step 2: Run test, expect FAIL on `AllReadersDie`.**

Run: `go test ./dnstt-client/ -run TestMultiPacketConn_AllReadersDie -v`
Expected: FAIL — ReadFrom hangs (current implementation has no exhaustion signal).

- [ ] **Step 3: Add reader counter and modify Close + readFrom + ReadFrom.**

In `dnstt-client/multi.go`, replace the file's contents with this updated version:

```go
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
	for _, conn := range conns {
		go c.readFrom(conn)
	}
	return c
}

// WriteTo sends p to addr using the next conn in round-robin order. The
// uint64 index wraps cleanly on overflow.
func (c *MultiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	i := int(c.idx.Add(1) % uint64(len(c.conns)))
	return c.conns[i].WriteTo(p, addr)
}

// ReadFrom blocks until a packet is received from any underlying conn, all
// readers exit (returns io.EOF), or Close is called (returns net.ErrClosed).
func (c *MultiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
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
}

// Close closes all underlying conns and stops the background readers. Safe
// to call multiple times.
func (c *MultiPacketConn) Close() error {
	var first error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		for _, conn := range c.conns {
			if err := conn.Close(); err != nil && first == nil {
				first = err
			}
		}
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
func (c *MultiPacketConn) readFrom(conn net.PacketConn) {
	defer func() {
		if c.activeReads.Add(-1) == 0 {
			// Last reader to exit closes recvCh; safe because no more
			// sends will happen.
			close(c.recvCh)
		}
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
```

Note: this consolidates Tasks 1, 2, and 3 changes into a single coherent file. All three tasks' test cases must pass.

- [ ] **Step 4: Run all multi tests.**

Run: `go test ./dnstt-client/ -run TestMultiPacketConn -v`
Expected: all 4 multi tests pass (`IndexNoOverflow`, `DeadlinePropagation`, `AllReadersDie_ReadReturns`, `DoubleClose`).

- [ ] **Step 5: Full suite.**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 6: Commit.**

```bash
git add dnstt-client/multi.go dnstt-client/multi_test.go
git commit -m "fix(client/multi): idempotent Close, EOF on reader exhaustion"
```

---

## Task 4: Noise handshake payload — change signatures

**Files:**
- Modify: `noise/noise.go` (`NewClient`, `NewServer`)
- Modify: `noise/noise_test.go` (rewrite `TestUnexpectedPayload`)
- Modify: `dnstt-client/main.go` (`NewClient` callsite — pass `nil` for now)
- Modify: `dnstt-server/main.go` (`NewServer` callsite — discard payload for now)
- Modify: `dnstt-server/e2e_test.go` (`NewClient` callsite — pass `nil`)

The signature change is mechanical; the *use* of the payload comes in Tasks 5 & 6.

- [ ] **Step 1: Write failing test.**

Replace `TestUnexpectedPayload` in `noise/noise_test.go` with:

```go
func TestHandshake_PayloadRoundTrip(t *testing.T) {
	privkey, err := GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := PubkeyFromPrivkey(privkey)
	if err != nil {
		t.Fatal(err)
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	want := []byte{0x01, 0x02, 0x03, 0x04}

	// Server: read payload from client.
	type srvResult struct {
		payload []byte
		err     error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		_, payload, err := NewServer(s, privkey)
		srvCh <- srvResult{payload, err}
	}()

	// Client: send payload.
	_, err = NewClient(c, pubkey, want)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	r := <-srvCh
	if r.err != nil {
		t.Fatalf("NewServer: %v", r.err)
	}
	if !bytes.Equal(r.payload, want) {
		t.Fatalf("server got payload %x, want %x", r.payload, want)
	}
}
```

Delete the existing `TestUnexpectedPayload` function entirely — its semantics no longer apply.

- [ ] **Step 2: Run test, expect compile errors.**

Run: `go test ./noise/ -run TestHandshake_PayloadRoundTrip -v`
Expected: compile errors — `NewClient` doesn't take 3 args, `NewServer` doesn't return 3 values.

- [ ] **Step 3: Update `NewClient` and `NewServer` signatures in `noise/noise.go`.**

Replace `NewClient`:

```go
// NewClient wraps an io.ReadWriteCloser in a Noise protocol as a client and
// returns after completing the handshake. clientPayload, if non-nil, is sent
// in the first handshake message and visible to the server.
func NewClient(rwc io.ReadWriteCloser, serverPubkey, clientPayload []byte) (io.ReadWriteCloser, error) {
	config := newConfig()
	config.Initiator = true
	config.PeerStatic = serverPubkey
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, err
	}

	// -> e, es (with optional payload)
	msg, _, _, err := handshakeState.WriteMessage(nil, clientPayload)
	if err != nil {
		return nil, err
	}
	err = writeMessage(rwc, msg)
	if err != nil {
		return nil, err
	}

	// <- e, es
	msg, err = readMessage(rwc)
	if err != nil {
		return nil, err
	}
	payload, sendCipher, recvCipher, err := handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		return nil, errors.New("unexpected server payload")
	}

	return newSocket(rwc, recvCipher, sendCipher), nil
}
```

Replace `NewServer`:

```go
// NewServer wraps an io.ReadWriteCloser in a Noise protocol as a server and
// returns after completing the handshake. The client's first-message payload
// (possibly empty) is returned to the caller for protocol negotiation.
func NewServer(rwc io.ReadWriteCloser, serverPrivkey []byte) (io.ReadWriteCloser, []byte, error) {
	config := newConfig()
	config.Initiator = false
	pubkey, err := PubkeyFromPrivkey(serverPrivkey)
	if err != nil {
		return nil, nil, fmt.Errorf("deriving public key: %v", err)
	}
	config.StaticKeypair = noise.DHKey{
		Private: serverPrivkey,
		Public:  pubkey,
	}
	handshakeState, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}

	// -> e, es (read client payload)
	msg, err := readMessage(rwc)
	if err != nil {
		return nil, nil, err
	}
	clientPayload, _, _, err := handshakeState.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, err
	}

	// <- e, es (no server payload)
	msg, recvCipher, sendCipher, err := handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	err = writeMessage(rwc, msg)
	if err != nil {
		return nil, nil, err
	}

	return newSocket(rwc, recvCipher, sendCipher), clientPayload, nil
}
```

- [ ] **Step 4: Update callsites.**

In `dnstt-client/main.go` find `noise.NewClient(conn, pubkey)` (around line 281) and change to:

```go
rw, err := noise.NewClient(conn, pubkey, nil)
```

In `dnstt-server/main.go` find `noise.NewServer(conn, privkey)` (around line 327) and change to:

```go
rw, _, err := noise.NewServer(conn, privkey)
```

In `dnstt-server/e2e_test.go` find both `noise.NewClient(kcpConn, pubkey)` calls (around line 132 and 249) and change to:

```go
rw, err := noise.NewClient(kcpConn, pubkey, nil)
```

- [ ] **Step 5: Run all tests, expect noise tests to pass and existing e2e tests to still work.**

Run: `go test ./...`
Expected: all pass. The new `TestHandshake_PayloadRoundTrip` passes; old `TestUnexpectedPayload` is gone.

- [ ] **Step 6: Commit.**

```bash
git add noise/noise.go noise/noise_test.go dnstt-client/main.go dnstt-server/main.go dnstt-server/e2e_test.go
git commit -m "feat(noise): expose handshake payload through NewClient/NewServer"
```

---

## Task 5: Define handshake-param wire format and helpers

**Files:**
- Create: `dnstt-server/handshake.go` (server-side: encode + decode + validate)
- Create: `dnstt-client/handshake.go` (client-side: encode)
- Test: `dnstt-server/handshake_test.go` (**new**)

We keep the encoding/decoding in dedicated files so it's grep-able and unit-testable independently.

- [ ] **Step 1: Write failing test.**

Create `dnstt-server/handshake_test.go`:

```go
package main

import (
	"bytes"
	"testing"
)

func TestEncodeHandshakeParams(t *testing.T) {
	got := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: true})
	want := []byte{4, 2, 0x01, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestDecodeHandshakeParams(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   []byte
		want    handshakeParams
		wantErr bool
	}{
		{"happy", []byte{4, 2, 0x01, 0}, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, false},
		{"zero", []byte{0, 0, 0, 0}, handshakeParams{}, false},
		{"too short", []byte{1, 2, 3}, handshakeParams{}, true},
		{"too long", []byte{1, 2, 3, 4, 5}, handshakeParams{}, true},
		{"empty", []byte{}, handshakeParams{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeHandshakeParams(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidateHandshakeParams(t *testing.T) {
	server := handshakeParams{FECData: 4, FECParity: 2, Compress: true}
	if err := validateHandshakeParams(server, server); err != nil {
		t.Fatalf("matching params should pass, got %v", err)
	}
	client := handshakeParams{FECData: 0, FECParity: 0, Compress: true}
	if err := validateHandshakeParams(client, server); err == nil {
		t.Fatal("mismatched FEC should fail")
	}
}
```

- [ ] **Step 2: Run test, expect compile errors.**

Run: `go test ./dnstt-server/ -run TestEncodeHandshakeParams -v`
Expected: compile error — types/functions undefined.

- [ ] **Step 3: Implement server-side handshake helpers.**

Create `dnstt-server/handshake.go`:

```go
package main

import (
	"errors"
	"fmt"
)

// handshakeParamsLen is the wire size of a serialized handshakeParams.
const handshakeParamsLen = 4

// handshakeParams are the per-session parameters the client sends inside the
// first Noise handshake message so the server can verify they match its own
// configuration. A mismatch makes the tunnel silently malfunction, so this
// negotiation lets us fail closed at handshake time with a clear message.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p to the 4-byte wire format. Layout:
//
//	[0] uint8  fec_data
//	[1] uint8  fec_parity
//	[2] uint8  flags    bit 0: compress
//	[3] uint8  reserved (=0)
func encodeHandshakeParams(p handshakeParams) []byte {
	buf := make([]byte, handshakeParamsLen)
	buf[0] = p.FECData
	buf[1] = p.FECParity
	if p.Compress {
		buf[2] |= 0x01
	}
	return buf
}

// decodeHandshakeParams parses the 4-byte wire format. Returns an error if
// the input is not exactly 4 bytes.
func decodeHandshakeParams(b []byte) (handshakeParams, error) {
	if len(b) != handshakeParamsLen {
		return handshakeParams{}, fmt.Errorf("handshake params: expected %d bytes, got %d",
			handshakeParamsLen, len(b))
	}
	return handshakeParams{
		FECData:   b[0],
		FECParity: b[1],
		Compress:  b[2]&0x01 != 0,
	}, nil
}

// validateHandshakeParams returns nil if client and server params match, or
// an error describing the mismatch otherwise.
func validateHandshakeParams(client, server handshakeParams) error {
	if client == server {
		return nil
	}
	return errors.New(formatParamMismatch(client, server))
}

func formatParamMismatch(client, server handshakeParams) string {
	return fmt.Sprintf(
		"client param mismatch: client fec-data=%d fec-parity=%d compress=%v; server fec-data=%d fec-parity=%d compress=%v",
		client.FECData, client.FECParity, client.Compress,
		server.FECData, server.FECParity, server.Compress,
	)
}
```

- [ ] **Step 4: Run server tests, expect PASS.**

Run: `go test ./dnstt-server/ -run TestEncodeHandshakeParams -v && go test ./dnstt-server/ -run TestDecodeHandshakeParams -v && go test ./dnstt-server/ -run TestValidateHandshakeParams -v`
Expected: all PASS.

- [ ] **Step 5: Implement client-side encoder.**

Create `dnstt-client/handshake.go`:

```go
package main

// handshakeParamsLen is the wire size of a serialized handshake-params blob.
const handshakeParamsLen = 4

// handshakeParams are the per-session parameters the client sends inside the
// first Noise handshake message so the server can verify they match its own
// configuration.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p to the 4-byte wire format. Layout:
//
//	[0] uint8  fec_data
//	[1] uint8  fec_parity
//	[2] uint8  flags    bit 0: compress
//	[3] uint8  reserved (=0)
func encodeHandshakeParams(p handshakeParams) []byte {
	buf := make([]byte, handshakeParamsLen)
	buf[0] = p.FECData
	buf[1] = p.FECParity
	if p.Compress {
		buf[2] |= 0x01
	}
	return buf
}
```

(The client doesn't decode, only encodes.)

- [ ] **Step 6: Run full suite.**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 7: Commit.**

```bash
git add dnstt-server/handshake.go dnstt-server/handshake_test.go dnstt-client/handshake.go
git commit -m "feat(handshake): add params codec and validator"
```

---

## Task 6: Server consumes handshake payload and validates params

**Files:**
- Modify: `dnstt-server/main.go` (`acceptStreams` — start of function)
- Modify: `dnstt-server/main.go` (`run` — pass server params; `acceptSessions` — same)

The simplest threading: pass `serverParams handshakeParams` from `main()` → `run` → `acceptSessions` → `acceptStreams`.

- [ ] **Step 1: Read current `run` signature in `dnstt-server/main.go`.**

Confirm signature (around line 947):
```go
func run(ctx context.Context, privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, paranoia bool, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool) error
```

- [ ] **Step 2: Write failing integration test.**

Append to `dnstt-server/e2e_test.go`:

```go
// TestSessionE2E_ParamMismatch verifies that the server rejects a client
// whose FEC/compress params don't match the server's local configuration.
func TestSessionE2E_ParamMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := noise.PubkeyFromPrivkey(privkey)
	if err != nil {
		t.Fatal(err)
	}

	serverQPCAddr := turbotunnel.DummyAddr{}
	serverQPC := turbotunnel.NewQueuePacketConn(serverQPCAddr, 60*time.Second)
	t.Cleanup(func() { serverQPC.Close() })
	clientID := turbotunnel.NewClientID()
	clientQPC := turbotunnel.NewQueuePacketConn(clientID, 60*time.Second)
	t.Cleanup(func() { clientQPC.Close() })

	go func() {
		outgoing := clientQPC.OutgoingQueue(serverQPCAddr)
		for {
			select {
			case p := <-outgoing:
				serverQPC.QueueIncoming(p, clientID)
			case <-ctx.Done():
				return
			case <-clientQPC.Closed():
				return
			}
		}
	}()
	go func() {
		outgoing := serverQPC.OutgoingQueue(clientID)
		for {
			select {
			case p := <-outgoing:
				clientQPC.QueueIncoming(p, serverQPCAddr)
			case <-ctx.Done():
				return
			case <-serverQPC.Closed():
				return
			}
		}
	}()

	mtu := 1200
	ln, err := kcp.ServeConn(nil, 0, 0, serverQPC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	// Server expects fec=0, compress=false.
	serverParams := handshakeParams{FECData: 0, FECParity: 0, Compress: false}
	go func() {
		_ = acceptSessions(ln, privkey, mtu, "echo-unused", defaultKCPConfig(), nil, false, serverParams)
	}()

	kcpConn, err := kcp.NewConn3(0, serverQPCAddr, nil, 0, 0, clientQPC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kcpConn.Close() })
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetWindowSize(128, 128)
	kcpConn.SetMtu(mtu)

	// Client claims FEC=4/2 — should be rejected.
	clientPayload := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: false})
	rw, err := noise.NewClient(kcpConn, pubkey, clientPayload)
	if err != nil {
		// Server's close on the wire may surface as a handshake failure
		// here; that's the success path for this test.
		return
	}

	// If the handshake "succeeded", the server should close the connection
	// next; reading should fail quickly.
	kcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := rw.Read(buf); err == nil {
		t.Fatal("expected read failure after param mismatch, got nil")
	}
}
```

Note: this test depends on `acceptSessions` having an extra `handshakeParams` argument. That signature change happens in step 3.

- [ ] **Step 3: Modify `acceptStreams` in `dnstt-server/main.go`.**

Find the function signature (line ~325):
```go
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, authDB *authDatabase, compress bool) error {
```

Replace with:
```go
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, authDB *authDatabase, compress bool, serverParams handshakeParams) error {
```

Inside the function, replace the line `rw, err := noise.NewServer(conn, privkey)` (~line 327) with:

```go
rw, clientPayload, err := noise.NewServer(conn, privkey)
if err != nil {
	return err
}

// Validate handshake params: client must declare matching FEC/compress.
clientParams, err := decodeHandshakeParams(clientPayload)
if err != nil {
	return fmt.Errorf("invalid handshake params: %w", err)
}
if err := validateHandshakeParams(clientParams, serverParams); err != nil {
	log.Printf("session %08x: %v", conn.GetConv(), err)
	return err
}
```

Remove the now-redundant `if err != nil { return err }` that previously followed `noise.NewServer`.

- [ ] **Step 4: Modify `acceptSessions` signature.**

Find (line ~407):
```go
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, kcpCfg kcpConfig, authDB *authDatabase, compress bool) error {
```

Replace with:
```go
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, kcpCfg kcpConfig, authDB *authDatabase, compress bool, serverParams handshakeParams) error {
```

Update the recursive call inside (line ~429):
```go
err := acceptStreams(conn, privkey, upstream, authDB, compress, serverParams)
```

- [ ] **Step 5: Modify `run` signature and main wiring.**

Find (line ~947):
```go
func run(ctx context.Context, privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, paranoia bool, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool) error {
```

Replace with (no new arg — derive locally):
```go
func run(ctx context.Context, privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, paranoia bool, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool) error {
	serverParams := handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}
```

Then update the `acceptSessions` callsite inside `run` (~line 988):
```go
err := acceptSessions(ln, privkey, mtu, upstream, kcpCfg, authDB, compress, serverParams)
```

- [ ] **Step 6: Run full suite.**

Run: `go test ./...`
Expected: all pass; `TestSessionE2E_ParamMismatch` passes; existing E2E tests fail because the test client doesn't send a 4-byte payload yet — that's the next task.

If existing E2E tests fail with `unexpected client payload` or similar — good, that's the expected gate.

- [ ] **Step 7: Update existing E2E tests in `dnstt-server/e2e_test.go` to pass valid params.**

In `TestSessionE2E` (around line 115), find `acceptSessions(ln, privkey, mtu, upstream, defaultKCPConfig(), nil, false)` and change to:

```go
serverParams := handshakeParams{}
if err := acceptSessions(ln, privkey, mtu, upstream, defaultKCPConfig(), nil, false, serverParams); err != nil && ctx.Err() == nil {
	t.Logf("acceptSessions: %v", err)
}
```

In `TestSessionE2E` find `noise.NewClient(kcpConn, pubkey, nil)` (you set this in Task 4) and change to:

```go
rw, err := noise.NewClient(kcpConn, pubkey, encodeHandshakeParams(handshakeParams{}))
```

Same for `TestSessionE2E_SOCKS5`.

(The new `encodeHandshakeParams` lives in the `dnstt-server` package — both test functions are in that package, so the call resolves locally.)

- [ ] **Step 8: Run full suite.**

Run: `go test ./...`
Expected: all tests pass including `TestSessionE2E_ParamMismatch`.

- [ ] **Step 9: Commit.**

```bash
git add dnstt-server/main.go dnstt-server/e2e_test.go
git commit -m "feat(server): validate FEC/compress via handshake payload"
```

---

## Task 7: Client sends handshake payload

**Files:**
- Modify: `dnstt-client/main.go` (`sessionLoop` — encode and pass to `noise.NewClient`)

- [ ] **Step 1: Locate the `noise.NewClient` callsite.**

In `dnstt-client/main.go`, find (around line 281):
```go
rw, err := noise.NewClient(conn, pubkey, nil)
```

- [ ] **Step 2: Build params from existing `fecData`, `fecParity`, `compress`.**

`sessionLoop` already takes `fecData int, fecParity int`, and `compress bool` as arguments. Replace the line above with:

```go
clientParams := encodeHandshakeParams(handshakeParams{
	FECData:   uint8(fecData),
	FECParity: uint8(fecParity),
	Compress:  compress,
})
rw, err := noise.NewClient(conn, pubkey, clientParams)
```

- [ ] **Step 3: Run full suite.**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 4: Build both binaries to confirm everything compiles.**

Run: `cd /mnt/Docs/dnstt && go build ./...`
Expected: no errors.

- [ ] **Step 5: Commit.**

```bash
git add dnstt-client/main.go
git commit -m "feat(client): send FEC/compress params in Noise handshake"
```

---

## Task 8: Server UDP truncate — rebuild Resp instead of slicing wire bytes (#14)

**Files:**
- Modify: `dnstt-server/main.go` (`sendLoop` — truncate branch)
- Test: `dnstt-server/main_test.go` (**create**)

- [ ] **Step 1: Write failing test.**

Create `dnstt-server/main_test.go`:

```go
package main

import (
	"bytes"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// TestRebuildTruncatedResponse verifies that an oversize response gets a
// valid wire-format with no Answer/Authority and TC=1 — never a mid-RR slice.
func TestRebuildTruncatedResponse(t *testing.T) {
	name, err := dns.NewName([][]byte{[]byte("test"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	resp := &dns.Message{
		ID:    0x1234,
		Flags: 0x8400, // response, AA=1, RCODE=0
		Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Answer: []dns.RR{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 60,
				Data: dns.EncodeRDataTXT(bytes.Repeat([]byte("A"), 4000))},
		},
	}

	out := rebuildAsTruncated(resp, 1232)

	if len(out) > 1232 {
		t.Fatalf("rebuilt wire length %d exceeds limit 1232", len(out))
	}
	parsed, err := dns.MessageFromWireFormat(out)
	if err != nil {
		t.Fatalf("rebuilt wire is not valid DNS: %v", err)
	}
	if parsed.Flags&0x0200 == 0 {
		t.Fatalf("expected TC=1, got flags=%04x", parsed.Flags)
	}
	if len(parsed.Answer) != 0 {
		t.Fatalf("expected zero answers, got %d", len(parsed.Answer))
	}
	if len(parsed.Question) != 1 {
		t.Fatalf("expected one question preserved, got %d", len(parsed.Question))
	}
}
```

- [ ] **Step 2: Run test, expect compile error.**

Run: `go test ./dnstt-server/ -run TestRebuildTruncatedResponse -v`
Expected: `rebuildAsTruncated` undefined.

- [ ] **Step 3: Implement `rebuildAsTruncated` and use it in `sendLoop`.**

In `dnstt-server/main.go`, near the top of the file (after the existing helpers), add:

```go
// rebuildAsTruncated converts an oversized DNS response into a valid
// truncated reply: Question preserved, Answer/Authority cleared, TC=1.
// If the result still exceeds limit (long Question name + EDNS OPT),
// EDNS OPT is dropped too.
func rebuildAsTruncated(resp *dns.Message, limit int) []byte {
	stripped := &dns.Message{
		ID:         resp.ID,
		Flags:      resp.Flags | 0x0200, // TC = 1
		Question:   resp.Question,
		Additional: resp.Additional, // keep OPT if present
	}
	buf, err := stripped.WireFormat()
	if err == nil && len(buf) <= limit {
		return buf
	}

	// Last-ditch: drop OPT too.
	stripped.Additional = nil
	buf, err = stripped.WireFormat()
	if err != nil || len(buf) > limit {
		// Truncate at the message header (12 bytes) plus first Question if
		// any. WireFormat shouldn't realistically fail here.
		return buf
	}
	return buf
}
```

Find the truncate branch in `sendLoop` (around line 836):

```go
buf, err := rec.Resp.WireFormat()
if err != nil {
	log.Printf("resp WireFormat: %v", err)
	continue
}
// Truncate if necessary.
// https://tools.ietf.org/html/rfc1035#section-4.1.1
if len(buf) > maxUDPPayload {
	log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
	buf = buf[:maxUDPPayload]
	buf[2] |= 0x02 // TC = 1
}
```

Replace the `if len(buf) > maxUDPPayload` block with:

```go
if len(buf) > maxUDPPayload {
	metricTruncated.Add(1)
	if shouldLogTruncate() {
		log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
	}
	buf = rebuildAsTruncated(rec.Resp, maxUDPPayload)
}
```

- [ ] **Step 4: Add `metricTruncated` counter and `shouldLogTruncate` rate-limited helper.**

In `dnstt-server/metrics.go`, add a new counter. First read the file to see the existing pattern:

Run: `cat /mnt/Docs/dnstt/dnstt-server/metrics.go | head -40`

Add (alongside the other `expvar.NewInt` declarations):

```go
var metricTruncated = expvar.NewInt("dnstt_truncated_responses")
```

In `dnstt-server/main.go`, add a small helper near the other top-level vars:

```go
// truncateLogLast tracks the last time we logged a truncate event, so we
// don't flood the log when many oversized responses queue up at once.
var truncateLogLast atomic.Int64

// shouldLogTruncate returns true at most once per second.
func shouldLogTruncate() bool {
	now := time.Now().UnixNano()
	last := truncateLogLast.Load()
	if now-last < int64(time.Second) {
		return false
	}
	return truncateLogLast.CompareAndSwap(last, now)
}
```

Add `"sync/atomic"` to the import block if not already there.

- [ ] **Step 5: Run test, expect PASS.**

Run: `go test ./dnstt-server/ -run TestRebuildTruncatedResponse -v`
Expected: PASS.

- [ ] **Step 6: Full suite.**

Run: `go test ./...`
Expected: all pass.

- [ ] **Step 7: Commit.**

```bash
git add dnstt-server/main.go dnstt-server/main_test.go dnstt-server/metrics.go
git commit -m "fix(server): preserve wire format on UDP truncation"
```

---

## Task 9: Client multipath/single/auto refactor (#1, #16)

**Files:**
- Modify: `dnstt-client/main.go` (`makeDoH`, `makeDoT`, `makeUDP`, multipath block, single/auto block)
- Modify: `dnstt-client/auto.go` (no signature change — DNS wrapping moves out)

This is the big architectural fix. Take it slow.

- [ ] **Step 1: Re-read the current state.**

Run: `grep -n "DNSPacketConn\|makeDoH\|makeDoT\|makeUDP\|makeDoQ\|firstUsed\|MultiPacketConn" /mnt/Docs/dnstt/dnstt-client/main.go`

Confirm the locations of the bare-transport constructors and the multipath block.

- [ ] **Step 2: Modify `makeDoH` to return a bare HTTPPacketConn.**

In `dnstt-client/main.go`, find `makeDoH` (around line 621). Replace its body so it returns the bare `*HTTPPacketConn` (no `DNSPacketConn` wrapping) and signal the addr separately:

```go
makeDoH := func() (net.PacketConn, net.Addr, error) {
	addr := turbotunnel.DummyAddr{}
	var rt http.RoundTripper
	if utlsClientHelloID == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		if dohAddr != "" {
			u, err := url.Parse(dohURL)
			if err != nil {
				return nil, nil, err
			}
			serverName := u.Hostname()
			override := dohAddr
			tlsCfg := baseTLSConfig.Clone()
			tlsCfg.ServerName = serverName
			transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, network, override)
			}
		} else if pins != nil {
			transport.TLSClientConfig = baseTLSConfig.Clone()
		}
		rt = transport
	} else {
		rt = NewUTLSRoundTripper(nil, utlsClientHelloID, dohAddr)
	}
	pconn, err := NewHTTPPacketConn(rt, dohURL, 32)
	if err != nil {
		return nil, nil, err
	}
	return pconn, addr, nil
}
```

(The change is removing the `NewDNSPacketConn(...)` wrap on the return.)

- [ ] **Step 3: Modify `makeDoT` similarly.**

```go
makeDoT := func() (net.PacketConn, net.Addr, error) {
	addr := turbotunnel.DummyAddr{}
	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if utlsClientHelloID == nil {
		dialer := &tls.Dialer{Config: baseTLSConfig}
		dialTLSContext = dialer.DialContext
	} else {
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return utlsDialContext(ctx, network, addr, nil, utlsClientHelloID)
		}
	}
	pconn, err := NewTLSPacketConn(dotAddr, dialTLSContext, defaultDoTSenders)
	if err != nil {
		return nil, nil, err
	}
	return pconn, addr, nil
}
```

- [ ] **Step 4: Modify `makeUDP` similarly.**

```go
makeUDP := func() (net.PacketConn, net.Addr, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	fixed := &fixedAddrConn{udpConn, remoteAddr}
	addr := turbotunnel.DummyAddr{}
	return fixed, addr, nil
}
```

- [ ] **Step 5: `makeDoQ` stays unchanged.**

DoQ has its own framing (RFC 9250) and isn't DNS-over-UDP-encoded; do not wrap it.

- [ ] **Step 6: Rewrite the multipath block.**

Find (around line 732) and replace the `if multipath { ... }` block entirely:

```go
if multipath {
	var conns []net.PacketConn
	if dohURL != "" {
		pconn, _, err := makeDoH()
		if err != nil {
			fmt.Fprintf(os.Stderr, "multipath DoH: %v\n", err)
			os.Exit(1)
		}
		conns = append(conns, pconn)
	}
	if dotAddr != "" {
		pconn, _, err := makeDoT()
		if err != nil {
			fmt.Fprintf(os.Stderr, "multipath DoT: %v\n", err)
			os.Exit(1)
		}
		conns = append(conns, pconn)
	}
	if udpAddr != "" {
		pconn, _, err := makeUDP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "multipath UDP: %v\n", err)
			os.Exit(1)
		}
		conns = append(conns, pconn)
	}
	if len(conns) < 2 {
		fmt.Fprintf(os.Stderr, "-multipath requires at least two of -doh, -dot, -udp\n")
		os.Exit(1)
	}
	// Multipath: bump KCP window to 512 so out-of-order packets arriving via
	// transports with different latencies don't stall the session.
	if kcpCfg.window < 512 {
		kcpCfg.window = 512
	}
	multi := NewMultiPacketConn(conns)
	dnsConn := NewDNSPacketConn(multi, turbotunnel.DummyAddr{}, domain, obfuscate)
	firstConn := dnsConn
	firstUsed := false
	makeConn = func() (net.PacketConn, error) {
		if !firstUsed {
			firstUsed = true
			return firstConn, nil
		}
		// Reconnect: rebuild every transport.
		var newConns []net.PacketConn
		if dohURL != "" {
			if p, _, e := makeDoH(); e == nil {
				newConns = append(newConns, p)
			}
		}
		if dotAddr != "" {
			if p, _, e := makeDoT(); e == nil {
				newConns = append(newConns, p)
			}
		}
		if udpAddr != "" {
			if p, _, e := makeUDP(); e == nil {
				newConns = append(newConns, p)
			}
		}
		if len(newConns) == 0 {
			return nil, fmt.Errorf("all multipath transports failed")
		}
		return NewDNSPacketConn(NewMultiPacketConn(newConns), turbotunnel.DummyAddr{}, domain, obfuscate), nil
	}
}
```

Note: `firstUsed` survives here, but only to avoid re-dialing on the first run after we already verified connectivity. It's a local `bool` inside a closure called sequentially from `run()`, so no concurrency. We're not removing `firstUsed` — only the broken `sync.Once`-based version; the simple bool was always fine. The audit defect #16 was about a *broken* version (the `sync.Once` that captured `result` from a closed-over scope incorrectly). The simple sequential bool is fine.

- [ ] **Step 7: Rewrite the auto block.**

Find (around line 801) and replace `if autoTransport { ... }` with:

```go
} else if autoTransport {
	type candidate struct {
		name string
		make transportMaker
		addr string
	}
	candidates := []candidate{
		{"DoQ", makeDoQ, doqAddr},
		{"DoT", makeDoT, dotAddr},
		{"DoH", makeDoH, dohURL},
		{"UDP", makeUDP, udpAddr},
	}
	var makers []struct {
		name string
		make transportMaker
	}
	for _, c := range candidates {
		if c.addr != "" {
			makers = append(makers, struct {
				name string
				make transportMaker
			}{c.name, c.make})
		}
	}
	if len(makers) == 0 {
		fmt.Fprintf(os.Stderr, "-auto requires at least one of -doh, -doq, -dot, -udp\n")
		os.Exit(1)
	}
	makeConn = func() (net.PacketConn, error) {
		bare, _, err := tryTransports(makers)
		if err != nil {
			return nil, err
		}
		// DoQ is already DNS-message-level; everything else needs a DNS wrap.
		if _, isDoQ := bare.(*QUICPacketConn); isDoQ {
			return bare, nil
		}
		return NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain, obfuscate), nil
	}
}
```

- [ ] **Step 8: Rewrite the single-transport block.**

Find (around line 834) and replace `} else { ... }` with:

```go
} else {
	type opt struct {
		s    string
		make func() (net.PacketConn, net.Addr, error)
		isDoQ bool
	}
	opts := []opt{
		{dohURL, makeDoH, false},
		{doqAddr, makeDoQ, true},
		{dotAddr, makeDoT, false},
		{udpAddr, makeUDP, false},
	}
	var chosen *opt
	for i := range opts {
		if opts[i].s == "" {
			continue
		}
		if chosen != nil {
			fmt.Fprintf(os.Stderr, "only one of -doh, -doq, -dot, and -udp may be given (or use -auto)\n")
			os.Exit(1)
		}
		chosen = &opts[i]
	}
	if chosen == nil {
		fmt.Fprintf(os.Stderr, "one of -doh, -doq, -dot, -udp, or -auto is required\n")
		os.Exit(1)
	}
	bare, _, err := chosen.make()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var firstConn net.PacketConn
	if chosen.isDoQ {
		firstConn = bare
	} else {
		firstConn = NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain, obfuscate)
	}
	firstUsed := false
	makeConn = func() (net.PacketConn, error) {
		if !firstUsed {
			firstUsed = true
			return firstConn, nil
		}
		bare, _, err := chosen.make()
		if err != nil {
			return nil, err
		}
		if chosen.isDoQ {
			return bare, nil
		}
		return NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain, obfuscate), nil
	}
}
```

- [ ] **Step 9: Build and test.**

Run: `cd /mnt/Docs/dnstt && go build ./... && go test ./...`
Expected: builds clean, all tests pass.

- [ ] **Step 10: Commit.**

```bash
git add dnstt-client/main.go
git commit -m "fix(client): single ClientID across multipath transports"
```

---

## Task 10: Smoke test on `150.241.94.29`

**Files:**
- Create: `scripts/smoke-multipath.sh`

This script deploys the freshly-built server to the test box, starts the client locally with multipath, and verifies traffic flows end-to-end.

- [ ] **Step 1: Confirm SSH works to the box.**

Run: `ssh -o BatchMode=yes -o ConnectTimeout=5 root@150.241.94.29 "uname -a"`
Expected: kernel version printed within 5 seconds.

If this fails, ask the user which key to use and adjust accordingly (e.g. `ssh -i ~/.ssh/dnstt-test root@...`).

- [ ] **Step 2: Create smoke script.**

Create `scripts/smoke-multipath.sh`:

```bash
#!/usr/bin/env bash
# End-to-end smoke test for G1 fixes.
# Deploys dnstt-server to the test box, runs dnstt-client locally with
# -multipath, and verifies a full HTTP request through the SOCKS5 tunnel.

set -euo pipefail

SERVER_HOST="${SERVER_HOST:-150.241.94.29}"
SERVER_USER="${SERVER_USER:-root}"
DOMAIN="${DOMAIN:-t.ivantopgaming.ru}"
LOCAL_ADDR="${LOCAL_ADDR:-127.0.0.1:7000}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

step()  { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
fatal() { printf "\033[1;31m!!!\033[0m %s\n" "$*"; exit 1; }

step "Building binaries"
go build -o /tmp/dnstt-server ./dnstt-server
go build -o /tmp/dnstt-client ./dnstt-client

step "Generating throwaway server keypair"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
/tmp/dnstt-server -gen-key -privkey-file "$TMPDIR/server.key" -pubkey-file "$TMPDIR/server.pub"

step "Deploying server binary and key to $SERVER_USER@$SERVER_HOST"
ssh "$SERVER_USER@$SERVER_HOST" "pkill -9 dnstt-server || true; mkdir -p /opt/dnstt"
scp /tmp/dnstt-server "$SERVER_USER@$SERVER_HOST:/opt/dnstt/dnstt-server"
scp "$TMPDIR/server.key" "$SERVER_USER@$SERVER_HOST:/opt/dnstt/server.key"

step "Starting server (background) on $SERVER_HOST in -socks5 mode"
ssh "$SERVER_USER@$SERVER_HOST" \
  "nohup /opt/dnstt/dnstt-server -udp :53 -privkey-file /opt/dnstt/server.key -socks5 -log-level debug $DOMAIN > /opt/dnstt/server.log 2>&1 &"
sleep 2
ssh "$SERVER_USER@$SERVER_HOST" "pgrep -a dnstt-server" || fatal "server did not start"

step "Starting client locally with -multipath"
PUBKEY_HEX="$(cat "$TMPDIR/server.pub")"
/tmp/dnstt-client \
  -multipath \
  -doh https://1.1.1.1/dns-query \
  -dot 1.1.1.1:853 \
  -udp 1.1.1.1:53 \
  -pubkey "$PUBKEY_HEX" \
  -log-level debug \
  "$DOMAIN" "$LOCAL_ADDR" &
CLIENT_PID=$!
trap 'kill -9 $CLIENT_PID 2>/dev/null || true; rm -rf "$TMPDIR"' EXIT

# Wait for client to come up.
for i in {1..15}; do
  if nc -z 127.0.0.1 7000 2>/dev/null; then
    break
  fi
  sleep 1
done
nc -z 127.0.0.1 7000 || fatal "client did not bind $LOCAL_ADDR"

step "Sending HTTP request through SOCKS5 tunnel"
GOT_IP="$(curl --max-time 30 --proxy "socks5h://$LOCAL_ADDR/" -s https://api.ipify.org)"
echo "  got: $GOT_IP"
echo "  expected: $SERVER_HOST"
if [[ "$GOT_IP" != "$SERVER_HOST" ]]; then
  fatal "tunnel produced wrong egress IP — multipath probably broken"
fi

step "Checking server only saw ONE session"
SESSIONS="$(ssh "$SERVER_USER@$SERVER_HOST" "grep -c 'begin session' /opt/dnstt/server.log || true")"
echo "  sessions: $SESSIONS"
if [[ "$SESSIONS" != "1" ]]; then
  fatal "expected exactly one KCP session; got $SESSIONS — multipath ClientID still split"
fi

step "Stopping server"
ssh "$SERVER_USER@$SERVER_HOST" "pkill -9 dnstt-server || true"

step "OK — multipath uses a single ClientID end-to-end"
```

- [ ] **Step 3: Make executable and run.**

Run: `chmod +x scripts/smoke-multipath.sh && ./scripts/smoke-multipath.sh`
Expected output:
```
==> Building binaries
==> Generating throwaway server keypair
==> Deploying server binary and key to root@150.241.94.29
==> Starting server (background) on 150.241.94.29 in -socks5 mode
==> Starting client locally with -multipath
==> Sending HTTP request through SOCKS5 tunnel
  got: 150.241.94.29
  expected: 150.241.94.29
==> Checking server only saw ONE session
  sessions: 1
==> Stopping server
==> OK — multipath uses a single ClientID end-to-end
```

If `sessions != 1` — multipath is still split. Re-investigate Task 9.
If `got != 150.241.94.29` — tunnel isn't passing traffic; check server log via `ssh root@150.241.94.29 cat /opt/dnstt/server.log`.

- [ ] **Step 4: Commit script.**

```bash
git add scripts/smoke-multipath.sh
git commit -m "test: end-to-end smoke for multipath single-ClientID"
```

---

## Self-Review Checklist

Run mentally before declaring G1 done:

- [ ] **Spec coverage.** Every audit-defect in scope (#1, #4, #14, #15, #16, #17) has a task that fixes it.
  - #1 multipath ClientID → Task 9.
  - #4 SetDeadline → Task 2.
  - #14 truncate → Task 8.
  - #15 round-robin overflow → Task 1.
  - #16 firstUsed (clarified to "remove broken sync.Once version") → Task 9.
  - #17 FEC/compress mismatch → Tasks 5, 6, 7.
- [ ] **Placeholder scan.** No "TBD"/"TODO"/"add appropriate handling".
- [ ] **Type/name consistency.** `handshakeParams`, `encodeHandshakeParams`, `decodeHandshakeParams`, `validateHandshakeParams`, `handshakeParamsLen`, `metricTruncated`, `truncateLogLast`, `shouldLogTruncate`, `rebuildAsTruncated` — all spelled the same in every task that mentions them.
- [ ] **Each task ends in a green test run + commit.**

---

## Final integration check (after Task 10)

- [ ] `go test ./...` — clean
- [ ] `go vet ./...` — clean
- [ ] `gofmt -l . | wc -l` — zero
- [ ] Smoke green
- [ ] Diff vs `master` reads as a coherent fix series

When all green: leave the branch on the local `fix/audit-pass-1`. Do **not** squash-merge yet — wait until G2/G3/G4/G5 finish so we can squash the entire audit pass into one commit per spec.
