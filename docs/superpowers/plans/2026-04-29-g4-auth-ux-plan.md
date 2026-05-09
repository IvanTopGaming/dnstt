# G4 Auth-UX & Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move client auth-token validation into the Noise handshake payload so server/client mismatch fails atomically with a clear error (closes audit defect #5), plus minor README cleanups (rotate-id warning #7, "Глейу"→"Glue" typo #19).

**Architecture:** Extend the 4-byte handshake payload introduced in G1 to optionally carry a 32-byte auth token gated by a flag bit in byte 2. Server decodes payload during Noise handshake, validates token against `authDB` inline, and rejects with a clear error message before any smux processing — eliminating the current race where the server reads 32 bytes after Noise from what is actually smux's first frame. Client sends token in the Noise payload, no longer does an after-Noise write/read dance.

**Tech Stack:** Go 1.24 stdlib (`crypto/sha256`, `encoding/binary`).

**Branch:** `fix/audit-pass-1`. Stack on top of G1+G2+G3.

**Testing:** Local `go test ./...` after every step. New e2e auth tests added in Task 4.

**Wire/CLI compat:** breaking changes per user direction. Old clients that send auth token after Noise will fail to handshake against new servers, and vice versa.

---

## Background

Current after-Noise auth dance (audit defect #5):

**Server (`dnstt-server/main.go:343-356`):**
```go
if authDB != nil {
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    var token [32]byte
    if _, err := io.ReadFull(rw, token[:]); err != nil { return ... }
    conn.SetReadDeadline(time.Time{})
    if !authDB.Verify(token) {
        // write DENIED + random padding
        return error
    }
    // write OK + random padding
}
```

**Client (`dnstt-client/main.go:287-301`):**
```go
if authToken != nil {
    if _, err := rw.Write(authToken); err != nil { return ... }
    resp := make([]byte, 8)
    if _, err := io.ReadFull(rw, resp); err != nil { return ... }
    if string(resp[:2]) != "OK" { return "auth denied by server" }
}
```

Problems:
- If server has `-auth-keys` but client has no `-auth-token`, server reads 32 bytes from smux's first frame as token → almost certainly fails verify → DENIED. Client meanwhile expects smux to start; it never sees the DENIED response cleanly.
- The 5-second deadline + io.ReadFull is a goroutine-exhaustion vector if a malicious client opens many sessions and stays silent.
- The OK/DENIED bytes leak that auth is in play (8 bytes after Noise that don't match smux frame layout).

After this group: auth is part of Noise handshake. Server validates inline. No after-Noise read/write. Server rejection happens before any smux interaction. The DoS vector via silent-after-Noise clients is gone (handshake itself has Noise's own framing+timing).

---

## File Structure

### Modified

- `dnstt-server/handshake.go` — extend codec to handle optional 32-byte auth token via flag bit. Decode returns `(params, authToken []byte, err)`.
- `dnstt-server/handshake_test.go` — extend tests for new wire format and auth-token round trip.
- `dnstt-client/handshake.go` — same codec extension on client side (encode only).
- `dnstt-server/main.go` — `acceptStreams` consumes token from Noise payload, validates inline. Old after-Noise auth block deleted.
- `dnstt-client/main.go` — `sessionLoop` builds payload with optional token. Old after-Noise auth block deleted.
- `dnstt-server/e2e_test.go` — new tests `TestSessionE2E_AuthSuccess`, `TestSessionE2E_AuthWrongToken`, `TestSessionE2E_AuthMissingToken`.
- `README.md` — rotate-id behavior warning, "Глейу-запись"→"Glue-запись" typo fix.

### NOT modified

- `dnstt-server/userdb.go` — `authDatabase` interface unchanged.
- `dnstt-server/handshake.go` `validateHandshakeParams` — still compares only FEC/compress; auth is a separate `authDB.Verify` call.

---

## Conventions

- Each task is one atomic commit. Squash to master happens at end of full audit pass.
- TDD: failing test → minimal code → passing test → commit.
- `gofmt -w` on touched files before commit.
- `go test ./...` after each task.

---

## Task 1: Extend handshake codec for optional auth token

**Files:**
- Modify: `dnstt-server/handshake.go` — extend `decodeHandshakeParams` to also return optional 32-byte auth token; extend `encodeHandshakeParams` to accept optional token.
- Modify: `dnstt-server/handshake_test.go` — update tests for new signatures + new round-trip cases.
- Modify: `dnstt-client/handshake.go` — same on client side (encode only — client doesn't decode incoming payloads from itself).

### Step 1: Read current codec

```bash
cd /mnt/Docs/dnstt
cat dnstt-server/handshake.go
cat dnstt-client/handshake.go
```

Confirm:
- `handshakeParams` struct: `FECData uint8, FECParity uint8, Compress bool`
- `handshakeParamsLen = 4`
- Encode: 4 bytes layout `[fec_data][fec_parity][flags(bit0=compress)][reserved=0]`
- Decode: server-side returns `(handshakeParams, error)`, validates `len(b) == 4` and reserved-bits/byte are zero
- `newHandshakeParamsFromInts(fec_data, fec_parity int, compress bool) (handshakeParams, error)` validates `[0,255]` range

### Step 2: Write failing tests for the codec extension

Replace the entirety of `/mnt/Docs/dnstt/dnstt-server/handshake_test.go` with the new content below:

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeHandshakeParams_NoToken(t *testing.T) {
	got := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: true}, nil)
	want := []byte{4, 2, 0x01, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestEncodeHandshakeParams_WithToken(t *testing.T) {
	var token [32]byte
	for i := range token {
		token[i] = byte(0xA0 + i)
	}
	got := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: true}, token[:])

	want := make([]byte, 0, handshakeParamsLen+32)
	// Flags byte 2 should have bit 0 (compress) AND bit 1 (has_auth_token) set.
	want = append(want, 4, 2, 0x03, 0)
	want = append(want, token[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestDecodeHandshakeParams(t *testing.T) {
	var goodToken [32]byte
	for i := range goodToken {
		goodToken[i] = byte(0xA0 + i)
	}
	withTokenInput := append([]byte{4, 2, 0x03, 0}, goodToken[:]...)

	for _, tc := range []struct {
		name        string
		input       []byte
		wantParams  handshakeParams
		wantToken   []byte // nil means "no token expected"
		wantErrFrag string // empty = success
	}{
		{"happy no token", []byte{4, 2, 0x01, 0}, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, nil, ""},
		{"zero", []byte{0, 0, 0, 0}, handshakeParams{}, nil, ""},
		{"happy with token", withTokenInput, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, goodToken[:], ""},
		{"too short", []byte{1, 2, 3}, handshakeParams{}, nil, "expected 4 bytes"},
		{"too long no token", []byte{1, 2, 0x01, 0, 99}, handshakeParams{}, nil, "expected 4 bytes"},
		{"empty", []byte{}, handshakeParams{}, nil, "expected 4 bytes"},
		{"reserved flag bits", []byte{0, 0, 0x04, 0}, handshakeParams{}, nil, "reserved bits"},
		{"reserved flag bits high", []byte{0, 0, 0xFC, 0}, handshakeParams{}, nil, "reserved bits"},
		{"reserved byte set", []byte{0, 0, 0, 0xAA}, handshakeParams{}, nil, "reserved byte"},
		{"token bit set but missing token bytes", []byte{0, 0, 0x02, 0}, handshakeParams{}, nil, "auth token bit set but"},
		{"token bit set with wrong size", append([]byte{0, 0, 0x02, 0}, make([]byte, 31)...), handshakeParams{}, nil, "auth token bit set but"},
		{"trailing bytes without token bit", append([]byte{0, 0, 0, 0}, make([]byte, 32)...), handshakeParams{}, nil, "expected 4 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotParams, gotToken, err := decodeHandshakeParams(tc.input)
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got params=%+v token=%x", tc.wantErrFrag, gotParams, gotToken)
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrFrag, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotParams != tc.wantParams {
				t.Fatalf("params: got %+v, want %+v", gotParams, tc.wantParams)
			}
			if !bytes.Equal(gotToken, tc.wantToken) {
				t.Fatalf("token: got %x, want %x", gotToken, tc.wantToken)
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

func TestNewHandshakeParamsFromInts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fecData     int
		fecParity   int
		compress    bool
		want        handshakeParams
		wantErrFrag string
	}{
		{"happy", 4, 2, true, handshakeParams{FECData: 4, FECParity: 2, Compress: true}, ""},
		{"zero", 0, 0, false, handshakeParams{}, ""},
		{"max", 255, 255, false, handshakeParams{FECData: 255, FECParity: 255}, ""},
		{"fec-data negative", -1, 0, false, handshakeParams{}, "fec-data must be in [0,255]"},
		{"fec-data too big", 256, 0, false, handshakeParams{}, "fec-data must be in [0,255]"},
		{"fec-parity negative", 0, -1, false, handshakeParams{}, "fec-parity must be in [0,255]"},
		{"fec-parity too big", 0, 256, false, handshakeParams{}, "fec-parity must be in [0,255]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newHandshakeParamsFromInts(tc.fecData, tc.fecParity, tc.compress)
			if tc.wantErrFrag != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %+v", tc.wantErrFrag, got)
				}
				if !strings.Contains(err.Error(), tc.wantErrFrag) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrFrag, err.Error())
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
```

### Step 3: Run tests, expect compile errors

```bash
cd /mnt/Docs/dnstt
go test ./dnstt-server/ -run "TestEncodeHandshakeParams|TestDecodeHandshakeParams" -v
```
Expected: compile error — `encodeHandshakeParams` 1-arg signature mismatch, `decodeHandshakeParams` 2-return-value mismatch.

### Step 4: Update server-side codec

In `/mnt/Docs/dnstt/dnstt-server/handshake.go`, replace the whole file with:

```go
package main

import (
	"errors"
	"fmt"
)

// handshakeParamsLen is the wire size of the fixed-length prefix of a
// serialized handshake payload. The full payload is either
// handshakeParamsLen bytes (no auth token) or handshakeParamsLen + 32
// bytes (auth token present).
const handshakeParamsLen = 4

// authTokenLen is the wire size of an auth token.
const authTokenLen = 32

// flag bit positions inside byte 2 of the wire format.
const (
	flagCompress     = 0x01
	flagHasAuthToken = 0x02
	// flagsKnownMask covers every defined flag bit. Bits outside this
	// mask must be zero on the wire — decode rejects unknown bits so
	// future-version clients fail closed against current-version servers.
	flagsKnownMask = flagCompress | flagHasAuthToken
)

// handshakeParams are the per-session parameters the client sends inside the
// first Noise handshake message so the server can verify they match its own
// configuration. A mismatch makes the tunnel silently malfunction, so this
// negotiation lets us fail closed at handshake time with a clear message.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p plus an optional 32-byte auth token to
// the wire format. Layout:
//
//	[0]   uint8  fec_data
//	[1]   uint8  fec_parity
//	[2]   uint8  flags (bit 0: compress, bit 1: has_auth_token)
//	[3]   uint8  reserved (=0)
//	[4..] [32]   auth_token (only present if has_auth_token bit is set)
//
// authToken may be nil (no token) or exactly authTokenLen bytes.
func encodeHandshakeParams(p handshakeParams, authToken []byte) []byte {
	size := handshakeParamsLen
	if authToken != nil {
		size += authTokenLen
	}
	buf := make([]byte, 0, size)

	flags := byte(0)
	if p.Compress {
		flags |= flagCompress
	}
	if authToken != nil {
		flags |= flagHasAuthToken
	}
	buf = append(buf, p.FECData, p.FECParity, flags, 0 /* reserved */)
	if authToken != nil {
		buf = append(buf, authToken...)
	}
	return buf
}

// decodeHandshakeParams parses the wire format. Returns the params plus the
// optional auth token (nil if has_auth_token bit was clear). Returns an
// error if the input length, reserved bits, or auth-token-bit/length pairing
// is invalid.
func decodeHandshakeParams(b []byte) (handshakeParams, []byte, error) {
	if len(b) < handshakeParamsLen {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: expected %d bytes, got %d",
			handshakeParamsLen, len(b))
	}
	flags := b[2]
	if flags&^flagsKnownMask != 0 {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: reserved bits set in flags byte (got %#02x)", flags)
	}
	if b[3] != 0 {
		return handshakeParams{}, nil, fmt.Errorf("handshake params: reserved byte must be 0 (got %#02x)", b[3])
	}

	hasToken := flags&flagHasAuthToken != 0
	var expectedLen int
	if hasToken {
		expectedLen = handshakeParamsLen + authTokenLen
	} else {
		expectedLen = handshakeParamsLen
	}
	if len(b) != expectedLen {
		if hasToken {
			return handshakeParams{}, nil, fmt.Errorf("handshake params: auth token bit set but payload is %d bytes (expected %d)", len(b), expectedLen)
		}
		return handshakeParams{}, nil, fmt.Errorf("handshake params: expected %d bytes, got %d", expectedLen, len(b))
	}

	params := handshakeParams{
		FECData:   b[0],
		FECParity: b[1],
		Compress:  flags&flagCompress != 0,
	}
	var token []byte
	if hasToken {
		token = make([]byte, authTokenLen)
		copy(token, b[handshakeParamsLen:])
	}
	return params, token, nil
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

// newHandshakeParamsFromInts builds a handshakeParams from CLI-provided
// ints, enforcing the [0, 255] uint8 range so silent truncation cannot
// happen. Returns an error suitable for printing directly to the user.
func newHandshakeParamsFromInts(fecData, fecParity int, compress bool) (handshakeParams, error) {
	if fecData < 0 || fecData > 255 {
		return handshakeParams{}, fmt.Errorf("fec-data must be in [0,255], got %d", fecData)
	}
	if fecParity < 0 || fecParity > 255 {
		return handshakeParams{}, fmt.Errorf("fec-parity must be in [0,255], got %d", fecParity)
	}
	return handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, nil
}
```

### Step 5: Update client-side codec

In `/mnt/Docs/dnstt/dnstt-client/handshake.go`, replace the whole file with:

```go
package main

import "fmt"

// handshakeParamsLen is the wire size of the fixed-length prefix of a
// serialized handshake payload.
const handshakeParamsLen = 4

// authTokenLen is the wire size of an auth token.
const authTokenLen = 32

// flag bit positions inside byte 2 of the wire format.
const (
	flagCompress     = 0x01
	flagHasAuthToken = 0x02
)

// handshakeParams mirror the server-side type. The duplication is
// intentional — the two binaries are separate `package main` units.
type handshakeParams struct {
	FECData   uint8
	FECParity uint8
	Compress  bool
}

// encodeHandshakeParams serializes p plus an optional 32-byte auth token
// to the wire format. Layout matches the server-side decoder:
//
//	[0]   uint8  fec_data
//	[1]   uint8  fec_parity
//	[2]   uint8  flags (bit 0: compress, bit 1: has_auth_token)
//	[3]   uint8  reserved (=0)
//	[4..] [32]   auth_token (only present if has_auth_token bit is set)
//
// authToken may be nil (no token) or exactly authTokenLen bytes.
func encodeHandshakeParams(p handshakeParams, authToken []byte) []byte {
	size := handshakeParamsLen
	if authToken != nil {
		size += authTokenLen
	}
	buf := make([]byte, 0, size)

	flags := byte(0)
	if p.Compress {
		flags |= flagCompress
	}
	if authToken != nil {
		flags |= flagHasAuthToken
	}
	buf = append(buf, p.FECData, p.FECParity, flags, 0 /* reserved */)
	if authToken != nil {
		buf = append(buf, authToken...)
	}
	return buf
}

// newHandshakeParamsFromInts builds a handshakeParams from CLI-provided
// ints, enforcing the [0, 255] uint8 range so silent truncation cannot
// happen. Returns an error suitable for printing directly to the user.
func newHandshakeParamsFromInts(fecData, fecParity int, compress bool) (handshakeParams, error) {
	if fecData < 0 || fecData > 255 {
		return handshakeParams{}, fmt.Errorf("fec-data must be in [0,255], got %d", fecData)
	}
	if fecParity < 0 || fecParity > 255 {
		return handshakeParams{}, fmt.Errorf("fec-parity must be in [0,255], got %d", fecParity)
	}
	return handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, nil
}
```

### Step 6: Update existing callsites that call encode/decode with the old signature

Find every callsite of `encodeHandshakeParams` and `decodeHandshakeParams` across the codebase:

```bash
grep -rn "encodeHandshakeParams\|decodeHandshakeParams" --include="*.go"
```

Existing callsites (after G3):

- `dnstt-client/main.go` `sessionLoop`: `encodeHandshakeParams(handshakeParams{...})`
  - Update to: `encodeHandshakeParams(handshakeParams{...}, nil)` — auth token plumbing comes in Task 3, this commit just keeps the call compiling.
- `dnstt-server/main.go` `acceptStreams`: `decodeHandshakeParams(clientPayload)` — change variable name from `clientParams, err :=` to `clientParams, _, err :=` (ignore returned token for now; Task 2 wires it).
- `dnstt-server/e2e_test.go` (multiple places): `encodeHandshakeParams(handshakeParams{})` → `encodeHandshakeParams(handshakeParams{}, nil)`.

Apply the minimal-fix changes to keep compilation green. Body logic stays the same.

### Step 7: Build + test

```bash
go build ./...
go test ./...
```

All tests must pass, including the 12 new TestDecodeHandshakeParams subtests.

### Step 8: Commit

```bash
gofmt -w dnstt-server/handshake.go dnstt-server/handshake_test.go dnstt-client/handshake.go dnstt-client/main.go dnstt-server/main.go dnstt-server/e2e_test.go
git add dnstt-server/handshake.go dnstt-server/handshake_test.go dnstt-client/handshake.go dnstt-client/main.go dnstt-server/main.go dnstt-server/e2e_test.go
git commit -m "feat(handshake): codec carries optional auth token via flag bit"
```

---

## Task 2: Server consumes auth token from Noise payload

Server now extracts the auth token from `noise.NewServer`'s second return value, validates against `authDB`, and rejects with a clear log message inside `acceptStreams` — no after-Noise read/write.

**Files:**
- Modify: `dnstt-server/main.go` (`acceptStreams`)

### Step 1: Locate current acceptStreams body

```bash
cd /mnt/Docs/dnstt
grep -n "func acceptStreams\|authDB\|conn.SetReadDeadline\|io.ReadFull(rw, token" dnstt-server/main.go
```

Confirm `acceptStreams` currently:
1. Calls `noise.NewServer(conn, privkey)` to get `(rw, clientPayload, err)`.
2. Calls `decodeHandshakeParams(clientPayload)` to validate FEC/compress.
3. AFTER that, if `authDB != nil`, sets a 5-second read deadline, calls `io.ReadFull(rw, token[:])`, validates `authDB.Verify`, writes OK/DENIED.

### Step 2: Rewrite the auth section

Find the block starting with `// Token auth: read 32-byte token before smux, verify it.` (around line 343) through the closing `}` of the `if authDB != nil { ... }` block.

DELETE the entire block from `// Token auth: read 32-byte token before smux, verify it.` through `rw.Write(resp[:])`.

Then change the `decodeHandshakeParams` call (a few lines above, currently `clientParams, err := decodeHandshakeParams(clientPayload)`) to capture the token:

```go
	// Validate handshake params: client must declare matching FEC/compress.
	clientParams, clientToken, err := decodeHandshakeParams(clientPayload)
	if err != nil {
		return fmt.Errorf("invalid handshake params: %w", err)
	}
	if err := validateHandshakeParams(clientParams, serverParams); err != nil {
		return err
	}

	// Validate auth token if the server has an authDB. The token (or its
	// absence) is part of the Noise payload, so authentication is atomic
	// with the handshake — a missing or wrong token aborts the connection
	// before any smux processing.
	if authDB != nil {
		if clientToken == nil {
			return fmt.Errorf("auth required: client did not send an auth token")
		}
		var token [32]byte
		copy(token[:], clientToken)
		if !authDB.Verify(token) {
			h := sha256.Sum256(token[:])
			return fmt.Errorf("unauthorized client (sha256-prefix=%x)", h[:8])
		}
	} else if clientToken != nil {
		// Server has no authDB but client sent a token. Don't fail the
		// session — the token is just ignored — but log it once so an
		// operator can notice misconfiguration.
		log.Printf("session %08x: client sent auth token but server has no -auth-keys", conn.GetConv())
	}
```

The `crypto/sha256` import is already present (added in G2 Task 7). Verify with:

```bash
grep -n '"crypto/sha256"' dnstt-server/main.go
```

If absent, add it.

### Step 3: Build + test

```bash
go build ./...
go test ./...
```

All tests pass. Existing E2E tests don't exercise the auth path, so they should be unaffected. Auth-specific E2E tests come in Task 4.

### Step 4: Commit

```bash
gofmt -w dnstt-server/main.go
git add dnstt-server/main.go
git commit -m "feat(server): validate auth token inside Noise handshake"
```

---

## Task 3: Client sends auth token in Noise payload

Client builds the Noise payload with optional token, no longer does an after-Noise write/read dance.

**Files:**
- Modify: `dnstt-client/main.go` (`sessionLoop`)

### Step 1: Locate current sessionLoop auth block

```bash
cd /mnt/Docs/dnstt
grep -n "if authToken != nil\|sending auth token\|reading auth response" dnstt-client/main.go
```

Confirm `sessionLoop` currently:
1. Calls `noise.NewClient(conn, pubkey, encodeHandshakeParams(...))` to handshake.
2. AFTER that, if `authToken != nil`, writes 32 bytes, reads 8 bytes, checks for "OK".

### Step 2: Rewrite the auth section

Find the block:

```go
	clientParams := encodeHandshakeParams(handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, nil)
	rw, err := noise.NewClient(conn, pubkey, clientParams)
	if err != nil {
		return err
	}

	// Token auth: send 32-byte token and wait for server acknowledgement.
	if authToken != nil {
		if _, err := rw.Write(authToken); err != nil {
			return fmt.Errorf("sending auth token: %v", err)
		}
		resp := make([]byte, 8)
		if _, err := io.ReadFull(rw, resp); err != nil {
			return fmt.Errorf("reading auth response: %v", err)
		}
		if string(resp[:2]) != "OK" {
			return fmt.Errorf("auth denied by server")
		}
	}
```

(After Task 1, the `encodeHandshakeParams(...)` call has `nil` as second arg.)

Replace with:

```go
	clientPayload := encodeHandshakeParams(handshakeParams{
		FECData:   uint8(fecData),
		FECParity: uint8(fecParity),
		Compress:  compress,
	}, authToken)
	rw, err := noise.NewClient(conn, pubkey, clientPayload)
	if err != nil {
		return err
	}
```

(Auth token now travels inside the handshake payload; no separate write/read dance.)

### Step 3: Drop unused `io` import if it's no longer referenced

```bash
grep -n "io\." dnstt-client/main.go | head -5
```

If `io.` no longer appears in main.go, remove the `"io"` import. Most likely it's still used elsewhere — check before removing.

### Step 4: Build + test

```bash
go build ./...
go test ./...
```

All clean.

### Step 5: Commit

```bash
gofmt -w dnstt-client/main.go
git add dnstt-client/main.go
git commit -m "feat(client): send auth token in Noise handshake payload"
```

---

## Task 4: E2E tests for auth (success / wrong / missing)

**Files:**
- Modify: `dnstt-server/e2e_test.go` — add three tests.

### Step 1: Append tests

In `/mnt/Docs/dnstt/dnstt-server/e2e_test.go`, append after the existing tests:

```go
// makeAuthDB builds an in-memory authDatabase with a single token for tests.
func makeAuthDB(t *testing.T, token [32]byte) *authDatabase {
	t.Helper()
	return newAuthDatabase([][32]byte{token})
}

// runAuthHandshake drives a server-side acceptStreams against a fake
// session and returns the error it produced (or nil on success). The
// client-side handshake is replicated inline so the test can vary the
// payload independently of dnstt-client's internal call.
func runAuthHandshake(t *testing.T, authDB *authDatabase, clientToken []byte) error {
	t.Helper()
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

	serverParams := handshakeParams{}
	sessErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptKCP()
		if err != nil {
			sessErrCh <- err
			return
		}
		defer conn.Close()
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 50, 2, 1)
		conn.SetWindowSize(128, 128)
		conn.SetMtu(mtu)
		sessErrCh <- acceptStreams(conn, privkey, "echo-unused", authDB, false, serverParams, false)
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

	clientPayload := encodeHandshakeParams(handshakeParams{}, clientToken)
	rw, clientErr := noise.NewClient(kcpConn, pubkey, clientPayload)
	if rw != nil {
		// Drain server-side close to release buffers.
		kcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = rw.Read(make([]byte, 1))
	}
	_ = clientErr

	select {
	case err := <-sessErrCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return within 5s")
		return nil
	}
}

// TestSessionE2E_AuthSuccess verifies that a client with the right token
// passes the handshake (acceptStreams returns nil or any non-auth error).
func TestSessionE2E_AuthSuccess(t *testing.T) {
	var token [32]byte
	for i := range token {
		token[i] = 0xCD
	}
	authDB := makeAuthDB(t, token)

	err := runAuthHandshake(t, authDB, token[:])
	// Past-handshake the test client doesn't open smux streams, so
	// acceptStreams will return an EOF or smux error — not an auth error.
	if err != nil && strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("got auth error with valid token: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "auth required") {
		t.Fatalf("got auth-required error with valid token: %v", err)
	}
}

// TestSessionE2E_AuthWrongToken verifies that a client with a token not in
// authDB is rejected with an "unauthorized client" error.
func TestSessionE2E_AuthWrongToken(t *testing.T) {
	var serverToken [32]byte
	for i := range serverToken {
		serverToken[i] = 0xCD
	}
	authDB := makeAuthDB(t, serverToken)

	var wrongToken [32]byte
	for i := range wrongToken {
		wrongToken[i] = 0xEF
	}

	err := runAuthHandshake(t, authDB, wrongToken[:])
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
	if !strings.Contains(err.Error(), "unauthorized client") {
		t.Fatalf("expected 'unauthorized client', got %v", err)
	}
}

// TestSessionE2E_AuthMissingToken verifies that a client that does not
// send a token is rejected with an "auth required" error when the server
// has an authDB.
func TestSessionE2E_AuthMissingToken(t *testing.T) {
	var token [32]byte
	for i := range token {
		token[i] = 0xCD
	}
	authDB := makeAuthDB(t, token)

	err := runAuthHandshake(t, authDB, nil)
	if err == nil {
		t.Fatal("expected auth-required error, got nil")
	}
	if !strings.Contains(err.Error(), "auth required") {
		t.Fatalf("expected 'auth required', got %v", err)
	}
}
```

The file already imports `bytes`, `context`, `io`, `net`, `testing`, `time`, plus `kcp`, `smux`, `noise`, `turbotunnel`, `dns`, `strings`. Verify `strings` is in the import list (added in G2 task 6); if missing, add.

### Step 2: Build + test

```bash
go build ./...
go test ./dnstt-server/ -run "TestSessionE2E_Auth" -v
```

Three new tests must pass.

### Step 3: Full suite

```bash
go test ./...
```

Clean.

### Step 4: Commit

```bash
gofmt -w dnstt-server/e2e_test.go
git add dnstt-server/e2e_test.go
git commit -m "test(server/auth): cover happy path, wrong token, missing token"
```

---

## Task 5: README cleanup (rotate-id warning + Glue typo)

**Files:**
- Modify: `README.md`

### Step 1: Locate the rotate-id flag description

```bash
cd /mnt/Docs/dnstt
grep -n "rotate-id" README.md
```

Find the row in the client flag table that documents `-rotate-id`.

### Step 2: Add rotate-id behavior warning

Add a paragraph immediately after the client flag table (or in the existing "Шифрование и аутентификация" section if that's where ClientID rotation is documented). The exact insertion:

```bash
grep -n "^### \|^## " README.md | head -30
```

Find the existing "Шифрование и аутентификация" section. After its last subsection but before the next `## ` heading, add:

```markdown
### ClientID rotation и долгие потоки

`-rotate-id N` пересоздаёт KCP-сессию каждые N минут (новый ClientID, новый smux). Это затрудняет долгосрочную корреляцию для пассивного наблюдателя, но **обрывает** все TCP-потоки внутри туннеля в момент ротации. Для долгих сессий (SSH, БД-подключения, длинные HTTP-стримы) это не подходит — приложение увидит разрыв и должно будет переподключаться.

Используйте `-rotate-id` только для короткоживущего трафика (web-серфинг, API-запросы), либо не используйте вовсе и положитесь на остальные средства маскировки (uTLS, padding, multipath).
```

### Step 3: Fix the "Глейу-запись" typo

In `README.md` find:

```
; Глейу-запись для NS-сервера
```

Replace with:

```
; Glue-запись для NS-сервера
```

(Single-line correction.)

### Step 4: Verify no other typos

```bash
grep -n "Глей" README.md
```

Should return zero matches.

### Step 5: Commit

```bash
git add README.md
git commit -m "docs: warn about -rotate-id breaking long streams; fix Glue typo"
```

---

## Self-Review Checklist

Run mentally before declaring G4 done:

- [ ] **Spec coverage:**
  - #5 auth handshake UX → Tasks 1, 2, 3, 4 (codec, server, client, e2e tests).
  - #7 rotate-id docs → Task 5.
  - #19 README typo → Task 5.
- [ ] **Placeholder scan:** none.
- [ ] **Type/name consistency:** `handshakeParams` (3 fields), `encodeHandshakeParams(p, authToken)`, `decodeHandshakeParams(b) → (params, token, err)`, `validateHandshakeParams(client, server)`, `newHandshakeParamsFromInts(fec_data, fec_parity, compress)`, `flagCompress`, `flagHasAuthToken`, `flagsKnownMask`, `authTokenLen` — uniform across tasks.
- [ ] Each task ends in green test run + commit.

---

## Final Integration Check (after Task 5)

- [ ] `go test ./...` — clean
- [ ] `go vet ./...` — clean
- [ ] Diff vs `master` (G1+G2+G3+G4) reads as a coherent fix series
- [ ] Optional smoke: re-run `scripts/smoke-multipath.sh` to confirm tunnel still works end-to-end with the new handshake-payload-with-token format

When all green: G4 complete. Branch `fix/audit-pass-1` continues to accumulate. Squash-merge to master happens at the end of the whole audit pass (after G5 if scoped, or now if user prefers).
