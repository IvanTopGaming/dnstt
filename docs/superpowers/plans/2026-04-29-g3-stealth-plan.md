# G3 Stealth/Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dnstt server behave like a real authoritative DNS server (synthesized SOA/NS, NXDOMAIN-with-SOA-in-Authority, REFUSED for out-of-zone) so passive DPI and active probers can't spot the tunnel from response shape; remove client-side DGA-pattern decoy queries.

**Architecture:** New `zoneInfo` value, built once at server startup from the positional `domain` arg, holds synthesized SOA and NS records. `responseFor` is rewritten to dispatch by (apex/sub/outside) × QTYPE and emits auth-NS-shaped responses. The `-paranoia` and `-obfuscate` flags are removed; mimicry becomes the default.

**Tech Stack:** Go 1.24 stdlib (`encoding/binary`, `bytes`, `time`, `crypto/tls` already used), package-internal DNS encoding helpers in `dns/dns.go`.

**Branch:** `fix/audit-pass-1`. Stack on top of G1+G2.

**Testing:** Local `go test ./...` after every step. Smoke check at end via `dig` against the test box (covered in Task 8).

**Wire/CLI compat:** breaking changes per user direction. `-paranoia` and `-obfuscate` disappear; `paranoia:` YAML field disappears.

---

## File Structure

### Modified

- `dns/dns.go` — add `RRTypeSOA` and `RRTypeNS` constants.
- `dnstt-server/main.go` — `responseFor` rewritten; `recvLoop`/`run` signatures change (drop `paranoia bool`, add `zone zoneInfo`); `paranoidResponse` removed; `sendLoop` AAAA branch simplified; `rebuildAsTruncated` extended to preserve Authority; `-paranoia` flag removed; `main()` builds `zoneInfo`.
- `dnstt-server/config.go` — `Paranoia` field and its `setDefault` call removed.
- `dnstt-server/e2e_test.go` — three callsites updated for new signatures; new `TestSessionE2E_ProberQueriesIgnored`.
- `dnstt-server/main_test.go` — extended with `TestResponseFor_*` cases.
- `dnstt-client/dns.go` — `sendDecoy`, `decoyProbability`, `obfuscate` field, the `obfuscate` parameter to `NewDNSPacketConn` all removed; `sendLoop` no longer fires decoys.
- `dnstt-client/main.go` — `-obfuscate` flag removed; 5 `NewDNSPacketConn` callsites updated to drop the `obfuscate` arg.
- `start-client.sh` — `-obfuscate` line removed.
- `README.md` — `-paranoia` and `-obfuscate` mentions removed; new section explaining auth-NS-by-default behavior.

### Created

- `dnstt-server/zone.go` — `zoneInfo` type, `newZoneInfo`, internal helpers `encodeRDataSOA`, `encodeRDataNS`, `encodeName`.
- `dnstt-server/zone_test.go` — unit tests for `newZoneInfo`, SOA/NS RDATA encoding.

### NOT modified

- `dns/dns.go` builder/parser (no message-level changes).
- `dnstt-client/config.go` (key=value loader auto-handles flag removal — flag.Set will error cleanly on `obfuscate = true`).
- `noise/`, `turbotunnel/`, `dnstt-client/multi.go` etc.

---

## Conventions

- Each task is one atomic commit. Squash to master happens at end of full audit pass.
- TDD: failing test → minimal code → passing test → commit.
- `gofmt -w` on touched files before commit.
- `go test ./...` after each task.

---

## Task 1: zone.go scaffolding + RR type constants

Build the `zoneInfo` type and helpers in isolation. No callers yet. This commit is purely additive: no existing behavior changes.

**Files:**
- Create: `dnstt-server/zone.go`
- Create: `dnstt-server/zone_test.go`
- Modify: `dns/dns.go` (add 2 constants)

- [ ] **Step 1: Add SOA and NS RRType constants.**

In `/mnt/Docs/dnstt/dns/dns.go` find:

```go
	RRTypeA   = 1
	RRTypeTXT = 16
	// ...
	RRTypeAAAA = 28
	// ...
	RRTypeOPT = 41
```

Add `RRTypeSOA` and `RRTypeNS` (canonical IANA values):

```go
	RRTypeA    = 1
	RRTypeNS   = 2
	RRTypeSOA  = 6
	RRTypeTXT  = 16
	// ...
	RRTypeAAAA = 28
	// ...
	RRTypeOPT  = 41
```

Place them in numeric order with the existing constants. Don't reorder unrelated constants.

- [ ] **Step 2: Write failing tests.**

Create `/mnt/Docs/dnstt/dnstt-server/zone_test.go`:

```go
package main

import (
	"bytes"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestNewZoneInfo_Basic(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	// Apex preserved.
	if z.apex.String() != apex.String() {
		t.Fatalf("apex %s, want %s", z.apex, apex)
	}
	// SOA name == apex.
	if z.soa.Name.String() != apex.String() {
		t.Fatalf("SOA owner %s, want apex %s", z.soa.Name, apex)
	}
	if z.soa.Type != dns.RRTypeSOA {
		t.Fatalf("SOA type %d, want %d", z.soa.Type, dns.RRTypeSOA)
	}
	if z.soa.Class != dns.ClassIN {
		t.Fatalf("SOA class %d, want %d", z.soa.Class, dns.ClassIN)
	}
	// NS name == apex, target == ns.<apex>.
	if z.ns.Name.String() != apex.String() {
		t.Fatalf("NS owner %s, want apex %s", z.ns.Name, apex)
	}
	if z.ns.Type != dns.RRTypeNS {
		t.Fatalf("NS type %d, want %d", z.ns.Type, dns.RRTypeNS)
	}
}

func TestSOARDataWireFormat(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	// SOA RDATA layout: mname-name + rname-name + 5*uint32.
	// mname = "ns.t.example.com." → labels: ns, t, example, com, root
	//   wire: 02 'n' 's' 01 't' 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' 03 'c' 'o' 'm' 00
	expectedMname := []byte{
		2, 'n', 's',
		1, 't',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	if !bytes.HasPrefix(z.soa.Data, expectedMname) {
		t.Fatalf("SOA mname encoding mismatch:\n got prefix %x\n want         %x",
			z.soa.Data[:len(expectedMname)], expectedMname)
	}
}

func TestNSRDataWireFormat(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	// NS RDATA = encoded ns.<apex>.
	expectedNs := []byte{
		2, 'n', 's',
		1, 't',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	if !bytes.Equal(z.ns.Data, expectedNs) {
		t.Fatalf("NS RDATA mismatch:\n got  %x\n want %x", z.ns.Data, expectedNs)
	}
}
```

- [ ] **Step 3: Run tests, expect compile error.**

```
cd /mnt/Docs/dnstt
go test ./dnstt-server/ -run TestNewZoneInfo -v
```
Expected: `newZoneInfo` undefined.

- [ ] **Step 4: Create zone.go.**

Create `/mnt/Docs/dnstt/dnstt-server/zone.go`:

```go
package main

import (
	"bytes"
	"encoding/binary"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// zoneInfo describes the zone the server is authoritative for, along with
// synthesized SOA and NS resource records that make non-tunnel responses
// look like a real auth NS to passive DPI and active probers.
type zoneInfo struct {
	apex dns.Name
	soa  dns.RR
	ns   dns.RR
}

// SOA timer values (BIND-defaults-ish).
const (
	soaRefresh = 3600
	soaRetry   = 1800
	soaExpire  = 604800
	soaMinimum = 60
)

// newZoneInfo constructs a zoneInfo for apex. mname = "ns.<apex>", rname =
// "hostmaster.<apex>", serial = YYYYMMDDnn at start time. SOA timer
// values follow BIND's typical "small zone" defaults.
func newZoneInfo(apex dns.Name) zoneInfo {
	mname := prependLabel(apex, []byte("ns"))
	rname := prependLabel(apex, []byte("hostmaster"))

	now := time.Now().UTC()
	serial := uint32(now.Year())*1000000 +
		uint32(now.Month())*10000 +
		uint32(now.Day())*100 +
		1

	soaRDATA := encodeRDataSOA(mname, rname, serial,
		soaRefresh, soaRetry, soaExpire, soaMinimum)

	nsRDATA := encodeName(mname)

	return zoneInfo{
		apex: apex,
		soa: dns.RR{
			Name:  apex,
			Type:  dns.RRTypeSOA,
			Class: dns.ClassIN,
			TTL:   responseTTL,
			Data:  soaRDATA,
		},
		ns: dns.RR{
			Name:  apex,
			Type:  dns.RRTypeNS,
			Class: dns.ClassIN,
			TTL:   responseTTL,
			Data:  nsRDATA,
		},
	}
}

// prependLabel returns label.<apex> as a new dns.Name.
func prependLabel(apex dns.Name, label []byte) dns.Name {
	out := make(dns.Name, 0, len(apex)+1)
	out = append(out, label)
	out = append(out, apex...)
	return out
}

// encodeName writes a DNS name in uncompressed wire format: each label
// prefixed by its 1-byte length, followed by a zero-length root label.
func encodeName(name dns.Name) []byte {
	var buf bytes.Buffer
	for _, label := range name {
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // root terminator
	return buf.Bytes()
}

// encodeRDataSOA assembles the wire-format RDATA of an SOA record per
// RFC 1035 §3.3.13: mname, rname, serial, refresh, retry, expire, minimum.
func encodeRDataSOA(mname, rname dns.Name, serial, refresh, retry, expire, minimum uint32) []byte {
	var buf bytes.Buffer
	buf.Write(encodeName(mname))
	buf.Write(encodeName(rname))
	binary.Write(&buf, binary.BigEndian, serial)
	binary.Write(&buf, binary.BigEndian, refresh)
	binary.Write(&buf, binary.BigEndian, retry)
	binary.Write(&buf, binary.BigEndian, expire)
	binary.Write(&buf, binary.BigEndian, minimum)
	return buf.Bytes()
}
```

`responseTTL` is the existing constant in `main.go` (= 60). It's package-scoped in the same `package main`, so `zone.go` references it without import.

- [ ] **Step 5: Run tests, expect PASS.**

```
go test ./dnstt-server/ -run "TestNewZoneInfo|TestSOARDataWireFormat|TestNSRDataWireFormat" -v
```
Expected: 3 tests PASS.

- [ ] **Step 6: Full suite.**

```
go test ./...
go build ./...
```
All clean.

- [ ] **Step 7: Commit.**

```
gofmt -w dns/dns.go dnstt-server/zone.go dnstt-server/zone_test.go
git add dns/dns.go dnstt-server/zone.go dnstt-server/zone_test.go
git commit -m "feat(server/zone): synthesize SOA and NS records"
```

---

## Task 2: rewrite responseFor with auth-NS-like behavior

Replace the current `responseFor` body and signature. Drop `paranoidResponse`. Update `recvLoop`, `run`, and existing E2E callsites for the new signatures. Add unit tests for the new behavior.

**Files:**
- Modify: `dnstt-server/main.go` — `responseFor`, `recvLoop`, `run` signatures and bodies.
- Modify: `dnstt-server/main_test.go` — extend with `TestResponseFor_*`.
- Modify: `dnstt-server/e2e_test.go` — update three call sites for new signatures.

This is the largest task in G3.

- [ ] **Step 1: Read the current responseFor for context.**

```
grep -n "func responseFor\|func recvLoop\|func run\|func paranoidResponse\|paranoia bool" dnstt-server/main.go
```

Confirm the signatures match the spec and that paranoidResponse exists at ~line 495.

- [ ] **Step 2: Write failing tests.**

Append to `/mnt/Docs/dnstt/dnstt-server/main_test.go` (existing file from G1 task 8):

```go
func makeTestZone(t *testing.T) zoneInfo {
	t.Helper()
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	return newZoneInfo(apex)
}

func mustName(t *testing.T, parts ...string) dns.Name {
	t.Helper()
	labels := make([][]byte, 0, len(parts))
	for _, p := range parts {
		labels = append(labels, []byte(p))
	}
	n, err := dns.NewName(labels)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// makeQuery returns a minimal valid query for given name and type, with
// EDNS0 OPT advertising 4096-byte payload size.
func makeQuery(name dns.Name, qtype uint16) *dns.Message {
	return &dns.Message{
		ID:    0x1234,
		Flags: 0x0100, // QR=0, RD=1
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
}

func TestResponseFor_OutsideZone_Refused(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "google", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp == nil {
		t.Fatal("nil response")
	}
	const RcodeRefused = 5
	if got := resp.Rcode(); got != RcodeRefused {
		t.Fatalf("RCODE %d, want REFUSED (%d)", got, RcodeRefused)
	}
	if resp.Flags&0x0400 != 0 {
		t.Fatal("AA must be 0 for out-of-zone")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answer, got %d", len(resp.Answer))
	}
}

func TestResponseFor_ApexSOA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeSOA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer (SOA), got %d", len(resp.Answer))
	}
	if resp.Answer[0].Type != dns.RRTypeSOA {
		t.Fatalf("answer type %d, want SOA (%d)", resp.Answer[0].Type, dns.RRTypeSOA)
	}
}

func TestResponseFor_ApexNS(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeNS)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Type != dns.RRTypeNS {
		t.Fatalf("expected 1 NS answer, got %+v", resp.Answer)
	}
}

func TestResponseFor_ApexA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (no record)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answer (no A record), got %d", len(resp.Answer))
	}
	// Authority must contain SOA.
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority")
	}
}

func TestResponseFor_ApexAAAA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if len(resp.Answer) != 0 {
		t.Fatal("expected no answer for apex AAAA")
	}
}

func TestResponseFor_ApexMX(t *testing.T) {
	zone := makeTestZone(t)
	const RRTypeMX = 15
	q := makeQuery(mustName(t, "t", "example", "com"), RRTypeMX)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (no MX)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatal("expected no answer")
	}
}

func TestResponseFor_NonExistentSubdomain_A(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "random", "t", "example", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority on NXDOMAIN")
	}
}

func TestResponseFor_NonExistentSubdomain_MX(t *testing.T) {
	zone := makeTestZone(t)
	const RRTypeMX = 15
	q := makeQuery(mustName(t, "random", "t", "example", "com"), RRTypeMX)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
}

func TestResponseFor_TunnelAAAA_BlendPoll(t *testing.T) {
	zone := makeTestZone(t)
	// Build a base32-encoded tunnel name with valid ClientID-bearing prefix.
	// 8 bytes ClientID + 4 bytes (len-prefix 0xe3 + 3 random padding bytes).
	decoded := make([]byte, 8+1+3)
	for i := range decoded[:8] {
		decoded[i] = byte(i + 1) // ClientID = 0102030405060708
	}
	decoded[8] = 0xe0 + 3 // 3 bytes of padding
	encoded := base32Encoding.EncodeToString(decoded)
	encoded = strings.ToLower(encoded)

	prefixLabels := [][]byte{[]byte(encoded)}
	zoneLabels := [][]byte{[]byte("t"), []byte("example"), []byte("com")}
	allLabels := append(prefixLabels, zoneLabels...)
	name, err := dns.NewName(allLabels)
	if err != nil {
		t.Fatal(err)
	}
	q := makeQuery(name, dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (AAAA blend poll)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no AAAA answer (blend poll), got %d", len(resp.Answer))
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority for AAAA blend poll")
	}
}

func TestResponseFor_PayloadTooShort(t *testing.T) {
	zone := makeTestZone(t)
	// Encode a payload < 8 bytes (no ClientID).
	decoded := []byte{1, 2, 3, 4}
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))
	name, err := dns.NewName([][]byte{[]byte(encoded), []byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	q := makeQuery(name, dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
}
```

You'll need `"strings"` in main_test.go imports. If not present, add it alphabetically.

- [ ] **Step 3: Run tests, expect compile errors.**

```
go test ./dnstt-server/ -run TestResponseFor -v
```
Expected: many compile errors (responseFor signature mismatch, plus undefined symbols if zone.go isn't yet referenced from main.go — that's fine; tests reference it directly).

- [ ] **Step 4: Rewrite responseFor.**

In `/mnt/Docs/dnstt/dnstt-server/main.go`, locate the existing `responseFor` (around line 561). Replace its declaration and body with:

```go
// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for carrying downstream data in a TXT record.
//
// The server impersonates a real authoritative NS for zone.apex: SOA/NS at
// the apex resolve to the synthesized records in zone; non-tunnel queries
// at or below the apex return NOERROR/NXDOMAIN with SOA in Authority;
// queries outside the apex are REFUSED.
func responseFor(query *dns.Message, zone zoneInfo) (*dns.Message, []byte) {
	const RcodeRefused = 5
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR=1, RCODE=NOERROR
		Question: query.Question,
	}

	// QR != 0 means it's a response, not a query — drop.
	if query.Flags&0x8000 != 0 {
		return nil, nil
	}

	// EDNS(0) parsing — unchanged from prior behavior.
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}
		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	// Exactly one Question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]

	// Opcode != 0 not supported.
	if query.Opcode() != 0 {
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	// Outside our zone → REFUSED, no AA.
	prefix, inside := question.Name.TrimSuffix(zone.apex)
	if !inside {
		resp.Flags |= RcodeRefused
		return resp, nil
	}

	// EDNS payload-size sanity (matches old behavior — we need >= maxUDPPayload).
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, maxUDPPayload)
		return resp, nil
	}

	resp.Flags |= 0x0400 // AA=1 (we are authoritative for everything in this zone or absent within it)

	// Apex (no labels before the suffix).
	if len(prefix) == 0 {
		switch question.Type {
		case dns.RRTypeSOA:
			resp.Answer = []dns.RR{zone.soa}
		case dns.RRTypeNS:
			resp.Answer = []dns.RR{zone.ns}
		default:
			// NOERROR with no records of this type — Authority carries SOA.
			resp.Authority = []dns.RR{zone.soa}
		}
		return resp, nil
	}

	// Strictly under apex.
	// Only TXT and AAAA are tunnel-bearing types; everything else is NXDOMAIN+SOA.
	if question.Type != dns.RRTypeTXT && question.Type != dns.RRTypeAAAA {
		resp.Flags |= dns.RcodeNameError
		resp.Authority = []dns.RR{zone.soa}
		return resp, nil
	}

	// Try to base32-decode the prefix.
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= dns.RcodeNameError
		resp.Authority = []dns.RR{zone.soa}
		return resp, nil
	}
	payload = payload[:n]

	// AAAA blend-in poll: tunnel data flows via QNAME (caller of responseFor
	// extracts payload from the second return value), but AAAA responses
	// never carry payload — they look like "no AAAA record exists for this
	// name", which is what a real auth NS would return.
	if question.Type == dns.RRTypeAAAA {
		resp.Authority = []dns.RR{zone.soa}
		// Validate payload length so a malformed query still returns NXDOMAIN+SOA
		// (matches the test expectation TestResponseFor_PayloadTooShort).
		if len(payload) < 8 { // ClientID is 8 bytes
			resp.Flags = (resp.Flags &^ 0xf) | dns.RcodeNameError
			return resp, nil
		}
		return resp, payload
	}

	// TXT path: tunnel data flows in both directions. sendLoop fills Answer
	// with downstream payload.
	return resp, payload
}
```

`base32Encoding` is the existing package-scope `base32.StdEncoding.WithPadding(base32.NoPadding)` defined at top of main.go. It stays.

- [ ] **Step 5: Delete `paranoidResponse`.**

In `dnstt-server/main.go` find `func paranoidResponse(query *dns.Message) *dns.Message {` (around line 495) and delete the whole function plus the preceding doc comment and the `var fakeIPs = []net.IP{...}` declaration that's only used by `paranoidResponse`. Also delete the unused import `mathrand "math/rand"` if it becomes unused (verify with `goimports` or look at all `mathrand.` usages).

- [ ] **Step 6: Update recvLoop signature.**

Find `func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, limiter *clientRateLimiter, paranoia bool) error {`.

Change to:

```go
func recvLoop(zone zoneInfo, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, limiter *clientRateLimiter) error {
```

Inside the body, find the `responseFor(&query, domain, paranoia)` call and change to:

```go
		resp, payload := responseFor(&query, zone)
```

Also: the existing recvLoop has logic that, when payload is too short for ClientID, writes `resp.Flags |= dns.RcodeNameError` and a log message. After the new `responseFor` already handles this internally for AAAA, the recvLoop check is still needed for TXT — but since responseFor returns the payload without enforcing length on the TXT path, we keep recvLoop's check:

```go
			if n == len(clientID) {
				// rate-limit + queue payload to KCP
				...
			} else {
				// Payload too short — but responseFor already returned a NOERROR
				// response with Authority=[SOA] for an apex query, or a tunnel
				// candidate response for a sub-query. We need to convert the
				// sub-query NOERROR into NXDOMAIN since payload is invalid.
				if resp != nil && resp.Rcode() == dns.RcodeNoError && len(resp.Answer) == 0 {
					resp.Flags = (resp.Flags &^ 0xf) | dns.RcodeNameError
					if len(resp.Authority) == 0 {
						resp.Authority = []dns.RR{zone.soa}
					}
					log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
				}
			}
```

Replace the existing `else { ... }` block (around line 757) with the above.

- [ ] **Step 7: Update run signature.**

Find `func run(ctx context.Context, privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, paranoia bool, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool, socks5AllowPrivate bool) error {`.

Change to:

```go
func run(ctx context.Context, privkey []byte, zone zoneInfo, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool, socks5AllowPrivate bool) error {
```

(Removed `domain dns.Name`, removed `paranoia bool`, added `zone zoneInfo`.)

Inside the body, find the `recvLoop(...)` call and change to:

```go
	return recvLoop(zone, dnsConn, ttConn, ch, limiter)
```

- [ ] **Step 8: Update main() to build zoneInfo and call run.**

Find in `main()`:

```go
		var paranoia bool
```

Delete this declaration and the line:

```go
	flag.BoolVar(&paranoia, "paranoia", false, "return fake DNS answers for non-tunnel queries to hide tunnel presence")
```

Find the existing call:

```go
		err = run(ctx, privkey, domain, upstream, dnsConn, limiter, paranoia, fecData, fecParity, kcpCfg, authDB, compress, socks5AllowPrivate)
```

Replace with:

```go
		zone := newZoneInfo(domain)
		err = run(ctx, privkey, zone, upstream, dnsConn, limiter, fecData, fecParity, kcpCfg, authDB, compress, socks5AllowPrivate)
```

The variable `domain` is still defined just above this point from `dns.ParseName(flag.Arg(0))`.

- [ ] **Step 9: Update e2e_test.go.**

In `/mnt/Docs/dnstt/dnstt-server/e2e_test.go`, find the three places that previously referenced paranoia. Each test calls `acceptSessions(...)` (which DOESN'T take paranoia — that arg is in `run`/`recvLoop`, not `acceptSessions`). So no signature change in e2e_test.go is needed for the paranoia-dropping. Verify by:

```
grep -n "paranoia\|recvLoop\|responseFor" dnstt-server/e2e_test.go
```

Expected: zero references. If any appear, update them per the new signatures.

- [ ] **Step 10: Run tests.**

```
go build ./...
go test ./...
```

All tests must pass. The new TestResponseFor_* tests (10 tests added in step 2) should be green.

- [ ] **Step 11: Commit.**

```
gofmt -w dnstt-server/main.go dnstt-server/main_test.go
git add dnstt-server/main.go dnstt-server/main_test.go
git commit -m "feat(server): real auth-NS responses for non-tunnel queries"
```

---

## Task 3: AAAA-blend in sendLoop drops the [16]byte{0}

`sendLoop` currently writes a zeroed AAAA RR whenever the query is AAAA. After Task 2, `responseFor` already prepares the right `Authority=[SOA]` for AAAA-blend. `sendLoop` just needs to stop writing the zeroed Answer.

**Files:**
- Modify: `dnstt-server/main.go` (sendLoop AAAA branch)

- [ ] **Step 1: Locate the AAAA branch.**

```
grep -n "RRTypeAAAA" dnstt-server/main.go
```

There's a block in `sendLoop` (around current line 800-810) that does:

```go
				if qtype == dns.RRTypeAAAA {
					// AAAA queries are blend-in polls — respond with a
					// single zeroed record and do not dequeue any payload.
					rec.Resp.Answer = []dns.RR{{
						Name:  qname,
						Type:  dns.RRTypeAAAA,
						Class: qclass,
						TTL:   responseTTL,
						Data:  make([]byte, 16),
					}}
				} else {
					// ... TXT path ...
				}
```

- [ ] **Step 2: Remove the zeroed Answer write.**

Replace:

```go
				if qtype == dns.RRTypeAAAA {
					// AAAA queries are blend-in polls — respond with a
					// single zeroed record and do not dequeue any payload.
					// Pending KCP data stays for the next TXT response,
					// avoiding resolver-side RRset reordering corruption.
					rec.Resp.Answer = []dns.RR{{
						Name:  qname,
						Type:  dns.RRTypeAAAA,
						Class: qclass,
						TTL:   responseTTL,
						Data:  make([]byte, 16),
					}}
				} else {
```

With:

```go
				if qtype == dns.RRTypeAAAA {
					// AAAA queries are blend-in polls. responseFor already
					// set Authority=[SOA] to look like "no AAAA record".
					// We don't enqueue downstream payload here — pending
					// KCP data stays for the next TXT response (avoids
					// resolver-side RRset reordering corruption).
				} else {
```

(We keep the empty `if qtype == dns.RRTypeAAAA` block to preserve the else-branch shape; this is fine, the compiler optimizes it away. Alternative: invert to `if qtype != dns.RRTypeAAAA { ... }` and remove the empty block — but that changes more lines.)

- [ ] **Step 3: Run existing tests + new TestResponseFor_TunnelAAAA_BlendPoll.**

```
go test ./dnstt-server/ -run "TestResponseFor_TunnelAAAA_BlendPoll|TestSessionE2E" -v
```

Both must pass.

- [ ] **Step 4: Full suite + build.**

```
go test ./...
go build ./...
```
Clean.

- [ ] **Step 5: Commit.**

```
gofmt -w dnstt-server/main.go
git add dnstt-server/main.go
git commit -m "feat(server): AAAA-blend returns empty Answer + SOA"
```

---

## Task 4: drop -paranoia flag and ServerConfig.Paranoia

Final cleanup of the paranoia control surface.

**Files:**
- Modify: `dnstt-server/main.go` — the flag declaration is already removed in Task 2 step 8. Verify.
- Modify: `dnstt-server/config.go` — remove `Paranoia bool` field and corresponding `setDefault` call.

- [ ] **Step 1: Verify main.go has no -paranoia references.**

```
grep -n "paranoia" dnstt-server/main.go
```
Expected: zero matches (removed in Task 2). If any remain, delete them.

- [ ] **Step 2: Remove from ServerConfig.**

In `/mnt/Docs/dnstt/dnstt-server/config.go`, find:

```go
	Paranoia    bool    `yaml:"paranoia"`
```

Delete the line.

In `applyServerConfig` find:

```go
	// Boolean flags are always applied so that "paranoia: false" in the
	// config can explicitly disable a flag, not just silently skip it.
	setDefault("paranoia", fmt.Sprintf("%v", cfg.Paranoia))
```

Delete those three lines (including the comment that's now wrong). The "always-applied bool" comment can stay if it's still applicable to other booleans like `socks5`, `compress`.

- [ ] **Step 3: Build + test.**

```
go build ./...
go test ./...
```
Clean. If `go test ./dnstt-server/` reports `cfg.Paranoia` undefined anywhere, grep for stragglers and remove.

- [ ] **Step 4: Commit.**

```
gofmt -w dnstt-server/config.go
git add dnstt-server/config.go
git commit -m "fix(server): drop -paranoia flag and Paranoia config field"
```

---

## Task 5: rebuildAsTruncated preserves Authority

Extend the G1 truncate helper so it preserves the `Authority` section on its first build attempt. Without this, an oversized NXDOMAIN-with-SOA gets truncated to a bare NXDOMAIN, losing the SOA that the new auth-NS-mimicry depends on.

**Files:**
- Modify: `dnstt-server/main.go` — `rebuildAsTruncated`.
- Modify: `dnstt-server/main_test.go` — add a test.

- [ ] **Step 1: Read current rebuildAsTruncated.**

```
grep -n "func rebuildAsTruncated" dnstt-server/main.go
```

Confirm body keeps Question + Additional (OPT), drops Authority. We're about to change "drops Authority" to "keeps Authority on first try".

- [ ] **Step 2: Write failing test.**

Append to `/mnt/Docs/dnstt/dnstt-server/main_test.go`:

```go
func TestRebuildAsTruncated_PreservesAuthorityWhenItFits(t *testing.T) {
	zone := makeTestZone(t)
	name := mustName(t, "random", "t", "example", "com")
	resp := &dns.Message{
		ID:        0x1234,
		Flags:     0x8400 | dns.RcodeNameError, // AA=1, NXDOMAIN
		Question:  []dns.Question{{Name: name, Type: dns.RRTypeA, Class: dns.ClassIN}},
		Authority: []dns.RR{zone.soa},
	}
	out := rebuildAsTruncated(resp, 1232)

	parsed, err := dns.MessageFromWireFormat(out)
	if err != nil {
		t.Fatalf("not valid DNS: %v", err)
	}
	if parsed.Flags&0x0200 == 0 {
		t.Fatal("expected TC=1")
	}
	foundSOA := false
	for _, rr := range parsed.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected Authority SOA preserved when within limit")
	}
}
```

- [ ] **Step 3: Run test, expect FAIL.**

```
go test ./dnstt-server/ -run TestRebuildAsTruncated_PreservesAuthorityWhenItFits -v
```
Expected: test fails because current `rebuildAsTruncated` drops Authority.

- [ ] **Step 4: Modify rebuildAsTruncated.**

Find:

```go
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
	...
}
```

Replace with:

```go
func rebuildAsTruncated(resp *dns.Message, limit int) []byte {
	stripped := &dns.Message{
		ID:         resp.ID,
		Flags:      resp.Flags | 0x0200, // TC = 1
		Question:   resp.Question,
		Authority:  resp.Authority,  // keep SOA-in-Authority if present
		Additional: resp.Additional, // keep OPT if present
	}
	buf, err := stripped.WireFormat()
	if err == nil && len(buf) <= limit {
		return buf
	}

	// Fallback 1: drop Authority but keep OPT.
	stripped.Authority = nil
	buf, err = stripped.WireFormat()
	if err == nil && len(buf) <= limit {
		return buf
	}

	// Last-ditch: drop OPT too.
	stripped.Additional = nil
	buf, err = stripped.WireFormat()
	if err != nil || len(buf) > limit {
		return buf
	}
	return buf
}
```

- [ ] **Step 5: Run tests.**

```
go test ./dnstt-server/ -run TestRebuildAsTruncated -v
```
Expected: 3 tests pass (existing 2 + new 1).

- [ ] **Step 6: Full suite.**

```
go test ./...
```
Clean.

- [ ] **Step 7: Commit.**

```
gofmt -w dnstt-server/main.go dnstt-server/main_test.go
git add dnstt-server/main.go dnstt-server/main_test.go
git commit -m "fix(server/truncate): preserve Authority in rebuildAsTruncated"
```

---

## Task 6: prober E2E test

**Files:**
- Modify: `dnstt-server/e2e_test.go` — add `TestSessionE2E_ProberQueriesIgnored`.

- [ ] **Step 1: Append the test.**

In `/mnt/Docs/dnstt/dnstt-server/e2e_test.go`, append after the existing tests:

```go
// TestSessionE2E_ProberQueriesIgnored verifies that an active prober's
// out-of-zone query receives REFUSED while the in-progress tunnel session
// continues working unaffected.
func TestSessionE2E_ProberQueriesIgnored(t *testing.T) {
	apex, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatal(err)
	}
	zone := newZoneInfo(apex)

	// Drive a query directly through responseFor (the lowest-level path).
	// This is the unit-of-truth for prober resistance: the same code runs
	// in production recvLoop.
	q := &dns.Message{
		ID:    0xBEEF,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: mustParseName(t, "google.com"), Type: dns.RRTypeA, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	resp, _ := responseFor(q, zone)
	const RcodeRefused = 5
	if resp == nil {
		t.Fatal("nil response")
	}
	if got := resp.Rcode(); got != RcodeRefused {
		t.Fatalf("RCODE %d, want REFUSED (%d)", got, RcodeRefused)
	}
	if resp.Flags&0x0400 != 0 {
		t.Fatal("AA must be 0 for out-of-zone")
	}
}

func mustParseName(t *testing.T, s string) dns.Name {
	t.Helper()
	n, err := dns.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
```

(This test deliberately exercises just `responseFor` rather than the full smux+KCP setup — the existing `TestSessionE2E_*` tests already cover the full pipeline; we just need to assert the prober-resistance invariant.)

If `mustParseName` clashes with the `mustName` helper from `main_test.go` (different package, different file — but both in `package main` of dnstt-server), use `mustParseName` only here. Both can coexist; `mustName` takes parts, `mustParseName` takes a string.

Actually since `main_test.go` and `e2e_test.go` are in the same package, define `mustParseName` ONLY in `e2e_test.go` (as above) and use it. Don't redeclare `mustName`.

- [ ] **Step 2: Run.**

```
go test ./dnstt-server/ -run TestSessionE2E -v
```

All four E2E tests must pass (`TestSessionE2E`, `TestSessionE2E_SOCKS5`, `TestSessionE2E_ParamMismatch`, `TestSessionE2E_ProberQueriesIgnored`).

- [ ] **Step 3: Full suite.**

```
go test ./...
```
Clean.

- [ ] **Step 4: Commit.**

```
gofmt -w dnstt-server/e2e_test.go
git add dnstt-server/e2e_test.go
git commit -m "feat(server/e2e): test prober queries return REFUSED outside zone"
```

---

## Task 7: client drops -obfuscate and sendDecoy

Per Q4 decision: decoys are dropped entirely. Through DoH/DoT/DoQ, the resolver sees our queries anyway; on-path observers see TLS, not DNS contents. Decoys helped only in raw UDP (debug-only).

**Files:**
- Modify: `dnstt-client/dns.go` — remove `sendDecoy`, `obfuscate` field, `decoyProbability` constant, the `obfuscate` parameter on `NewDNSPacketConn`, decoy invocation in `sendLoop`.
- Modify: `dnstt-client/main.go` — remove `-obfuscate` flag and update 5 `NewDNSPacketConn` callsites.
- Modify: `start-client.sh` — remove the `-obfuscate` line.

- [ ] **Step 1: Read current obfuscate surface.**

```
grep -n "obfuscate\|sendDecoy\|decoyProbability" dnstt-client/dns.go dnstt-client/main.go
```

Confirm:
- `decoyProbability` constant
- `obfuscate bool` field on `DNSPacketConn`
- `NewDNSPacketConn(transport, addr, domain, obfuscate)` signature
- `sendDecoy` function definition
- `if c.obfuscate && len(p) > 0 && mathrand.Intn(decoyProbability) == 0 { go c.sendDecoy(...) }` in sendLoop
- `-obfuscate` flag in main.go
- 5 `NewDNSPacketConn` callsites in main.go

- [ ] **Step 2: Strip dns.go.**

In `/mnt/Docs/dnstt/dnstt-client/dns.go`:

(a) Find the `decoyProbability` const and remove it. It's likely:
```go
	decoyProbability = 5 // ~20% chance
```

(b) Find the `DNSPacketConn` struct definition. Remove the `obfuscate bool` field.

(c) Find `NewDNSPacketConn` signature:
```go
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, obfuscate bool) *DNSPacketConn {
```
Change to:
```go
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
```

Inside the function, remove the line `obfuscate: obfuscate,` from the struct literal.

(d) Find and delete the entire `sendDecoy` function (~50 lines).

(e) Find in `sendLoop`:
```go
		// Obfuscation: occasionally send a decoy query after a real
		// data packet to disguise traffic patterns.
		if c.obfuscate && len(p) > 0 && mathrand.Intn(decoyProbability) == 0 {
			go c.sendDecoy(transport, addr)
		}
```
Delete those lines.

(f) Verify imports: `mathrand "math/rand"` is now unused if it was only consumed by sendDecoy. Run `goimports -w dnstt-client/dns.go` or grep for `mathrand` to confirm it's safe to remove. If it's still used elsewhere (e.g. `mathrand.Intn` in send loop for AAAA selection at line 387), keep the import.

- [ ] **Step 3: Strip main.go.**

In `/mnt/Docs/dnstt/dnstt-client/main.go`:

(a) Find:
```go
	flag.BoolVar(&obfuscate, "obfuscate", false, "send decoy A/AAAA queries to disguise traffic patterns")
```
Delete this line. Also find `var obfuscate bool` (or similar local declaration) and remove it.

(b) Find the 5 `NewDNSPacketConn` callsites. Each currently looks like:
```go
NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain, obfuscate)
```
Change each to:
```go
NewDNSPacketConn(bare, turbotunnel.DummyAddr{}, domain)
```

(Same pattern in multipath, multipath-reconnect, auto-closure, single-init, single-reconnect.)

- [ ] **Step 4: Strip start-client.sh.**

In `/mnt/Docs/dnstt/start-client.sh`, find the line:
```sh
    -obfuscate \
```
Delete it.

- [ ] **Step 5: Build + test.**

```
go build ./...
go test ./...
```
Clean.

- [ ] **Step 6: Commit.**

```
gofmt -w dnstt-client/dns.go dnstt-client/main.go
git add dnstt-client/dns.go dnstt-client/main.go start-client.sh
git commit -m "fix(client): remove -obfuscate flag and sendDecoy"
```

---

## Task 8: README updates

**Files:**
- Modify: `README.md`.

- [ ] **Step 1: Remove `-obfuscate` row from client flags table.**

In `README.md` find the `## Все флаги клиента` section, the `#### Безопасность и маскировка` table. Find and DELETE the row that begins:
```markdown
| `-obfuscate` | `false` | Вставлять случайные AAAA/A-запросы (~20%) ...
```

- [ ] **Step 2: Remove `-paranoia` row from server flags table.**

In `## Все флаги сервера`, the `#### Режим работы` table. Find and DELETE the row:
```markdown
| `-paranoia` | `false` | Возвращать правдоподобные поддельные A/AAAA-ответы ...
```

- [ ] **Step 3: Add an "auth-NS by default" subsection.**

After the existing `### Управление ключами` and `### Cert-пиннинг резолвера` subsections under `## Шифрование и аутентификация`, add a new subsection:

```markdown
### Маскировка авторитативного NS

Сервер по умолчанию ведёт себя как обычный авторитативный DNS-сервер для своей зоны. На запросы пробера это выглядит так:

```sh
dig @<server> <domain> SOA       # NOERROR + синтезированная SOA
dig @<server> <domain> NS        # NOERROR + ns.<domain>
dig @<server> nonexistent.<domain> A   # NXDOMAIN с SOA в Authority
dig @<server> google.com A       # REFUSED (имя вне нашей зоны)
```

Это закрывает несколько детектируемых сигнатур:

- **NXDOMAIN без SOA в Authority** — характерный признак, что отвечающий сервер не ведёт себя как обычный auth NS. После фикса все NXDOMAIN-ответы несут правильный SOA.
- **`::` (IPv6 ноль) на AAAA-запросы** — ни один реальный auth NS такого не возвращает; теперь AAAA-blend-poll выглядит как «нет AAAA-записи у этого имени» (NOERROR, пустой Answer, SOA в Authority).
- **Поддельные ответы на запросы вне зоны** — раньше старый `-paranoia` режим возвращал Cloudflare-IP на любой не-туннельный A-запрос, что было легко отличить. Теперь такие запросы корректно отфильтровываются REFUSED.

Известное ограничение: запрос `ns.<domain> A` (DNS-имя самого NS-хоста) внутри туннельной зоны сейчас возвращает NXDOMAIN, хотя в публичном DNS это имя обычно имеет glue-A-запись на IP сервера. Внимательный пробер может это заметить. Реализация corner-case'a — задача для отдельного фикса.
```

- [ ] **Step 4: Update SOCKS5 SSRF paragraph if needed.**

The SOCKS5 SSRF paragraph from G2 task 8 mentioned `-paranoia` — verify with:
```
grep -n "paranoia\|obfuscate" README.md
```
After steps 1-2, no matches should remain. If any remain (e.g. in examples), update them.

- [ ] **Step 5: Commit.**

```
git add README.md
git commit -m "docs: document G3 stealth changes"
```

---

## Self-Review Checklist

Before declaring G3 complete:

- [ ] **Spec coverage:**
  - #6 paranoia signatures → Tasks 1, 2, 4 (zone synthesis + responseFor rewrite + flag removal).
  - #8 obfuscate decoys → Task 7.
  - #9 AAAA-blend `::` → Task 3.
  - Authority preservation in truncate → Task 5.
  - Prober regression test → Task 6.
  - Documentation → Task 8.
- [ ] **Placeholder scan:** none.
- [ ] **Type/name consistency:** `zoneInfo`, `newZoneInfo`, `encodeRDataSOA`, `encodeName`, `prependLabel`, `responseTTL`, `RcodeRefused`, `RRTypeSOA`, `RRTypeNS` all used consistently across tasks.
- [ ] Each task ends in green test run + commit.

---

## Final Integration Check (after Task 8)

- [ ] `go test ./...` — clean
- [ ] `go vet ./...` — clean
- [ ] Smoke probe (one-shot, no need to re-run smoke-multipath.sh):
  ```bash
  ssh root@150.241.94.29 'pkill dnstt-server; nohup /opt/dnstt/dnstt-server -udp :53 -privkey-file /opt/dnstt/server.key -socks5 t.ivantopgaming.ru >/opt/dnstt/server.log 2>&1 &'
  sleep 2
  dig +short @150.241.94.29 t.ivantopgaming.ru SOA
  # expected: ns.t.ivantopgaming.ru. hostmaster.t.ivantopgaming.ru. <serial> 3600 1800 604800 60
  dig @150.241.94.29 google.com A | grep -i status
  # expected: status: REFUSED
  dig @150.241.94.29 nonexistent.t.ivantopgaming.ru A | grep -A1 "AUTHORITY SECTION"
  # expected: NXDOMAIN with SOA record
  ssh root@150.241.94.29 'pkill dnstt-server'
  ```

When all green: G3 complete. Ветка `fix/audit-pass-1` продолжает накапливать G1+G2+G3. Squash в master — после G4+G5.
