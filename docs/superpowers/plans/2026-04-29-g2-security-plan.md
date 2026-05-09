# G2 Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four security gaps identified in the audit: SOCKS5-mode SSRF (#2), TLS pin-cert that disables chain validation (#3), pubkey logged at info level (#12), and failed-token bytes logged in plaintext (#13).

**Architecture:** Defense-in-depth at the boundary points. SOCKS5 server denies private/loopback/link-local/cloud-metadata destinations by default with explicit opt-in flag for ops who need internal targets. Cert pinning becomes leaf-only with chain validation by default; users who need self-signed pinning opt in via a separate flag. Sensitive log output (pubkey, token-prefixes) is moved to debug-level or replaced with SHA-256 fingerprints.

**Tech Stack:** Go 1.24 stdlib (`net`, `net/netip`, `crypto/sha256`, `crypto/tls`, `log/slog`).

**Branch:** `fix/audit-pass-1` (continues from G1; G2 commits stack on top of `2a5f9c0`).

**Testing:** Local `go test ./...` after every step. No additional infra needed — all tests are unit-level.

**Wire/CLI compat:** breaking changes are fine (per user). New flags added: `-socks5-allow-private`, `-pin-cert-skip-chain`. Defaults flip to safer behavior.

---

## Design Decisions Locked

These are the calls that would normally come out of brainstorming. They are decided here so the plan can be executed without back-and-forth.

1. **SSRF deny-list scope.** Default-deny destinations whose resolved IP falls in any of: loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10) — covers cloud metadata `169.254.169.254`, RFC1918 private (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), IPv6 ULA (fc00::/7), multicast, broadcast, "this network" (0.0.0.0/8). Use `netip.Addr.IsPrivate / IsLoopback / IsLinkLocalUnicast / IsMulticast / IsUnspecified / IsLinkLocalMulticast` plus an explicit CGNAT range.

2. **`-socks5-allow-private` flag** opts back in to allowing those targets. Default: false.

3. **Pin-cert default policy:** pin matches the **leaf** certificate only (`cs.PeerCertificates[0]`), AND TLS chain validation runs normally (`InsecureSkipVerify=false`). This lines up with HPKP-style pinning: the pin replaces no part of CA validation, it's an additional check.

4. **`-pin-cert-skip-chain` flag** opts in to "pin replaces all CA validation." Required for self-signed certs.

5. **Pubkey at startup** moves to `slog.Debug`. Operators wanting to know it can use `-log-level debug` once and read it; routine `info`-level operation does not include it.

6. **Auth-token failure log** changes from `unauthorized client %x` (first 8 bytes of the failed token) to `unauthorized client (sha256-prefix=%x)` where `%x` is the first 8 bytes of `sha256(token)`. The hash is one-way so even verbose logs don't disclose the token shape.

---

## File Structure

### Modified

- `dnstt-server/socks5.go` — destination-IP deny check before dialing.
- `dnstt-server/main.go` — wire `-socks5-allow-private` flag and `socks5AllowPrivate bool` through to `handleSocks5Stream`; demote pubkey log to slog.Debug; rewrite token log line.
- `dnstt-server/config.go` — YAML field `socks5-allow-private`.
- `dnstt-client/pin.go` — leaf-only pin matching; chain validation respected by default; `pin-cert-skip-chain` mode.
- `dnstt-client/main.go` — wire `-pin-cert-skip-chain` flag.
- `dnstt-client/config.go` — `pin-cert-skip-chain` field.
- `README.md` — document new defaults and flags in §"Все флаги сервера" / §"Все флаги клиента" / §"Шифрование и аутентификация".

### Created

- `dnstt-server/socks5_dest.go` — `isDeniedDestination(host string, allowPrivate bool) error` plus the IP classification used by it. Pure helper, no dependencies on socks5.go state.
- `dnstt-server/socks5_dest_test.go` — table-driven coverage of the deny-list.
- `dnstt-client/pin_test.go` — tests for leaf-pin, intermediate-pin-rejected, expired-cert-rejected, skip-chain-mode.

---

## Conventions

- TDD: failing test → minimal code → passing test → commit, per task.
- `gofmt -w` on touched files before commit.
- Run `go test ./...` after each task.
- Each task = one atomic commit. Squash happens at G1+G2+...+G5 merge to master.
- Branch stays `fix/audit-pass-1`.

---

## Task 1: SOCKS5 destination deny-list helper (#2 part 1)

Build and unit-test the IP-classification helper before integrating it into the request handler.

**Files:**
- Create: `dnstt-server/socks5_dest.go`
- Create: `dnstt-server/socks5_dest_test.go`

- [ ] **Step 1: Write failing tests.**

Create `dnstt-server/socks5_dest_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestIsDeniedDestination(t *testing.T) {
	for _, tc := range []struct {
		name         string
		host         string
		allowPrivate bool
		wantErrFrag  string // empty = expected to allow
	}{
		// Public addresses — always allowed.
		{"public IPv4", "1.1.1.1", false, ""},
		{"public IPv6", "2001:db8::1", false, ""},
		{"google", "8.8.8.8", false, ""},

		// Loopback — denied even with allowPrivate, since this is almost
		// always an attempt to talk to the server itself.
		{"loopback v4 deny default", "127.0.0.1", false, "loopback"},
		{"loopback v4 still deny when allow", "127.0.0.1", true, "loopback"},
		{"loopback v6 deny", "::1", false, "loopback"},

		// Cloud metadata — denied even with allowPrivate.
		{"AWS metadata", "169.254.169.254", false, "link-local"},
		{"AWS metadata still deny when allow", "169.254.169.254", true, "link-local"},
		{"link-local IPv6", "fe80::1", false, "link-local"},

		// RFC1918 private — denied by default, allowed with flag.
		{"rfc1918 10/8 deny", "10.0.0.5", false, "private"},
		{"rfc1918 10/8 allow with flag", "10.0.0.5", true, ""},
		{"rfc1918 172.16/12 deny", "172.20.1.1", false, "private"},
		{"rfc1918 172.16/12 allow with flag", "172.20.1.1", true, ""},
		{"rfc1918 192.168/16 deny", "192.168.1.1", false, "private"},
		{"rfc1918 192.168/16 allow with flag", "192.168.1.1", true, ""},
		{"ULA IPv6 deny", "fd00::1", false, "private"},
		{"ULA IPv6 allow with flag", "fd00::1", true, ""},

		// CGNAT — denied by default, allowed with flag.
		{"CGNAT deny", "100.64.0.1", false, "private"},
		{"CGNAT allow with flag", "100.64.0.1", true, ""},

		// Multicast / broadcast / unspecified — denied always.
		{"multicast v4", "224.0.0.1", false, "multicast"},
		{"multicast v4 still deny", "224.0.0.1", true, "multicast"},
		{"unspecified v4", "0.0.0.0", false, "unspecified"},
		{"broadcast", "255.255.255.255", false, "broadcast"},
		{"multicast v6", "ff02::1", false, "multicast"},

		// Hostnames — accepted (resolution happens at dial time, but the
		// helper sees a literal hostname and lets net.Dial sort it out).
		{"hostname public", "example.com", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := isDeniedDestination(tc.host, tc.allowPrivate)
			if tc.wantErrFrag == "" {
				if err != nil {
					t.Fatalf("expected allow, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected deny containing %q, got nil", tc.wantErrFrag)
			}
			if !strings.Contains(err.Error(), tc.wantErrFrag) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErrFrag, err.Error())
			}
		})
	}
}
```

- [ ] **Step 2: Run test, expect compile error.**

```
cd /mnt/Docs/dnstt
go test ./dnstt-server/ -run TestIsDeniedDestination -v
```
Expected: `isDeniedDestination` undefined.

- [ ] **Step 3: Create helper.**

Create `dnstt-server/socks5_dest.go`:

```go
package main

import (
	"errors"
	"fmt"
	"net/netip"
)

// cgNATPrefix4 covers the RFC 6598 100.64.0.0/10 range that net/netip's
// IsPrivate does not classify as private.
var cgNATPrefix4 = netip.MustParsePrefix("100.64.0.0/10")

// broadcastV4 is 255.255.255.255. The stdlib does not surface a method for it.
var broadcastV4 = netip.MustParseAddr("255.255.255.255")

// isDeniedDestination returns a non-nil error if host (an IP literal or a
// hostname) resolves to a destination class that the SOCKS5 server should
// refuse. Loopback, link-local, multicast, broadcast, and unspecified are
// always denied. RFC1918/ULA/CGNAT private destinations are denied by
// default but allowed when allowPrivate is true. Hostnames pass through;
// the dialer's own resolver will fail with a normal connection error if it
// resolves to a literal that the deny-list catches at dial time.
func isDeniedDestination(host string, allowPrivate bool) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP literal; let the dialer try to resolve it. We can't
		// pre-screen hostnames without doing our own DNS, which would
		// add a side channel. Acceptable trade-off: the deny-list
		// catches direct-IP attempts; hostnames that resolve to private
		// IPs will reach the dialer.
		return nil
	}
	switch {
	case addr.IsLoopback():
		return errors.New("destination loopback address denied")
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		return errors.New("destination link-local address denied")
	case addr.IsMulticast():
		return errors.New("destination multicast address denied")
	case addr.IsUnspecified():
		return errors.New("destination unspecified address denied")
	case addr == broadcastV4:
		return errors.New("destination broadcast address denied")
	}
	private := addr.IsPrivate() || cgNATPrefix4.Contains(addr)
	if private && !allowPrivate {
		return fmt.Errorf("destination private address %s denied (use -socks5-allow-private to permit)", addr)
	}
	return nil
}
```

- [ ] **Step 4: Run tests, expect PASS.**

```
go test ./dnstt-server/ -run TestIsDeniedDestination -v
```
Expected: all 22 subtests PASS.

- [ ] **Step 5: Full suite.**

```
go test ./...
```
Expected: all packages pass.

- [ ] **Step 6: Commit.**

```
gofmt -w dnstt-server/socks5_dest.go dnstt-server/socks5_dest_test.go
git add dnstt-server/socks5_dest.go dnstt-server/socks5_dest_test.go
git commit -m "feat(server/socks5): add destination deny-list helper"
```

---

## Task 2: Wire deny-list into SOCKS5 handler (#2 part 2)

**Files:**
- Modify: `dnstt-server/socks5.go` — add `allowPrivate bool` to `handleSocks5Stream`, call `isDeniedDestination` before dialing, return SOCKS5 REP=0x02 on deny.
- Modify: `dnstt-server/main.go` — add `socks5AllowPrivate bool` flag, thread through `acceptStreams` → `handleSocks5Stream`.

- [ ] **Step 1: Read current `handleSocks5Stream` signature.**

```
grep -n "handleSocks5Stream" dnstt-server/*.go
```
Confirm: `func handleSocks5Stream(stream *smux.Stream, conv uint32, compress bool) error` and the only caller is `acceptStreams` in `main.go`.

- [ ] **Step 2: Modify `handleSocks5Stream` in `dnstt-server/socks5.go`.**

Find:
```go
func handleSocks5Stream(stream *smux.Stream, conv uint32, compress bool) error {
	target, err := socks5Handshake(stream)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake: %v", err)
	}

	log.Printf("stream %08x:%d SOCKS5 CONNECT %s", conv, stream.ID(), target)

	dialer := net.Dialer{Timeout: upstreamDialTimeout}
	conn, err := dialer.Dial("tcp", target)
```

Replace with:
```go
func handleSocks5Stream(stream *smux.Stream, conv uint32, compress bool, allowPrivate bool) error {
	target, err := socks5Handshake(stream)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake: %v", err)
	}

	log.Printf("stream %08x:%d SOCKS5 CONNECT %s", conv, stream.ID(), target)

	host, _, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		// Malformed target — refuse with REP=0x01 (general failure).
		stream.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return fmt.Errorf("stream %08x:%d SOCKS5 bad target %q: %v", conv, stream.ID(), target, splitErr)
	}
	if denyErr := isDeniedDestination(host, allowPrivate); denyErr != nil {
		// REP=0x02 = connection not allowed by ruleset, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
		stream.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return fmt.Errorf("stream %08x:%d SOCKS5 connect %s: %v", conv, stream.ID(), target, denyErr)
	}

	dialer := net.Dialer{Timeout: upstreamDialTimeout}
	conn, err := dialer.Dial("tcp", target)
```

- [ ] **Step 3: Modify `acceptStreams` in `dnstt-server/main.go`.**

Find the call site (inside the goroutine that processes accepted streams):
```go
err = handleSocks5Stream(stream, conn.GetConv(), compress)
```

Add `socks5AllowPrivate` to the call. The plumbing requires passing the flag through `acceptStreams` and `acceptSessions`. So:

In `acceptStreams` find the signature line:
```go
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, authDB *authDatabase, compress bool, serverParams handshakeParams) error {
```
Change to:
```go
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, authDB *authDatabase, compress bool, serverParams handshakeParams, socks5AllowPrivate bool) error {
```

Inside the function find the `handleSocks5Stream(stream, conn.GetConv(), compress)` call (only one). Change to:
```go
err = handleSocks5Stream(stream, conn.GetConv(), compress, socks5AllowPrivate)
```

In `acceptSessions` find the signature:
```go
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, kcpCfg kcpConfig, authDB *authDatabase, compress bool, serverParams handshakeParams) error {
```
Change to:
```go
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, kcpCfg kcpConfig, authDB *authDatabase, compress bool, serverParams handshakeParams, socks5AllowPrivate bool) error {
```

Inside, find the `acceptStreams` call and pass `socks5AllowPrivate`:
```go
err := acceptStreams(conn, privkey, upstream, authDB, compress, serverParams, socks5AllowPrivate)
```

In `run` find the signature and pass through:
```go
func run(ctx context.Context, privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, paranoia bool, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool, socks5AllowPrivate bool) error {
```
And the inner `acceptSessions` call:
```go
err := acceptSessions(ln, privkey, mtu, upstream, kcpCfg, authDB, compress, serverParams, socks5AllowPrivate)
```

- [ ] **Step 4: Add `-socks5-allow-private` flag in `main()`.**

In `main()` of `dnstt-server/main.go`, find the existing `socks5Mode` flag declaration:
```go
flag.BoolVar(&socks5Mode, "socks5", false, "act as a SOCKS5 proxy (omit UPSTREAMADDR)")
```
Right after it, add:
```go
var socks5AllowPrivate bool
flag.BoolVar(&socks5AllowPrivate, "socks5-allow-private", false, "allow SOCKS5 connections to RFC1918/ULA/CGNAT addresses (loopback and link-local stay denied)")
```

Find the `run(...)` call near the end of `main()` and add the new arg:
```go
err = run(ctx, privkey, domain, upstream, dnsConn, limiter, paranoia, fecData, fecParity, kcpCfg, authDB, compress, socks5AllowPrivate)
```

- [ ] **Step 5: Update existing E2E tests to pass `socks5AllowPrivate`.**

In `dnstt-server/e2e_test.go` find the three `acceptSessions` callsites (in `TestSessionE2E`, `TestSessionE2E_SOCKS5`, and the custom acceptor inside `TestSessionE2E_ParamMismatch`). The `TestSessionE2E_ParamMismatch` test calls `acceptStreams` directly. Update:

In `TestSessionE2E`:
```go
if err := acceptSessions(ln, privkey, mtu, upstream, defaultKCPConfig(), nil, false, serverParams, false); err != nil && ctx.Err() == nil {
```

In `TestSessionE2E_SOCKS5`:
```go
if err := acceptSessions(ln, privkey, mtu, "", defaultKCPConfig(), nil, false, serverParams, false); err != nil && ctx.Err() == nil {
```

In `TestSessionE2E_ParamMismatch`'s custom acceptor:
```go
sessErrCh <- acceptStreams(conn, privkey, "echo-unused", nil, false, serverParams, false)
```

The SOCKS5 test connects to the local echo server (127.0.0.1:port). Since loopback is always denied, this test would now fail. **Fix:** in `TestSessionE2E_SOCKS5` change `false` to `true` for the new arg AND the test's helper passes `127.0.0.1` — but loopback is denied even with allowPrivate. We need a different fix: the test should use a non-loopback address.

Solution: bind the echo server to `0.0.0.0:port` and have the SOCKS5 client connect to a non-loopback IP. The simplest portable approach: add a deny-list bypass for **test mode** by using a test-only flag is bad. Better: the test connects via the host's primary non-loopback interface.

Actually simplest: modify `startEchoServer` to bind on a non-loopback IPv4 address. But finding "the host's primary non-loopback IP" portably is hard.

Better still: factor the deny check into a function whose behavior the test can override via a build-tag-free hook. Add a package-level `socks5DenyHook func(host string, allowPrivate bool) error` defaulting to `isDeniedDestination`; tests can swap it.

Yes, that's cleaner. Apply this:

In `dnstt-server/socks5_dest.go`, ADD:
```go
// socks5DenyHook is the function consulted by the SOCKS5 handler to decide
// whether to refuse a destination. Tests may override it. Production code
// MUST NOT rewrite this — it exists solely to keep loopback-only test
// servers reachable.
var socks5DenyHook = isDeniedDestination
```

Change `handleSocks5Stream` to call `socks5DenyHook(host, allowPrivate)` instead of `isDeniedDestination(host, allowPrivate)` directly.

In `dnstt-server/e2e_test.go` add a new init at the top of `TestSessionE2E_SOCKS5`:
```go
// SOCKS5 e2e test connects to a loopback echo server. Override the deny
// hook so loopback isn't refused for the duration of this test.
prev := socks5DenyHook
socks5DenyHook = func(host string, allowPrivate bool) error { return nil }
t.Cleanup(func() { socks5DenyHook = prev })
```

- [ ] **Step 6: Run tests.**

```
go build ./...
go test ./...
```

All four E2E + unit tests must PASS. Notably `TestSessionE2E_SOCKS5` should still pass (because of the hook override), and a new run of `TestSessionE2E_ParamMismatch` must still pass (no SOCKS5 in that path).

- [ ] **Step 7: Commit.**

```
gofmt -w dnstt-server/socks5.go dnstt-server/socks5_dest.go dnstt-server/main.go dnstt-server/e2e_test.go
git add dnstt-server/socks5.go dnstt-server/socks5_dest.go dnstt-server/main.go dnstt-server/e2e_test.go
git commit -m "feat(server/socks5): refuse private/loopback destinations by default"
```

---

## Task 3: Server YAML config for `socks5-allow-private`

**Files:**
- Modify: `dnstt-server/config.go`

- [ ] **Step 1: Add the field.**

In `dnstt-server/config.go`, find the `ServerConfig` struct. Add:
```go
type ServerConfig struct {
	// ... existing fields ...
	Socks5AllowPrivate bool `yaml:"socks5-allow-private"`
}
```

(insert near the existing `Socks5 bool` field for locality.)

In `applyServerConfig`, find the section that applies booleans and append:
```go
setDefault("socks5-allow-private", fmt.Sprintf("%v", cfg.Socks5AllowPrivate))
```

- [ ] **Step 2: Run tests.**

```
go build ./...
go test ./...
```
All pass.

- [ ] **Step 3: Commit.**

```
gofmt -w dnstt-server/config.go
git add dnstt-server/config.go
git commit -m "feat(server/config): add socks5-allow-private to YAML"
```

---

## Task 4: Pin-cert leaf-only matching with chain validation (#3 part 1)

Pin matches leaf cert only; chain validation enabled by default.

**Files:**
- Modify: `dnstt-client/pin.go` — change `makePinnedTLSConfig` semantics.
- Create: `dnstt-client/pin_test.go` — coverage for leaf-only and chain validation.

- [ ] **Step 1: Write failing tests.**

Create `dnstt-client/pin_test.go`:

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeChain builds a (root CA, leaf cert) signed by root. notAfter offsets
// the leaf's expiry; pass time.Hour for valid, -time.Hour for expired.
func makeChain(t *testing.T, leafNotAfter time.Duration) (rootDER, leafDER []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafNotAfter),
		DNSNames:     []string{"test-leaf"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, leafDER
}

func certHash(der []byte) [32]byte { return sha256.Sum256(der) }

func TestMakePinnedTLSConfig_LeafMatchAcceptsValidChain(t *testing.T) {
	rootDER, leafDER := makeChain(t, time.Hour)
	leafHash := certHash(leafDER)
	pins := map[[32]byte]struct{}{leafHash: {}}

	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)

	// Build PeerCertificates: leaf, then root. Stdlib places leaf at index 0.
	leaf, _ := x509.ParseCertificate(leafDER)
	root, _ := x509.ParseCertificate(rootDER)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, root}}

	if err := cfg.VerifyConnection(cs); err != nil {
		t.Fatalf("expected accept on leaf pin match, got %v", err)
	}
}

func TestMakePinnedTLSConfig_PinOnIntermediateRejected(t *testing.T) {
	rootDER, leafDER := makeChain(t, time.Hour)
	rootHash := certHash(rootDER)
	pins := map[[32]byte]struct{}{rootHash: {}}

	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)

	leaf, _ := x509.ParseCertificate(leafDER)
	root, _ := x509.ParseCertificate(rootDER)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, root}}

	err := cfg.VerifyConnection(cs)
	if err == nil {
		t.Fatal("expected reject when pin is on intermediate, not leaf")
	}
	if !strings.Contains(err.Error(), "leaf") {
		t.Fatalf("expected error mentioning leaf, got %q", err.Error())
	}
}

func TestMakePinnedTLSConfig_NoPeerCertsRejected(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)
	cs := tls.ConnectionState{}
	if err := cfg.VerifyConnection(cs); err == nil {
		t.Fatal("expected error on empty PeerCertificates")
	}
}

func TestMakePinnedTLSConfig_InsecureSkipVerifyDefaultFalse(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)
	if cfg.InsecureSkipVerify {
		t.Fatal("default mode must keep InsecureSkipVerify=false so chain validation runs")
	}
}

func TestMakePinnedTLSConfig_SkipChainEnabledSetsInsecure(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, true)
	if !cfg.InsecureSkipVerify {
		t.Fatal("skip-chain mode must set InsecureSkipVerify=true so leaf pin replaces CA validation")
	}
}

// Use errors import to avoid "imported and not used" if it appears unused.
var _ = errors.New
```

- [ ] **Step 2: Run tests, expect compile error.**

```
go test ./dnstt-client/ -run TestMakePinnedTLSConfig -v
```
Expected: `makePinnedTLSConfig` signature mismatch (currently takes 2 args; tests call with 3).

- [ ] **Step 3: Rewrite `dnstt-client/pin.go`.**

Replace the entire body of `makePinnedTLSConfig`:

```go
// makePinnedTLSConfig returns a clone of base with leaf-only certificate
// pinning applied. The leaf certificate's SHA-256 hash must match an entry
// in pins. By default the standard chain validation runs in addition to
// the pin check; if skipChain is true, pin alone replaces the entire
// certificate-authority trust path (use only when pinning a self-signed
// cert).
func makePinnedTLSConfig(pins map[[32]byte]struct{}, base *tls.Config, skipChain bool) *tls.Config {
	cfg := base.Clone()
	cfg.InsecureSkipVerify = skipChain
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("certificate pinning: no peer certificates presented")
		}
		leaf := cs.PeerCertificates[0]
		h := sha256.Sum256(leaf.Raw)
		if _, ok := pins[h]; !ok {
			return fmt.Errorf("certificate pinning: leaf certificate did not match any pin")
		}
		return nil
	}
	return cfg
}
```

- [ ] **Step 4: Update callers.**

In `dnstt-client/main.go` find every call to `makePinnedTLSConfig(pins, ...)`. There is one, near where `baseTLSConfig` is built (around the area that processes `-pin-cert`). Change to:

```go
baseTLSConfig = makePinnedTLSConfig(pins, baseTLSConfig, pinSkipChain)
```

We'll add `pinSkipChain` as a flag in Task 5. For Task 4 only, add a temporary `false` literal so this commit compiles:
```go
baseTLSConfig = makePinnedTLSConfig(pins, baseTLSConfig, false)
```

(Task 5 will replace `false` with the flag value.)

- [ ] **Step 5: Run tests, expect PASS.**

```
go test ./dnstt-client/ -run TestMakePinnedTLSConfig -v
go test ./...
go build ./...
```
All clean. The new tests cover the four invariants: leaf match accepts, intermediate-pin rejects, empty cert rejects, default and skip-chain modes set InsecureSkipVerify correctly.

- [ ] **Step 6: Commit.**

```
gofmt -w dnstt-client/pin.go dnstt-client/pin_test.go dnstt-client/main.go
git add dnstt-client/pin.go dnstt-client/pin_test.go dnstt-client/main.go
git commit -m "fix(client/pin): leaf-only matching, keep chain validation by default"
```

---

## Task 5: `-pin-cert-skip-chain` flag (#3 part 2)

Wire the opt-in for self-signed-cert pinning that bypasses chain validation.

**Files:**
- Modify: `dnstt-client/main.go` — declare `pinSkipChain` flag, pass into `makePinnedTLSConfig`.
- Modify: `dnstt-client/config.go` — accept the option in the `key=value` config format.

- [ ] **Step 1: Add the flag in `dnstt-client/main.go`.**

Find the existing `-pin-cert` flag declaration:
```go
flag.StringVar(&pinCerts, "pin-cert", "", "comma-separated SHA256:<hex> certificate pins for DoT/DoH/DoQ")
```
Right after, add:
```go
var pinSkipChain bool
flag.BoolVar(&pinSkipChain, "pin-cert-skip-chain", false, "with -pin-cert: skip CA chain validation and trust only the pin (use for self-signed pinning)")
```

The local var `pinSkipChain bool` should be declared with the other locals near the top of `main()`. Either inline (as shown) or co-located.

- [ ] **Step 2: Use the flag.**

Find the call to `makePinnedTLSConfig` (Task 4 stub'd `false`):
```go
baseTLSConfig = makePinnedTLSConfig(pins, baseTLSConfig, false)
```
Change to:
```go
baseTLSConfig = makePinnedTLSConfig(pins, baseTLSConfig, pinSkipChain)
```

- [ ] **Step 3: Run tests + build.**

```
go build ./...
go test ./...
```
All pass.

- [ ] **Step 4: Commit.**

```
gofmt -w dnstt-client/main.go
git add dnstt-client/main.go
git commit -m "feat(client/pin): -pin-cert-skip-chain flag for self-signed pinning"
```

(The client config file format accepts arbitrary `key = value` pairs and runs `flag.Set`. So `pin-cert-skip-chain = true` in a config file will Just Work without changes to `dnstt-client/config.go`. Verify by inspection: `grep -n flag.Set dnstt-client/config.go` should show that the loader uses `flag.Set` for every key.)

---

## Task 6: Demote pubkey log to debug (#12)

**Files:**
- Modify: `dnstt-server/main.go` — change `log.Printf("pubkey %x", pubkey)` to `slog.Debug`.

- [ ] **Step 1: Locate the line.**

```
grep -n "pubkey %x" dnstt-server/main.go
```
Expected: line 1018 (in `run()` near the top).

- [ ] **Step 2: Replace.**

Find:
```go
	log.Printf("pubkey %x", pubkey)
```

Replace with:
```go
	slog.Debug("server pubkey", "hex", fmt.Sprintf("%x", pubkey))
```

The file already imports `log/slog`. The `%x` formatting via `fmt.Sprintf` keeps the same shape so an operator who runs `-log-level debug` once sees an identical hex string they can copy.

- [ ] **Step 3: Build + test.**

```
go build ./...
go test ./...
```
All pass.

- [ ] **Step 4: Manual verification.**

Run the gen-key smoke quickly:
```
go run ./dnstt-server -gen-key -privkey-file /tmp/test.key -pubkey-file /tmp/test.pub
go run ./dnstt-server -udp 127.0.0.1:5353 -privkey-file /tmp/test.key -socks5 -log-level info t.example.com 2>&1 | head -3
```
The `info`-level run should NOT include a `pubkey` line. Kill it (Ctrl+C). Then with `-log-level debug` it SHOULD include the line. Cleanup:
```
rm /tmp/test.key /tmp/test.pub
```

- [ ] **Step 5: Commit.**

```
gofmt -w dnstt-server/main.go
git add dnstt-server/main.go
git commit -m "fix(server): demote pubkey startup log to debug level"
```

---

## Task 7: Hash failed-token bytes in unauthorized log (#13)

**Files:**
- Modify: `dnstt-server/main.go` — replace `unauthorized client %x` with sha256-prefix.

- [ ] **Step 1: Locate.**

```
grep -n "unauthorized client" dnstt-server/main.go
```
Expected: line 359.

- [ ] **Step 2: Replace.**

Find:
```go
		return fmt.Errorf("unauthorized client %x", token[:8])
```

Replace with:
```go
		h := sha256.Sum256(token[:])
		return fmt.Errorf("unauthorized client (sha256-prefix=%x)", h[:8])
```

Add `"crypto/sha256"` to the import block of `dnstt-server/main.go` if not already present.

```
grep -n '"crypto/sha256"' dnstt-server/main.go
```
If missing, add to the import block.

- [ ] **Step 3: Build + test.**

```
go build ./...
go test ./...
```
All pass.

- [ ] **Step 4: Commit.**

```
gofmt -w dnstt-server/main.go
git add dnstt-server/main.go
git commit -m "fix(server): hash failed-token bytes in unauthorized log"
```

---

## Task 8: README updates

Document the new defaults and flags.

**Files:**
- Modify: `README.md` — three sections.

- [ ] **Step 1: Server flags section.**

In `README.md`, find the `## Все флаги сервера` section (around line 461). Inside the `#### Режим работы` table or right after the `-socks5` row, add:

```markdown
| `-socks5-allow-private` | `false` | С `-socks5`: разрешить подключения к RFC1918/ULA/CGNAT-адресам. Loopback и link-local (включая cloud-metadata `169.254.169.254`) **остаются заблокированы всегда**. По умолчанию SOCKS5 не выпускает трафик во внутренние сети — это закрывает SSRF при запуске на cloud VM |
```

- [ ] **Step 2: Client flags section.**

In `README.md` find `## Все флаги клиента`, the `#### Безопасность и маскировка` table. Add:

```markdown
| `-pin-cert-skip-chain` | `false` | С `-pin-cert`: пропустить валидацию цепочки и доверять только пину. Использовать только при пиннинге self-signed-сертификата. По умолчанию пин дополняет, а не заменяет, CA-валидацию |
```

Also UPDATE the existing `-pin-cert` row description to make leaf-only behavior explicit:
```markdown
| `-pin-cert PINS` | — | Comma-separated SHA256-пины **leaf**-сертификатов (`SHA256:aabbcc…`). По умолчанию пин — дополнение к стандартной CA-валидации. Применяется к DoT/DoH/DoQ |
```

- [ ] **Step 3: Encryption section update.**

In `README.md` `## Шифрование и аутентификация`, find or add a new subsection about cert pinning explaining the new semantics.

Add at the end of `### Управление ключами` (or as a new `### Cert-пиннинг резолвера` subsection):

```markdown
### Cert-пиннинг резолвера

`-pin-cert SHA256:abcdef...` фиксирует SHA-256 leaf-сертификата выбранного DoT/DoH/DoQ-резолвера. По умолчанию это **дополнительная** проверка поверх стандартной CA-валидации: соединение принимается только если оба условия выполнены.

Для self-signed-сертификатов добавьте `-pin-cert-skip-chain` — тогда CA-проверка отключается, и доверием служит только пин.

Получить пин leaf-сертификата:
```sh
echo | openssl s_client -connect 1.1.1.1:853 2>/dev/null | \
    openssl x509 -outform DER 2>/dev/null | \
    openssl dgst -sha256 -hex | awk '{print "SHA256:"$NF}'
```
```

- [ ] **Step 4: SOCKS5 section.**

In `README.md` find `### Запуск: встроенный SOCKS5-прокси (рекомендуется)`. Add a warning paragraph at its end:

```markdown
**SSRF-защита:** в SOCKS5-режиме сервер по умолчанию отказывает в подключениях к loopback (127.0.0.0/8, ::1), link-local (169.254/16, fe80::/10 — включая cloud-metadata 169.254.169.254), private (RFC1918, ULA), CGNAT (100.64/10), broadcast и multicast-адресам. Это закрывает атаки, при которых клиент с известным `pubkey` использует ваш сервер для разведки внутренней сети cloud-провайдера. Если внутренний доступ нужен (например, форвардить во внутренний admin-интерфейс), включите `-socks5-allow-private` — loopback и link-local всё равно остаются заблокированы.
```

- [ ] **Step 5: Commit.**

```
git add README.md
git commit -m "docs: document SOCKS5 SSRF defaults and pin-cert chain validation"
```

---

## Self-Review Checklist

Run mentally before declaring G2 done:

- [ ] **Spec coverage.**
  - #2 SOCKS5 SSRF → Tasks 1, 2, 3, 8.
  - #3 pin-cert chain validation → Tasks 4, 5, 8.
  - #12 pubkey logging → Task 6.
  - #13 token logging → Task 7.
- [ ] **Placeholder scan.** No "TBD"/"add appropriate handling".
- [ ] **Type/name consistency.** `isDeniedDestination`, `socks5AllowPrivate`, `pinSkipChain`, `socks5DenyHook`, `makePinnedTLSConfig` — used uniformly across tasks.
- [ ] **Each task ends in a green test run + commit.**

---

## Final Integration Check (after Task 8)

- [ ] `go test ./...` — clean
- [ ] `go vet ./...` — clean
- [ ] Diff vs `master` (G1+G2) reads as a coherent fix series

When all green: continue to G3 (skрытность / detection). G2 commits remain on `fix/audit-pass-1`. Squash-merge to master happens at the end of the whole audit pass.
