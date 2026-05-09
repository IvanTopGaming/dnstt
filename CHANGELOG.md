# Changelog

All notable changes to this fork of dnstt are documented here.
The original project lives at <https://www.bamsoftware.com/software/dnstt/>.

## [2.1.0] - 2026-05-09

First tagged release of the IvanTopGaming fork. Includes the full set of
transport, authentication, and operational features accumulated since the
upstream baseline, plus the audit-pass-1 hardening series.

### New features

- **DNS over QUIC (DoQ, RFC 9250)** — new `-doq` transport with per-query
  QUIC streams and 2-byte length-prefix framing; supports the same
  uTLS/cert-pin options as DoT.
- **Auto transport selection** — `-auto` tries DoQ → DoT → DoH → UDP in order
  and picks the first that succeeds; individual transports still configurable
  via their own flags.
- **Multipath** — `-multipath` sends data over multiple transports
  simultaneously (DoH + DoT + UDP); KCP window is automatically raised to 512
  to prevent head-of-line blocking from transports with different latencies.
  A single ClientID is shared across all transports so the server sees one
  tunnel.
- **Built-in SOCKS5 proxy mode** — server `-socks5` flag; each tunnel stream
  performs a SOCKS5 CONNECT handshake so the client chooses the destination.
  Built-in deny-list refuses loopback, link-local (cloud metadata), broadcast,
  multicast, and unspecified destinations; RFC1918/ULA/CGNAT denied by default,
  permitted via `-socks5-allow-private`. Hostnames (ATYP=0x03) are
  pre-resolved and each resulting IP is rechecked — defeats DNS-rebinding /
  hostname-based SSRF.
- **Token authentication** — server `-auth-keys FILE` and client
  `-auth-token HEX` implement a 32-byte pre-shared token layer carried
  *inside* the Noise handshake payload (atomic with key establishment).
  Server logs failed attempts with a SHA-256 prefix only — never the raw
  token. Both OK and DENIED responses include random padding to avoid a
  fixed-length DPI signature.
- **Per-client rate limiting** — server `-rate-limit` (req/s) and
  `-rate-burst` flags, with automatic purging of stale client entries.
- **zlib stream compression** — `-compress` flag on both sides; matched
  value is enforced via Noise handshake parameter validation. A
  flush-after-write wrapper prevents buffering hangs in interactive sessions
  (SSH, etc.).
- **KCP tuning presets** — `-kcp-mode fast|normal|slow` on both sides.
- **Forward error correction** — `-fec-data` / `-fec-parity` enable
  kcp-go's built-in Reed-Solomon FEC; matched values enforced via Noise
  handshake.
- **ClientID rotation** — client `-rotate-id N` rotates the tunnel identity
  every N minutes to resist long-term traffic correlation.
- **Certificate pinning** — `-pin-cert SHA256:<hex>[,...]` for DoT/DoH/DoQ.
  Matches against the leaf certificate's SHA-256 only; chain validation runs
  in addition by default. `-pin-cert-skip-chain` opts into self-signed
  pinning where the pin alone replaces the CA trust path.
- **DoH address override** — `-doh-addr` dials a specific IP:port for the
  DoH server, enabling use when DNS is not available or for cert-pinning.
- **Config file** — server `-config FILE` (YAML); client `-config FILE`
  (key=value); CLI flags always override file values.
- **Structured logging** — both binaries use `log/slog` with `-log-level`
  (debug/info/warn/error).
- **Debug HTTP server** — `-debug-addr` on both sides exposes `/debug/vars`
  and `/debug/pprof`.
- **Graceful shutdown** — SIGINT/SIGTERM unblocks the listener and allows
  in-flight streams to complete.
- **Docker** — multi-stage Dockerfile (golang:1.24-alpine → scratch), runs
  as uid 65534 (nobody), drops all capabilities and adds only
  `NET_BIND_SERVICE`. Includes a `docker-compose.yml` for server + keygen.

### Stealth — server behaves as an authoritative NS for its zone

- **Synthesized SOA and NS records** — apex `SOA`, `NS`, and any other
  structural query type returns NOERROR with the appropriate answer or empty
  Answer + SOA in Authority. Replies set AA=1.
- **REFUSED for queries outside the zone** — out-of-zone questions get
  RCODE=REFUSED with AA=0, matching real auth-NS behaviour.
- **NXDOMAIN with SOA in Authority** — non-existent under-apex names that
  are not tunnel-bearing types (TXT/AAAA) return NXDOMAIN + SOA, the
  standard shape for a real auth NS.
- **AAAA blend-poll** — AAAA queries used as tunnel polls return NOERROR
  with empty Answer and SOA in Authority; no synthetic IPv6 address is ever
  placed in Answer (no `::` leak).
- **Apex / NXDOMAIN answer regardless of EDNS** — structural responses
  (SOA/NS/NXDOMAIN+SOA) are returned for non-EDNS queries
  (`dig +noedns ...`); the FORMERR-on-small-payload check now only fires
  on the tunnel-bearing TXT/AAAA path where responses can exceed the
  requester's stated payload.
- **Truncated UDP wire format preserved** — when a UDP response exceeds the
  requester's payload size, the server rebuilds it with TC=1 and preserves
  the Authority section (degrading via OPT-drop fallback only when needed),
  rather than slicing the wire mid-RR.

### Bug fixes

- **AAAA RRset reordering** — DNS resolvers reorder multiple AAAA records
  in a response, corrupting multi-record payloads. Fixed by never encoding
  data in AAAA responses; AAAA queries now act as blend-in polls that
  return a single empty record without dequeuing KCP data.
- **Zlib interactive hang** — `zlib.Writer` buffers writes internally;
  without an explicit `Flush()` after each `Write()`, interactive sessions
  (SSH, etc.) stall until the buffer fills. Fixed with a `zlibFlushWriter`
  wrapper.
- **smux stream limit** — smux has no built-in stream cap. Fixed with a
  100-slot channel semaphore in `acceptStreams`; excess streams are
  rejected immediately.
- **DoT reconnect death** — a `break` in the DoT reconnect loop exited the
  loop permanently on the first reconnect failure. Fixed with a
  retry-and-continue pattern.
- **DoQ reconnect death** — `return` on DoQ dial failure exited the
  read/write goroutines permanently. Fixed with an inner retry loop with
  exponential backoff.
- **SOCKS5 error reply** — RFC 1928 requires the server to send a non-zero
  REP byte before closing on a failed CONNECT. Fixed to send `REP=0x04`
  (host unreachable) before returning the error.
- **`computeMaxEncodedPayload`** — `Class: dns.RRTypeTXT` (wrong constant)
  in the probe query's Question section; corrected to `Class: dns.ClassIN`.
- **Dockerfile Go version** — base image `golang:1.21` cannot build a
  module requiring `go 1.24`. Updated to `golang:1.24-alpine`.
- **Error wrapping** — several `fmt.Errorf` calls used `%v` instead of
  `%w`, preventing `errors.Is`/`errors.As` unwrapping. Fixed throughout.

### Audit pass 1 — correctness, security, stealth, auth-UX

- **G1 — Multipath ClientID & Close discipline** — round-robin index uses
  `atomic.Uint64` (no `Int64` overflow); `Close` is `sync.Once`-idempotent
  and waits on a reader `WaitGroup`;
  `SetDeadline` / `SetReadDeadline` / `SetWriteDeadline` propagate to all
  underlying conns; readers signal `io.EOF` on exhaustion via a
  last-reader-closes-recvCh idiom.
- **G1 — Handshake parameter codec** — Noise handshake payload now carries
  FEC (`fec-data` / `fec-parity`), `compress`, and the auth token in a
  single validated codec. Reserved bits in the flags byte are rejected.
  Param mismatch is logged on the server with full client/server values
  and the session is refused with a single error line.
- **G1 — UDP truncation rebuild** — the rebuild chain (preserve Authority
  → drop OPT → strip Authority → bare TC=1) is exercised in unit tests
  and never produces a truncated wire format mid-RR.
- **G2 — SOCKS5 destination filter** — IP-literal targets are checked
  against loopback / link-local / broadcast / multicast / unspecified /
  RFC1918 / ULA / CGNAT classes; v4-in-v6 mapped form (`::ffff:127.0.0.1`)
  is unmapped before classification. Hostnames (ATYP=0x03) are
  pre-resolved and *every* resolved IP is rechecked through the deny-list;
  the entire connection is refused if any one is denied (fail-closed
  against DNS-rebinding / round-robin SSRF). The dialer connects to the
  resolved literal — not the original hostname — closing the TOCTOU
  window.
- **G2 — Pin-cert leaf-only matching** — pin matches the leaf
  certificate's SHA-256 only; chain validation runs in addition by
  default. `-pin-cert-skip-chain` is the opt-in for self-signed pinning.
- **G2 — Log redaction** — failed auth attempts log a SHA-256 prefix of
  the presented token, never the raw bytes. The startup pubkey log line
  is demoted to debug level.
- **G3 — Authoritative NS behaviour** — synthesized SOA/NS, REFUSED for
  out-of-zone, NXDOMAIN+SOA for under-apex non-tunnel types, AAAA blend
  without `::` leak. See *Stealth* section above.
- **G4 — Auth token in Noise handshake** — the auth token now travels
  inside the Noise handshake payload, encrypted under the server's static
  key. Replaces the previous post-handshake token round-trip; the 5-second
  read-deadline DoS workaround is no longer needed.

### Removed

- **`-paranoia` (server)** — replaced by the synthesized SOA/NS responses
  and `REFUSED` for out-of-zone queries, which match real authoritative NS
  behaviour. The previous "fake A/AAAA on non-tunnel queries" was itself a
  fingerprint.
- **`-obfuscate` (client)** — decoy AAAA queries were themselves a
  fingerprint and provided no measurable benefit.

## Unreleased

(no changes since 2.1.0)

[2.1.0]: https://github.com/IvanTopGaming/dnstt/releases/tag/v2.1.0
