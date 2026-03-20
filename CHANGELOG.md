# Changelog

All notable changes to this fork of dnstt are documented here.
The original project lives at <https://www.bamsoftware.com/software/dnstt/>.

## Unreleased

### New features

- **DNS over QUIC (DoQ, RFC 9250)** — new `-doq` transport with per-query
  QUIC streams and 2-byte length-prefix framing; supports the same
  uTLS/cert-pin options as DoT.
- **Auto transport selection** — `-auto` tries DoQ → DoT → DoH → UDP in order
  and picks the first that succeeds; individual transports still configurable
  via their own flags.
- **Multipath** — `-multipath` sends data over multiple transports simultaneously
  (DoH + DoT + UDP); KCP window is automatically raised to 512 to prevent
  head-of-line blocking from transports with different latencies.
- **Built-in SOCKS5 proxy mode** — server `-socks5` flag; each tunnel stream
  performs a SOCKS5 CONNECT handshake so the client chooses the destination.
- **Token authentication** — server `-auth-keys FILE` and client `-auth-token HEX`
  implement a 32-byte pre-shared token layer on top of the Noise handshake;
  both OK and DENIED responses include random padding to avoid a fixed-length
  DPI signature.
- **Per-client rate limiting** — server `-rate-limit` (req/s) and `-rate-burst`
  flags, with automatic purging of stale client entries.
- **zlib stream compression** — `-compress` flag on both sides enables
  per-stream zlib compression; a flush-after-write wrapper prevents buffering
  hangs in interactive sessions (SSH, etc.).
- **KCP tuning presets** — `-kcp-mode fast|normal|slow` on both sides.
- **Forward error correction** — `-fec-data` / `-fec-parity` enable kcp-go's
  built-in Reed-Solomon FEC.
- **ClientID rotation** — client `-rotate-id N` rotates the tunnel identity
  every N minutes to resist long-term traffic correlation.
- **Traffic obfuscation** — client `-obfuscate` sends decoy AAAA queries
  alongside TXT tunnel queries to blend in with normal DNS traffic.
- **Certificate pinning** — `-pin-cert SHA256:<hex>[,...]` for DoT/DoH/DoQ.
- **DoH address override** — `-doh-addr` dials a specific IP:port for the DoH
  server, enabling use when DNS is not available or for cert-pinning.
- **Paranoia mode** — server `-paranoia` returns plausible fake A/AAAA answers
  for non-tunnel queries to hide the presence of the tunnel.
- **Config file** — server `-config FILE` (YAML); client `-config FILE`
  (key=value); CLI flags always override file values.
- **Structured logging** — both binaries use `log/slog` with `-log-level`
  (debug/info/warn/error).
- **Debug HTTP server** — `-debug-addr` on both sides exposes `/debug/vars`
  and `/debug/pprof`.
- **Graceful shutdown** — SIGINT/SIGTERM unblocks the listener and allows
  in-flight streams to complete.
- **Docker** — multi-stage Dockerfile (golang:1.24-alpine → scratch), runs as
  uid 65534 (nobody), drops all capabilities and adds only `NET_BIND_SERVICE`.
  Includes a `docker-compose.yml` for server + keygen.

### Bug fixes

- **AAAA RRset reordering** — DNS resolvers reorder multiple AAAA records in a
  response, corrupting multi-record payloads. Fixed by never encoding data in
  AAAA responses; AAAA queries now act as blend-in polls that return a single
  zeroed record without dequeuing KCP data.
- **Zlib interactive hang** — `zlib.Writer` buffers writes internally; without
  an explicit `Flush()` after each `Write()`, interactive sessions (SSH, etc.)
  stall until the buffer fills. Fixed with a `zlibFlushWriter` wrapper on both
  client and server.
- **Auth token DoS** — a client that completes the Noise handshake but never
  sends the auth token caused a goroutine to block forever, enabling goroutine
  exhaustion. Fixed with a 5-second read deadline on the token read.
- **smux stream limit** — smux has no built-in stream cap. Fixed with a
  100-slot channel semaphore in `acceptStreams`; excess streams are rejected
  immediately.
- **DoT reconnect death** — a `break` in the DoT reconnect loop exited the
  loop permanently on the first reconnect failure. Fixed with a retry-and-
  continue pattern.
- **DoQ reconnect death** — `return` on DoQ dial failure exited the read/write
  goroutines permanently. Fixed with an inner retry loop with exponential
  backoff.
- **SOCKS5 error reply** — RFC 1928 requires the server to send a non-zero REP
  byte before closing on a failed CONNECT. Fixed to send `REP=0x04` (host
  unreachable) before returning the error.
- **applyServerConfig booleans** — YAML `paranoia: false` could not disable a
  flag that defaults to true because the old code skipped zero-value booleans.
  Fixed by always applying boolean fields unconditionally.
- **computeMaxEncodedPayload** — `Class: dns.RRTypeTXT` (wrong constant) in
  the probe query's Question section; corrected to `Class: dns.ClassIN`.
- **Dockerfile Go version** — base image `golang:1.21` cannot build a module
  requiring `go 1.24`. Updated to `golang:1.24-alpine`.
- **Error wrapping** — several `fmt.Errorf` calls used `%v` instead of `%w`,
  preventing `errors.Is`/`errors.As` unwrapping. Fixed throughout.
