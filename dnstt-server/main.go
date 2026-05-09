// dnstt-server is the server end of a DNS tunnel.
//
// Usage:
//
//	dnstt-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	dnstt-server -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN UPSTREAMADDR
//
// Example:
//
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	dnstt-server -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	dnstt-server -gen-key
//	dnstt-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
package main

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	_ "expvar" // register /debug/vars HTTP handler
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // register /debug/pprof HTTP handlers
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	maxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second
)

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			fmt.Fprintf(os.Stderr, "deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				fmt.Fprintf(os.Stderr, "cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey, err := noise.PubkeyFromPrivkey(privkey)
	if err != nil {
		return fmt.Errorf("deriving public key: %v", err)
	}

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// zlibFlushWriter wraps a zlib.Writer and flushes after every Write to
// prevent buffering-induced hangs in interactive sessions (e.g. SSH).
type zlibFlushWriter struct {
	*zlib.Writer
}

func (w *zlibFlushWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil && n > 0 {
		err = w.Writer.Flush()
	}
	return n, err
}

// proxyStreams bidirectionally copies data between a smux Stream and a TCP
// connection until both sides are done. When compress is true, data is
// zlib-compressed on the stream side.
func proxyStreams(stream *smux.Stream, tcpConn *net.TCPConn, conv uint32, compress bool) error {
	var wg sync.WaitGroup
	wg.Add(2)
	if compress {
		enc := &zlibFlushWriter{zlib.NewWriter(stream)}
		dec, decErr := zlib.NewReader(stream)
		if decErr != nil {
			return fmt.Errorf("stream %08x:%d zlib reader: %v", conv, stream.ID(), decErr)
		}
		go func() {
			defer wg.Done()
			_, err := io.Copy(enc, tcpConn)
			if err == io.EOF {
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy stream←upstream (compressed): %v", conv, stream.ID(), err)
			}
			enc.Close()
			tcpConn.CloseRead()
			stream.Close()
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(tcpConn, dec)
			if err == io.EOF {
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy upstream←stream (compressed): %v", conv, stream.ID(), err)
			}
			dec.Close()
			tcpConn.CloseWrite()
		}()
	} else {
		go func() {
			defer wg.Done()
			_, err := io.Copy(stream, tcpConn)
			if err == io.EOF {
				// smux Stream.Write may return io.EOF.
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
			}
			tcpConn.CloseRead()
			stream.Close()
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(tcpConn, stream)
			if err == io.EOF {
				// smux Stream.WriteTo may return io.EOF.
				err = nil
			}
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
			}
			tcpConn.CloseWrite()
		}()
	}
	wg.Wait()
	return nil
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32, compress bool) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn, ok := upstreamConn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("stream %08x:%d upstream connection is not a *net.TCPConn", conv, stream.ID())
	}
	return proxyStreams(stream, upstreamTCPConn, conv, compress)
}

// kcpConfig holds tunable KCP parameters.
type kcpConfig struct {
	nodelay  int
	interval int
	resend   int
	nc       int
	window   int
}

// defaultKCPConfig returns the "normal" KCP configuration.
func defaultKCPConfig() kcpConfig {
	return kcpConfig{nodelay: 0, interval: 50, resend: 2, nc: 1, window: 128}
}

// maxConcurrentStreams is the maximum number of simultaneously open smux
// streams per KCP session. This bounds goroutine and fd usage per client.
const maxConcurrentStreams = 100

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. If upstream is empty, streams are handled as SOCKS5
// proxy connections; otherwise they are forwarded to the upstream address.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string, authDB *authDatabase, compress bool, serverParams handshakeParams, socks5AllowPrivate bool) error {
	// Put a Noise channel on top of the KCP conn.
	rw, clientPayload, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Validate handshake params and (optionally) auth token. Both travel
	// inside the Noise payload, so authentication is atomic with the
	// handshake — a missing or wrong token aborts the connection before
	// any smux processing, eliminating the prior after-Noise read-deadline
	// DoS vector.
	clientParams, clientToken, err := decodeHandshakeParams(clientPayload)
	if err != nil {
		return fmt.Errorf("invalid handshake params: %w", err)
	}
	if err := validateHandshakeParams(clientParams, serverParams); err != nil {
		return err
	}

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

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	// sem bounds the number of concurrent streams to prevent a single
	// client from exhausting goroutines and file descriptors.
	sem := make(chan struct{}, maxConcurrentStreams)

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Printf("session %08x: rejecting stream %d (too many concurrent streams)", conn.GetConv(), stream.ID())
			stream.Close()
			continue
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
				<-sem
			}()
			var err error
			if upstream == "" {
				err = handleSocks5Stream(stream, conn.GetConv(), compress, socks5AllowPrivate)
			} else {
				err = handleStream(stream, upstream, conn.GetConv(), compress)
			}
			if err != nil {
				log.Printf("stream %08x:%d: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string, kcpCfg kcpConfig, authDB *authDatabase, compress bool, serverParams handshakeParams, socks5AllowPrivate bool) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		metricSessions.Add(1)
		metricActiveSessions.Add(1)
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		conn.SetNoDelay(kcpCfg.nodelay, kcpCfg.interval, kcpCfg.resend, kcpCfg.nc)
		conn.SetWindowSize(kcpCfg.window, kcpCfg.window)
		if !conn.SetMtu(mtu) {
			log.Printf("warning: session %08x SetMtu(%d) failed", conn.GetConv(), mtu)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				metricActiveSessions.Add(-1)
				conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream, authDB, compress, serverParams, socks5AllowPrivate)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

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

// rebuildAsTruncated converts an oversized DNS response into a valid
// truncated reply: Question preserved, Answer/Authority cleared, TC=1.
// If the result still exceeds limit (long Question name + EDNS OPT),
// EDNS OPT is dropped too.
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
		// WireFormat shouldn't fail with just header+Question, but if it
		// does, return whatever we got — the caller's len-check still
		// guards the wire write.
		return buf
	}
	return buf
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response
// to this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
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

	// EDNS(0) parsing — same as prior behavior.
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

	resp.Flags |= 0x0400 // AA=1

	// Apex (no labels before the suffix). Structural responses fit easily in
	// 512 bytes, so we answer regardless of EDNS payload size — a real
	// authoritative NS responds to non-EDNS queries, and FORMERR-on-missing-OPT
	// is a strong fingerprint that this is not one.
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
	// NXDOMAIN+SOA also fits in 512 bytes, so it answers regardless of EDNS.
	if question.Type != dns.RRTypeTXT && question.Type != dns.RRTypeAAAA {
		resp.Flags |= dns.RcodeNameError
		resp.Authority = []dns.RR{zone.soa}
		return resp, nil
	}

	// Tunnel-bearing path: TXT data responses can exceed the requester's
	// stated payload size. Refuse with FORMERR rather than risk truncation
	// of in-band tunnel data. AAAA blend responses are small but share the
	// path for simplicity; tunnel clients always advertise EDNS anyway.
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, maxUDPPayload)
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

	// AAAA blend-in poll: tunnel data may flow via QNAME (caller extracts
	// payload from the second return value), but AAAA responses never carry
	// downstream payload — they look like "no AAAA record exists for this
	// name", which is what a real auth NS would return.
	if question.Type == dns.RRTypeAAAA {
		resp.Authority = []dns.RR{zone.soa}
		// Validate payload length so a malformed query still returns NXDOMAIN+SOA.
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

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch.
func recvLoop(zone zoneInfo, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *record, limiter *clientRateLimiter) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		metricQueries.Add(1)
		resp, payload := responseFor(&query, zone)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		if payload != nil {
			// responseFor returned a tunnel-bearing payload candidate.
			// Try to extract the ClientID and feed packets to KCP. If
			// the payload is too short, override the NOERROR response
			// with NXDOMAIN+SOA so a probe won't see "we accept any
			// garbage at this name". When payload is nil, the response
			// is already a complete structural answer (apex SOA/NS,
			// apex NOERROR no-data, REFUSED, etc.) and must not be
			// tampered with here.
			n = copy(clientID[:], payload)
			payload = payload[n:]
			if n == len(clientID) {
				// Apply per-client rate limiting if enabled.
				if limiter != nil && !limiter.Allow(clientID) {
					metricRateLimited.Add(1)
					if resp != nil {
						select {
						case ch <- &record{resp, addr, clientID}:
						default:
						}
					}
					continue
				}
				// Discard padding and pull out the packets contained in
				// the payload.
				r := bytes.NewReader(payload)
				for {
					p, err := nextPacket(r)
					if err != nil {
						break
					}
					// Feed the incoming packet to KCP.
					ttConn.QueueIncoming(p, clientID)
				}
			} else {
				// Payload is too short to contain a ClientID. responseFor
				// already handled this for AAAA (returned NXDOMAIN+SOA);
				// for TXT, we convert the would-be NOERROR into NXDOMAIN
				// here and ensure Authority has SOA.
				if resp != nil && resp.Rcode() == dns.RcodeNoError && len(resp.Answer) == 0 {
					resp.Flags = (resp.Flags &^ 0xf) | dns.RcodeNameError
					if len(resp.Authority) == 0 {
						resp.Authority = []dns.RR{zone.soa}
					}
					log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
				}
			}
		}
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID}:
			default:
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under maxEncodedPayload, then sends it.
func sendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *record, maxEncodedPayload int) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.
			qname := rec.Resp.Question[0].Name
			qtype := rec.Resp.Question[0].Type
			qclass := rec.Resp.Question[0].Class

			if qtype == dns.RRTypeTXT && len(rec.Resp.Answer) == 0 {
				// TXT tunnel response: gather as many KCP packets as
				// fit, encode them in TXT RDATA. Apex SOA/NS responses
				// already have Answer filled by responseFor and skip
				// this branch. AAAA blend-poll responses keep their
				// empty Answer + SOA-in-Authority (set by responseFor)
				// and pass through unchanged. Apex A/MX/etc. fall
				// through with empty Answer + SOA in Authority and
				// pass through unchanged.
				var payload bytes.Buffer
				limit := maxEncodedPayload
				// We loop and bundle as many packets from OutgoingQueue
				// into the response as will fit. Any packet that would
				// overflow the capacity of the DNS response, we stash
				// to be bundled into a future response.
				timer := time.NewTimer(maxResponseDelay)
				for {
					var p []byte
					unstash := ttConn.Unstash(rec.ClientID)
					outgoing := ttConn.OutgoingQueue(rec.ClientID)
					// Prioritize taking a packet first from the
					// stash, then from the outgoing queue, then
					// finally check for the expiration of the timer
					// or for a receive on ch (indicating a new
					// query that we must respond to).
					select {
					case p = <-unstash:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						default:
							select {
							case p = <-unstash:
							case p = <-outgoing:
							case <-timer.C:
							case nextRec = <-ch:
							}
						}
					}
					// We wait for the first packet in a bundle
					// only. The second and later packets must be
					// immediately available or they will be omitted
					// from this bundle.
					timer.Reset(0)

					if len(p) == 0 {
						// timer expired or receive on ch, we
						// are done with this response.
						break
					}

					limit -= 2 + len(p)
					if payload.Len() == 0 {
						// No packet length check for the first
						// packet; if it's too large, we allow
						// it to be truncated and dropped by the
						// receiver.
					} else if limit < 0 {
						// Stash this packet to send in the next
						// response.
						ttConn.Stash(p, rec.ClientID)
						break
					}
					if len(p) > 0xffff {
						log.Printf("sendLoop: dropping oversized packet of %d bytes", len(p))
						metricDropped.Add(1)
						continue
					}
					binary.Write(&payload, binary.BigEndian, uint16(len(p)))
					payload.Write(p)
				}
				timer.Stop()

				// Any changes to how TXT responses are built need to
				// happen also in computeMaxEncodedPayload.
				rec.Resp.Answer = []dns.RR{
					{
						Name:  qname,
						Type:  qtype,
						Class: qclass,
						TTL:   responseTTL,
						Data:  dns.EncodeRDataTXT(payload.Bytes()),
					},
				}
			}
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if len(buf) > maxUDPPayload {
			metricTruncated.Add(1)
			if shouldLogTruncate() {
				log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
			}
			buf = rebuildAsTruncated(rec.Resp, maxUDPPayload)
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			return err
		}
	}
	return nil
}

// computeMaxEncodedPayload computes the maximum amount of downstream TXT RR
// data that keep the overall response size less than maxUDPPayload, in the
// worst case when the response answers a query that has a maximum-length name
// in its Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int) int {
	limit -= 64 // safety margin against amplification detection
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  dns.RRTypeTXT,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	resp, _ := responseFor(query, newZoneInfo(dns.Name{}))
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := low + (high-low)/2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

func run(ctx context.Context, privkey []byte, zone zoneInfo, upstream string, dnsConn net.PacketConn, limiter *clientRateLimiter, fecData, fecParity int, kcpCfg kcpConfig, authDB *authDatabase, compress bool, socks5AllowPrivate bool) error {
	serverParams, err := newHandshakeParamsFromInts(fecData, fecParity, compress)
	if err != nil {
		return err
	}
	defer dnsConn.Close()

	// Close the DNS conn when the context is cancelled to unblock recvLoop.
	go func() {
		<-ctx.Done()
		dnsConn.Close()
	}()

	pubkey, err := noise.PubkeyFromPrivkey(privkey)
	if err != nil {
		return fmt.Errorf("deriving public key: %v", err)
	}
	slog.Debug("server pubkey", "hex", fmt.Sprintf("%x", pubkey))

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// global maximum which no packet will exceed. We choose that maximum to
	// keep the UDP payload size under maxUDPPayload, even in the worst case
	// of a maximum-length name in the query's Question section.
	maxEncodedPayload := computeMaxEncodedPayload(maxUDPPayload)
	// 2 bytes accounts for a packet length prefix.
	mtu := maxEncodedPayload - 2
	if mtu < 80 {
		if mtu < 0 {
			mtu = 0
		}
		return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload", maxUDPPayload, mtu)
	}
	log.Printf("effective MTU %d", mtu)

	// Start up the virtual PacketConn for turbotunnel.
	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
	ln, err := kcp.ServeConn(nil, fecData, fecParity, ttConn)
	if err != nil {
		return fmt.Errorf("opening KCP listener: %v", err)
	}
	defer ln.Close()
	go func() {
		err := acceptSessions(ln, privkey, mtu, upstream, kcpCfg, authDB, compress, serverParams, socks5AllowPrivate)
		if err != nil {
			log.Printf("acceptSessions: %v", err)
		}
	}()

	ch := make(chan *record, 100)
	defer close(ch)

	// We could run multiple copies of sendLoop; that would allow more time
	// for each response to collect downstream data before being evicted by
	// another response that needs to be sent.
	go func() {
		err := sendLoop(dnsConn, ttConn, ch, maxEncodedPayload)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	return recvLoop(zone, dnsConn, ttConn, ch, limiter)
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var udpAddr string
	var socks5Mode bool
	var rateLimit float64
	var rateBurst int
	var debugAddr string
	var fecData, fecParity int
	var kcpMode string
	var compress bool
	var configFile string
	var authKeysFile string
	logLevel := new(slog.LevelVar) // default INFO

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
  %[1]s -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] [-socks5] DOMAIN [UPSTREAMADDR]

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
  %[1]s -udp :53 -privkey-file server.key -socks5 t.example.com

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (required)")
	flag.BoolVar(&socks5Mode, "socks5", false, "act as a SOCKS5 proxy (omit UPSTREAMADDR)")
	var socks5AllowPrivate bool
	flag.BoolVar(&socks5AllowPrivate, "socks5-allow-private", false, "allow SOCKS5 connections to RFC1918/ULA/CGNAT addresses (loopback and link-local stay denied)")
	flag.Float64Var(&rateLimit, "rate-limit", 0, "maximum DNS queries per second per client (0 = unlimited)")
	flag.IntVar(&rateBurst, "rate-burst", 50, "burst size for -rate-limit")
	flag.StringVar(&debugAddr, "debug-addr", "", "address for debug HTTP server exposing /debug/vars and /debug/pprof")
	flag.IntVar(&fecData, "fec-data", 0, "FEC data shards (0 = disabled)")
	flag.IntVar(&fecParity, "fec-parity", 0, "FEC parity shards (0 = disabled)")
	flag.StringVar(&kcpMode, "kcp-mode", "normal", "KCP tuning mode: fast, normal, slow")
	flag.BoolVar(&compress, "compress", false, "enable zlib compression on streams")
	flag.StringVar(&configFile, "config", "", "path to YAML config file")
	flag.StringVar(&authKeysFile, "auth-keys", "", "file containing authorized 32-byte hex tokens (one per line)")
	flag.Func("log-level", `minimum log level: debug, info, warn, error (default "info")`, func(s string) error {
		return logLevel.UnmarshalText([]byte(s))
	})

	// Two-phase parse: pre-scan for -config to load it before flag.Parse().
	for i, arg := range os.Args[1:] {
		if arg == "-config" || arg == "--config" {
			if i+1 < len(os.Args[1:]) {
				configFile = os.Args[i+2]
			}
		} else if strings.HasPrefix(arg, "-config=") {
			configFile = strings.TrimPrefix(arg, "-config=")
		} else if strings.HasPrefix(arg, "--config=") {
			configFile = strings.TrimPrefix(arg, "--config=")
		}
	}
	if configFile != "" {
		cfg, err := loadServerConfig(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config file: %v\n", err)
			os.Exit(1)
		}
		applyServerConfig(cfg)
	}

	flag.Parse()

	// Set up structured logging. slog.SetDefault also redirects log.Printf
	// calls through the slog handler, enabling level filtering for all output.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
			}
			return a
		},
	})))

	if debugAddr != "" {
		go func() {
			log.Printf("debug HTTP server listening on %s", debugAddr)
			if err := http.ListenAndServe(debugAddr, nil); err != nil {
				log.Printf("debug server: %v", err)
			}
		}()
	}

	if genKey {
		// -gen-key mode.
		if flag.NArg() != 0 || privkeyString != "" || udpAddr != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.
		expectedArgs := 2
		if socks5Mode {
			expectedArgs = 1
		}
		if flag.NArg() != expectedArgs {
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}

		var upstream string
		if !socks5Mode {
			upstream = flag.Arg(1)
			// We keep upstream as a string in order to eventually pass
			// it to net.Dial in handleStream. But for the sake of
			// displaying an error or warning at startup, rather than
			// only when the first stream occurs, we apply some parsing
			// and name resolution checks here.
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: %v\n", upstream, err)
				os.Exit(1)
			}
			upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
			if err != nil {
				log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
			} else if upstreamIPAddr.IP == nil {
				fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: missing host in address\n", upstream)
				os.Exit(1)
			}
			// Do a quick connectivity probe so problems surface at
			// startup rather than silently on the first client stream.
			probeConn, probeErr := net.DialTimeout("tcp", upstream, 5*time.Second)
			if probeErr != nil {
				log.Printf("warning: upstream %s is not reachable: %v", upstream, probeErr)
			} else {
				probeConn.Close()
			}
		}

		if udpAddr == "" {
			fmt.Fprintf(os.Stderr, "the -udp option is required\n")
			os.Exit(1)
		}
		dnsConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening UDP listener: %v\n", err)
			os.Exit(1)
		}

		if pubkeyFilename != "" {
			fmt.Fprintf(os.Stderr, "-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			fmt.Fprintf(os.Stderr, "only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		var limiter *clientRateLimiter
		if rateLimit > 0 {
			limiter = newClientRateLimiter(rateLimit, rateBurst)
			log.Printf("rate limiting: %.1f req/s per client, burst %d", rateLimit, rateBurst)
			// Periodically purge stale client entries.
			go func() {
				ticker := time.NewTicker(idleTimeout)
				defer ticker.Stop()
				for range ticker.C {
					limiter.Purge(idleTimeout * 2)
				}
			}()
		}

		// Parse KCP mode.
		kcpCfg := defaultKCPConfig()
		switch kcpMode {
		case "fast":
			kcpCfg = kcpConfig{nodelay: 1, interval: 20, resend: 2, nc: 1, window: 256}
		case "normal":
			kcpCfg = kcpConfig{nodelay: 0, interval: 50, resend: 2, nc: 1, window: 128}
		case "slow":
			kcpCfg = kcpConfig{nodelay: 0, interval: 100, resend: 0, nc: 0, window: 64}
		default:
			fmt.Fprintf(os.Stderr, "unknown -kcp-mode %q: must be fast, normal, or slow\n", kcpMode)
			os.Exit(1)
		}

		// Load auth keys if specified.
		var authDB *authDatabase
		if authKeysFile != "" {
			var err error
			authDB, err = loadAuthKeysFile(authKeysFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "loading auth keys: %v\n", err)
				os.Exit(1)
			}
			log.Printf("auth: loaded %d keys from %s", authDB.Len(), authKeysFile)
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		zone := newZoneInfo(domain)
		err = run(ctx, privkey, zone, upstream, dnsConn, limiter, fecData, fecParity, kcpCfg, authDB, compress, socks5AllowPrivate)
		if err != nil && ctx.Err() == nil {
			log.Fatal(err)
		}
	}
}
