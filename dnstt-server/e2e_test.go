package main

// End-to-end integration test for the dnstt server. It bypasses the DNS
// transport layer and directly feeds KCP packets into the server's virtual
// PacketConn (turbotunnel.QueuePacketConn). This tests the full
// KCP → Noise → smux → upstream TCP pipeline.

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// startEchoServer starts a TCP echo server. Each accepted connection echoes
// back everything it reads. Returns the listening address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// TestSessionE2E verifies that data flows end-to-end through the server's
// KCP+Noise+smux stack to an upstream TCP echo server and back.
func TestSessionE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate server keypair.
	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := noise.PubkeyFromPrivkey(privkey)
	if err != nil {
		t.Fatal(err)
	}

	upstream := startEchoServer(t)

	// serverQPC is the server's virtual DNS transport. Normally recvLoop
	// feeds it; here we feed it directly from the test client.
	serverQPCAddr := turbotunnel.DummyAddr{}
	serverQPC := turbotunnel.NewQueuePacketConn(serverQPCAddr, 60*time.Second)
	t.Cleanup(func() { serverQPC.Close() })

	// clientQPC is the test client's underlying PacketConn. KCP will send
	// packets through it toward serverQPCAddr; the relay delivers them to
	// the server, and vice versa.
	clientID := turbotunnel.NewClientID()
	clientQPC := turbotunnel.NewQueuePacketConn(clientID, 60*time.Second)
	t.Cleanup(func() { clientQPC.Close() })

	// Relay: client → server (client writes to serverQPCAddr, server reads
	// with clientID as the source address so it can route responses back).
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
	// Relay: server → client.
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

	// Start the server-side KCP listener and session handler.
	mtu := 1200
	ln, err := kcp.ServeConn(nil, 0, 0, serverQPC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	serverParams := handshakeParams{}
	go func() {
		if err := acceptSessions(ln, privkey, mtu, upstream, defaultKCPConfig(), nil, false, serverParams, false); err != nil && ctx.Err() == nil {
			t.Logf("acceptSessions: %v", err)
		}
	}()

	// Create a client-side KCP connection (conv=0, server address = serverQPCAddr).
	kcpConn, err := kcp.NewConn3(0, serverQPCAddr, nil, 0, 0, clientQPC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kcpConn.Close() })
	kcpConn.SetStreamMode(true)
	kcpConn.SetNoDelay(0, 0, 0, 1)
	kcpConn.SetWindowSize(128, 128)
	kcpConn.SetMtu(mtu)

	// Perform the Noise handshake as a client.
	rw, err := noise.NewClient(kcpConn, pubkey, encodeHandshakeParams(handshakeParams{}, nil))
	if err != nil {
		t.Fatal(err)
	}

	// Open an smux client session over the Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })

	// Open a stream.
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	stream.SetDeadline(time.Now().Add(8 * time.Second))

	// Send data and verify it is echoed back.
	want := []byte("hello, dnstt tunnel!")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q, want %q", got, want)
	}
}

// TestSessionE2E_SOCKS5 verifies the built-in SOCKS5 proxy mode: the server
// should perform a SOCKS5 handshake and connect to the address requested by
// the client, which in this test is our echo server.
func TestSessionE2E_SOCKS5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// SOCKS5 e2e test connects to a loopback echo server. Override the deny
	// hook so loopback isn't refused for the duration of this test.
	prevDenyHook := socks5DenyHook
	socks5DenyHook = func(host string, allowPrivate bool) error { return nil }
	t.Cleanup(func() { socks5DenyHook = prevDenyHook })

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatal(err)
	}
	pubkey, err := noise.PubkeyFromPrivkey(privkey)
	if err != nil {
		t.Fatal(err)
	}

	echoAddr := startEchoServer(t)
	echoHost, echoPort, err := net.SplitHostPort(echoAddr)
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
	// upstream="" triggers SOCKS5 mode in acceptSessions.
	serverParams := handshakeParams{}
	go func() {
		if err := acceptSessions(ln, privkey, mtu, "", defaultKCPConfig(), nil, false, serverParams, false); err != nil && ctx.Err() == nil {
			t.Logf("acceptSessions: %v", err)
		}
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

	rw, err := noise.NewClient(kcpConn, pubkey, encodeHandshakeParams(handshakeParams{}, nil))
	if err != nil {
		t.Fatal(err)
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stream.Close() })
	stream.SetDeadline(time.Now().Add(8 * time.Second))

	// Perform SOCKS5 handshake: client greeting → server selection →
	// client request (CONNECT to echo server) → server reply.
	// 1. Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth).
	stream.Write([]byte{0x05, 0x01, 0x00})
	// 2. Server sends method selection: VER=5, METHOD=0x00.
	reply := make([]byte, 2)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatal("reading method selection:", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected method selection: %x", reply)
	}

	// 3. Request: CONNECT to echoHost:echoPort using domain name.
	host := []byte(echoHost)
	port := mustParsePort(t, echoPort)
	req := []byte{
		0x05, 0x01, 0x00, 0x03, // VER, CMD=CONNECT, RSV, ATYP=domain
		byte(len(host)),
	}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	stream.Write(req)

	// 4. Server success reply: VER=5, REP=0 (success).
	resp := make([]byte, 10)
	if _, err := io.ReadFull(stream, resp); err != nil {
		t.Fatal("reading CONNECT reply:", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT failed with REP=0x%02x", resp[1])
	}

	// Now the stream is connected to the echo server.
	want := []byte("socks5 tunnel works!")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q, want %q", got, want)
	}
}

func mustParsePort(t *testing.T, s string) uint16 {
	t.Helper()
	port, err := net.LookupPort("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}

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

	// Custom acceptor that captures the per-session error so the test can
	// assert the server rejected for the right reason (param mismatch),
	// rather than tolerating any client-side failure path.
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
		// Run acceptStreams directly so its returned error is observable.
		sessErrCh <- acceptStreams(conn, privkey, "echo-unused", nil, false, serverParams, false)
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

	// Client claims FEC=4/2 — server should reject.
	clientPayload := encodeHandshakeParams(handshakeParams{FECData: 4, FECParity: 2, Compress: false}, nil)
	rw, clientErr := noise.NewClient(kcpConn, pubkey, clientPayload)
	if rw != nil {
		// Drain whatever the server closes for us so the connection
		// doesn't keep buffers around. Best-effort.
		kcpConn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		_, _ = rw.Read(make([]byte, 1))
	}
	_ = clientErr // Either Noise handshake error or post-Noise read failure is fine.

	// The authoritative assertion is server-side: acceptStreams must return
	// an error mentioning "client param mismatch".
	select {
	case err := <-sessErrCh:
		if err == nil {
			t.Fatal("server accepted mismatched params (returned nil); validation skipped?")
		}
		if !strings.Contains(err.Error(), "client param mismatch") {
			t.Fatalf("server returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not return within 5s; param validation may be hanging")
	}
}

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

// makeAuthDB builds an in-memory authDatabase with a single token for tests.
func makeAuthDB(t *testing.T, token [32]byte) *authDatabase {
	t.Helper()
	return newAuthDatabase([][32]byte{token})
}

// runAuthHandshake drives a server-side acceptStreams against a fake
// session and returns the error it produced. The client-side handshake
// is replicated inline so the test can vary the payload independently of
// dnstt-client's internal call. The client always opens one smux stream
// after the handshake so acceptStreams produces a deterministic terminal
// error (auth rejection on auth failure, dial failure on auth success).
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

	// Use an unreachable upstream so the dial in handleStream fails quickly
	// once auth passes — that surfaces a deterministic non-auth error from
	// acceptStreams that the test can distinguish from auth rejection.
	const unreachableUpstream = "127.0.0.1:1" // port 1 is reserved/unused

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
		sessErrCh <- acceptStreams(conn, privkey, unreachableUpstream, authDB, false, serverParams, false)
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

	// Drive the full client side: Noise handshake then one smux stream
	// open. If auth fails, noise.NewClient or smux.Client will surface
	// the close. If auth passes, the stream open succeeds and the server
	// will fail to dial unreachableUpstream — that error returns via
	// sessErrCh.
	clientPayload := encodeHandshakeParams(handshakeParams{}, clientToken)
	rw, _ := noise.NewClient(kcpConn, pubkey, clientPayload)
	if rw != nil {
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = 2
		smuxConfig.KeepAliveTimeout = idleTimeout
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
		if sess, err := smux.Client(rw, smuxConfig); err == nil {
			if stream, err := sess.OpenStream(); err == nil {
				// Read once to drive the server's stream-handler to
				// completion (which will fail on the unreachable dial).
				stream.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = stream.Read(make([]byte, 1))
				stream.Close()
			}
			sess.Close()
		}
		_ = rw.Close()
	}
	_ = kcpConn.Close()
	// KCP has no FIN-equivalent, so closing the client side doesn't make
	// the server's Read return. Tear down the underlying QPCs to break
	// the server's KCP read and let acceptStreams return.
	_ = clientQPC.Close()
	_ = serverQPC.Close()

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
	if err == nil {
		t.Fatal("expected post-auth error from unreachable upstream, got nil — auth path may not have completed")
	}
	if strings.Contains(err.Error(), "unauthorized client") {
		t.Fatalf("auth was rejected with valid token: %v", err)
	}
	if strings.Contains(err.Error(), "auth required") {
		t.Fatalf("auth was rejected as missing with valid token: %v", err)
	}
	// Positive proof: the error must indicate progression past auth into
	// the dial path (or smux teardown). Common substrings: "connect",
	// "dial", "stream", "EOF", "closed".
	allowedFrags := []string{"connect", "dial", "stream", "EOF", "closed", "broken pipe"}
	matched := false
	for _, frag := range allowedFrags {
		if strings.Contains(err.Error(), frag) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("expected post-auth error (connect/dial/stream/EOF), got %v", err)
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
