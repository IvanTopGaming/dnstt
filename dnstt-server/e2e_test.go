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
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
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
	go func() {
		if err := acceptSessions(ln, privkey, mtu, upstream, defaultKCPConfig(), nil, false); err != nil && ctx.Err() == nil {
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
	rw, err := noise.NewClient(kcpConn, pubkey)
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
	go func() {
		if err := acceptSessions(ln, privkey, mtu, "", defaultKCPConfig(), nil, false); err != nil && ctx.Err() == nil {
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

	rw, err := noise.NewClient(kcpConn, pubkey)
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
