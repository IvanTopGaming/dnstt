package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/xtaci/smux"
)

// socks5Handshake performs a SOCKS5 server-side handshake on rw and returns
// the target address as "host:port". Only the CONNECT command (0x01) with no
// authentication (method 0x00) is supported.
func socks5Handshake(rw io.ReadWriter) (string, error) {
	// Client greeting: [VER][NMETHODS][METHODS...]
	var ver, nMethods byte
	if err := binary.Read(rw, binary.BigEndian, &ver); err != nil {
		return "", fmt.Errorf("reading VER: %v", err)
	}
	if ver != 5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", ver)
	}
	if err := binary.Read(rw, binary.BigEndian, &nMethods); err != nil {
		return "", fmt.Errorf("reading NMETHODS: %v", err)
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return "", fmt.Errorf("reading METHODS: %v", err)
	}

	// Select method 0x00 (no authentication).
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		rw.Write([]byte{0x05, 0xFF}) //nolint:errcheck
		return "", fmt.Errorf("client does not support no-auth method")
	}
	if _, err := rw.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("writing method selection: %v", err)
	}

	// Client request: [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
	var cmd, rsv, atyp byte
	if err := binary.Read(rw, binary.BigEndian, &ver); err != nil {
		return "", fmt.Errorf("reading request VER: %v", err)
	}
	if ver != 5 {
		return "", fmt.Errorf("unsupported SOCKS version %d in request", ver)
	}
	if err := binary.Read(rw, binary.BigEndian, &cmd); err != nil {
		return "", fmt.Errorf("reading CMD: %v", err)
	}
	if cmd != 0x01 {
		// Send command not supported reply.
		rw.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return "", fmt.Errorf("unsupported SOCKS5 command 0x%02x (only CONNECT supported)", cmd)
	}
	if err := binary.Read(rw, binary.BigEndian, &rsv); err != nil {
		return "", fmt.Errorf("reading RSV: %v", err)
	}
	if err := binary.Read(rw, binary.BigEndian, &atyp); err != nil {
		return "", fmt.Errorf("reading ATYP: %v", err)
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(rw, addr); err != nil {
			return "", fmt.Errorf("reading IPv4 address: %v", err)
		}
		host = net.IP(addr).String()
	case 0x03: // Domain name
		var nameLen byte
		if err := binary.Read(rw, binary.BigEndian, &nameLen); err != nil {
			return "", fmt.Errorf("reading domain name length: %v", err)
		}
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(rw, name); err != nil {
			return "", fmt.Errorf("reading domain name: %v", err)
		}
		host = string(name)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(rw, addr); err != nil {
			return "", fmt.Errorf("reading IPv6 address: %v", err)
		}
		host = "[" + net.IP(addr).String() + "]"
	default:
		rw.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
		return "", fmt.Errorf("unsupported SOCKS5 ATYP 0x%02x", atyp)
	}

	var port uint16
	if err := binary.Read(rw, binary.BigEndian, &port); err != nil {
		return "", fmt.Errorf("reading DST.PORT: %v", err)
	}

	// Send success reply: VER=5, REP=0 (success), RSV=0, ATYP=1 (IPv4),
	// BND.ADDR=0.0.0.0, BND.PORT=0.
	if _, err := rw.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return "", fmt.Errorf("writing success reply: %v", err)
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

// handleSocks5Stream performs a SOCKS5 handshake on stream, then
// bidirectionally connects it to the target TCP address requested by the
// client.
func handleSocks5Stream(stream *smux.Stream, conv uint32) error {
	target, err := socks5Handshake(stream)
	if err != nil {
		return fmt.Errorf("SOCKS5 handshake: %v", err)
	}

	log.Printf("stream %08x:%d SOCKS5 CONNECT %s", conv, stream.ID(), target)

	dialer := net.Dialer{Timeout: upstreamDialTimeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("stream %08x:%d SOCKS5 connect %s: %v", conv, stream.ID(), target, err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("stream %08x:%d SOCKS5 upstream connection is not a *net.TCPConn", conv, stream.ID())
	}

	// Bidirectional copy, same as handleStream.
	return proxyStreams(stream, tcpConn, conv)
}
