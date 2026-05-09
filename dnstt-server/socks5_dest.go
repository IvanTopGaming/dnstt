package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// cgNATPrefix4 covers the RFC 6598 100.64.0.0/10 range that net/netip's
// IsPrivate does not classify as private.
var cgNATPrefix4 = netip.MustParsePrefix("100.64.0.0/10")

// broadcastV4 is 255.255.255.255. The stdlib does not surface a method for it.
var broadcastV4 = netip.MustParseAddr("255.255.255.255")

// isDeniedDestination returns a non-nil error if host (an IP literal)
// resolves to a destination class that the SOCKS5 server should refuse.
// Loopback, link-local, multicast, broadcast, and unspecified are always
// denied. RFC1918/ULA/CGNAT private destinations are denied by default
// but allowed when allowPrivate is true. Non-IP hostnames return nil
// here; resolveAllowedDestination handles those by resolving and
// rechecking each result.
func isDeniedDestination(host string, allowPrivate bool) error {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP literal — caller (resolveAllowedDestination) will
		// resolve and re-check.
		return nil
	}
	// Unmap v4-in-v6 (e.g. "::ffff:127.0.0.1") so subsequent predicates
	// see the v4 form. Without this, an attacker could bypass the
	// loopback/private checks by encoding the address in mapped form.
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback():
		return errors.New("destination loopback address denied")
	case addr == broadcastV4:
		return errors.New("destination broadcast address denied")
	case addr.IsMulticast():
		return errors.New("destination multicast address denied")
	case addr.IsLinkLocalUnicast():
		return errors.New("destination link-local address denied")
	case addr.IsUnspecified():
		return errors.New("destination unspecified address denied")
	}
	private := addr.IsPrivate() || cgNATPrefix4.Contains(addr)
	if private && !allowPrivate {
		return fmt.Errorf("destination private address %s denied (use -socks5-allow-private to permit)", addr)
	}
	return nil
}

// socks5DenyHook is the function consulted by the SOCKS5 handler to decide
// whether to refuse a destination. Tests may override it to allow loopback
// echo servers. Production code MUST NOT rewrite this.
var socks5DenyHook = isDeniedDestination

// socks5LookupHook resolves a hostname for the SOCKS5 destination check.
// Tests substitute a deterministic table; production resolves through the
// system resolver.
var socks5LookupHook = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// resolveAllowedDestination returns a literal "<ip>:<port>" target safe to
// dial without re-resolution, or an error if any candidate IP hits the
// deny-list. For IP literals it just delegates to socks5DenyHook. For
// hostnames it resolves via socks5LookupHook and rejects the entire
// connection if ANY result is denied (fail-closed against DNS rebinding /
// round-robin where one record is public and another is internal). The
// returned literal pins the dialer to a specific IP we have already
// vetted, closing the TOCTOU window between check and dial.
func resolveAllowedDestination(ctx context.Context, host, port string, allowPrivate bool) (string, error) {
	if _, err := netip.ParseAddr(host); err == nil {
		// IP literal — direct deny-list check, no resolution needed.
		if denyErr := socks5DenyHook(host, allowPrivate); denyErr != nil {
			return "", denyErr
		}
		return net.JoinHostPort(host, port), nil
	}
	addrs, err := socks5LookupHook(ctx, "ip", host)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: no addresses returned", host)
	}
	var first netip.Addr
	for _, addr := range addrs {
		if denyErr := socks5DenyHook(addr.String(), allowPrivate); denyErr != nil {
			return "", fmt.Errorf("%s resolves to denied %s: %w", host, addr, denyErr)
		}
		if !first.IsValid() {
			first = addr
		}
	}
	return net.JoinHostPort(first.String(), port), nil
}
