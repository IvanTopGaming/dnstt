package main

import (
	"context"
	"errors"
	"net/netip"
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

		// IPv4-in-IPv6 mapped — must be unmapped to v4 before classification,
		// otherwise an attacker can bypass loopback/private checks via
		// "::ffff:127.0.0.1" or "::ffff:10.0.0.1".
		{"v4-mapped loopback", "::ffff:127.0.0.1", false, "loopback"},
		{"v4-mapped loopback still deny when allow", "::ffff:127.0.0.1", true, "loopback"},
		{"v4-mapped rfc1918 deny", "::ffff:10.0.0.5", false, "private"},
		{"v4-mapped rfc1918 allow with flag", "::ffff:10.0.0.5", true, ""},
		{"v4-mapped link-local", "::ffff:169.254.169.254", false, "link-local"},
		{"v4-mapped link-local still deny when allow", "::ffff:169.254.169.254", true, "link-local"},
		{"v4-mapped public", "::ffff:1.1.1.1", false, ""},

		// These two specifically guard the helper's non-stdlib predicates
		// (broadcastV4 strict equality and cgNATPrefix4.Contains), which
		// would NOT match the v4-mapped form without addr.Unmap().
		{"v4-mapped broadcast", "::ffff:255.255.255.255", false, "broadcast"},
		{"v4-mapped CGNAT deny", "::ffff:100.64.0.1", false, "private"},
		{"v4-mapped CGNAT allow with flag", "::ffff:100.64.0.1", true, ""},

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

// withLookupHook swaps socks5LookupHook for the duration of t and returns
// the resolved addresses for any host the test case maps. Other hosts get
// errLookupNotFound.
func withLookupHook(t *testing.T, table map[string][]string) {
	t.Helper()
	prev := socks5LookupHook
	socks5LookupHook = func(_ context.Context, _, host string) ([]netip.Addr, error) {
		ips, ok := table[host]
		if !ok {
			return nil, errLookupNotFound
		}
		out := make([]netip.Addr, 0, len(ips))
		for _, s := range ips {
			a, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("test fixture: bad IP %q: %v", s, err)
			}
			out = append(out, a)
		}
		return out, nil
	}
	t.Cleanup(func() { socks5LookupHook = prev })
}

var errLookupNotFound = errors.New("test: host not in lookup table")

// TestResolveAllowedDestination_IPLiteralLoopback_Denied verifies that an
// IP-literal loopback target still hits the deny-list (existing behaviour
// preserved through the refactor).
func TestResolveAllowedDestination_IPLiteralLoopback_Denied(t *testing.T) {
	_, err := resolveAllowedDestination(context.Background(), "127.0.0.1", "22", false)
	if err == nil {
		t.Fatal("expected deny, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error should mention loopback, got %q", err.Error())
	}
}

// TestResolveAllowedDestination_IPLiteralPublic_Allowed verifies that an
// IP-literal public address dials back as a literal "host:port".
func TestResolveAllowedDestination_IPLiteralPublic_Allowed(t *testing.T) {
	got, err := resolveAllowedDestination(context.Background(), "1.1.1.1", "443", false)
	if err != nil {
		t.Fatalf("unexpected deny: %v", err)
	}
	if got != "1.1.1.1:443" {
		t.Fatalf("got %q, want %q", got, "1.1.1.1:443")
	}
}

// TestResolveAllowedDestination_HostnameResolvesLoopback_Denied is the
// SSRF regression: a hostname that resolves to a loopback IP MUST be
// refused. Previously isDeniedDestination returned nil for any non-IP
// host and net.Dialer.Dial would happily resolve and connect.
func TestResolveAllowedDestination_HostnameResolvesLoopback_Denied(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"localhost": {"127.0.0.1"},
	})
	_, err := resolveAllowedDestination(context.Background(), "localhost", "22", false)
	if err == nil {
		t.Fatal("expected deny, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error should mention loopback, got %q", err.Error())
	}
}

// TestResolveAllowedDestination_HostnameResolvesMetadata_Denied covers the
// cloud-metadata IP via a hostname (the canonical SSRF target).
func TestResolveAllowedDestination_HostnameResolvesMetadata_Denied(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"metadata.google.internal": {"169.254.169.254"},
	})
	_, err := resolveAllowedDestination(context.Background(), "metadata.google.internal", "80", false)
	if err == nil {
		t.Fatal("expected deny, got nil")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("error should mention link-local, got %q", err.Error())
	}
}

// TestResolveAllowedDestination_HostnameResolvesPublic_AllowedAsLiteral
// verifies that a hostname resolving to a public IP returns the literal
// "<ip>:<port>" so the dialer cannot inadvertently re-resolve to a
// different (possibly internal) IP between our check and the connect.
func TestResolveAllowedDestination_HostnameResolvesPublic_AllowedAsLiteral(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"example.com": {"93.184.216.34"},
	})
	got, err := resolveAllowedDestination(context.Background(), "example.com", "443", false)
	if err != nil {
		t.Fatalf("unexpected deny: %v", err)
	}
	if got != "93.184.216.34:443" {
		t.Fatalf("got %q, want %q", got, "93.184.216.34:443")
	}
}

// TestResolveAllowedDestination_HostnameMixed_FailClosed verifies the
// fail-closed semantics when DNS returns multiple IPs and at least one is
// in the deny class. We must refuse the whole connection rather than
// pick the allowed one — otherwise an attacker can bypass via DNS
// rebinding (round-robin on the same hostname).
func TestResolveAllowedDestination_HostnameMixed_FailClosed(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"rebind.test": {"93.184.216.34", "127.0.0.1"},
	})
	_, err := resolveAllowedDestination(context.Background(), "rebind.test", "80", false)
	if err == nil {
		t.Fatal("expected deny when any result is in deny class")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error should mention loopback, got %q", err.Error())
	}
}

// TestResolveAllowedDestination_HostnameLookupFails verifies that a
// resolver error is wrapped and returned (handler will refuse with REP=04).
func TestResolveAllowedDestination_HostnameLookupFails(t *testing.T) {
	withLookupHook(t, map[string][]string{}) // empty table → all hosts fail
	_, err := resolveAllowedDestination(context.Background(), "nonexistent.test", "80", false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errLookupNotFound) {
		t.Fatalf("expected wrapped errLookupNotFound, got %v", err)
	}
}

// TestResolveAllowedDestination_RFC1918Hostname_Denied verifies that the
// allowPrivate=false default also rejects hostnames resolving to RFC1918
// (covers the LAN-pivot variant of the SSRF).
func TestResolveAllowedDestination_RFC1918Hostname_Denied(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"intranet.lan": {"10.0.0.5"},
	})
	_, err := resolveAllowedDestination(context.Background(), "intranet.lan", "22", false)
	if err == nil {
		t.Fatal("expected deny for hostname → private")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Fatalf("error should mention private, got %q", err.Error())
	}
}

// TestResolveAllowedDestination_RFC1918Hostname_AllowedWithFlag verifies
// the -socks5-allow-private flag still works through the hostname path.
func TestResolveAllowedDestination_RFC1918Hostname_AllowedWithFlag(t *testing.T) {
	withLookupHook(t, map[string][]string{
		"intranet.lan": {"10.0.0.5"},
	})
	got, err := resolveAllowedDestination(context.Background(), "intranet.lan", "22", true)
	if err != nil {
		t.Fatalf("unexpected deny under allowPrivate=true: %v", err)
	}
	if got != "10.0.0.5:22" {
		t.Fatalf("got %q, want %q", got, "10.0.0.5:22")
	}
}
