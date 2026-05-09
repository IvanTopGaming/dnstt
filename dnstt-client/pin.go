package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

// parsePinSet parses a comma-separated list of "SHA256:<hex>" certificate pins
// and returns a set of 32-byte SHA-256 hashes. A pin must match the SHA-256
// hash of the leaf certificate's DER bytes; intermediates and roots are not
// consulted. Pair with makePinnedTLSConfig to install the resulting set.
func parsePinSet(s string) (map[[32]byte]struct{}, error) {
	pins := make(map[[32]byte]struct{})
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		algo, hexHash, ok := strings.Cut(part, ":")
		if !ok || !strings.EqualFold(algo, "sha256") {
			return nil, fmt.Errorf("pin %q: expected format SHA256:<hex>", part)
		}
		b, err := hex.DecodeString(hexHash)
		if err != nil {
			return nil, fmt.Errorf("pin %q: invalid hex: %v", part, err)
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("pin %q: expected 32-byte SHA-256 hash, got %d bytes", part, len(b))
		}
		var h [32]byte
		copy(h[:], b)
		pins[h] = struct{}{}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("pin set is empty")
	}
	return pins, nil
}

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
