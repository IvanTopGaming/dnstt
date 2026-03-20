package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

// parsePinSet parses a comma-separated list of "SHA256:<hex>" certificate pins
// and returns a set of 32-byte SHA-256 hashes. Each pin matches any certificate
// in the server's chain (leaf or intermediate).
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

// makePinnedTLSConfig returns a clone of base with certificate pinning applied.
// Standard hostname verification is replaced by a check that at least one
// certificate in the server's chain matches a pin in pins.
func makePinnedTLSConfig(pins map[[32]byte]struct{}, base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.InsecureSkipVerify = true // hostname check replaced by pin check below
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		for _, cert := range cs.PeerCertificates {
			h := sha256.Sum256(cert.Raw)
			if _, ok := pins[h]; ok {
				return nil
			}
		}
		return fmt.Errorf("certificate pinning: none of the %d peer certificates matched a pin", len(cs.PeerCertificates))
	}
	return cfg
}
