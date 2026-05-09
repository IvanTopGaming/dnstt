package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeChain builds a (root CA, leaf cert) signed by root. notAfter offsets
// the leaf's expiry; pass time.Hour for valid, -time.Hour for expired.
func makeChain(t *testing.T, leafNotAfter time.Duration) (rootDER, leafDER []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafNotAfter),
		DNSNames:     []string{"test-leaf"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, leafDER
}

func certHash(der []byte) [32]byte { return sha256.Sum256(der) }

func TestMakePinnedTLSConfig_LeafMatchAcceptsValidChain(t *testing.T) {
	rootDER, leafDER := makeChain(t, time.Hour)
	leafHash := certHash(leafDER)
	pins := map[[32]byte]struct{}{leafHash: {}}

	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)

	// Build PeerCertificates: leaf, then root. Stdlib places leaf at index 0.
	leaf, _ := x509.ParseCertificate(leafDER)
	root, _ := x509.ParseCertificate(rootDER)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, root}}

	if err := cfg.VerifyConnection(cs); err != nil {
		t.Fatalf("expected accept on leaf pin match, got %v", err)
	}
}

func TestMakePinnedTLSConfig_PinOnIntermediateRejected(t *testing.T) {
	rootDER, leafDER := makeChain(t, time.Hour)
	rootHash := certHash(rootDER)
	pins := map[[32]byte]struct{}{rootHash: {}}

	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)

	leaf, _ := x509.ParseCertificate(leafDER)
	root, _ := x509.ParseCertificate(rootDER)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, root}}

	err := cfg.VerifyConnection(cs)
	if err == nil {
		t.Fatal("expected reject when pin is on intermediate, not leaf")
	}
	if !strings.Contains(err.Error(), "leaf") {
		t.Fatalf("expected error mentioning leaf, got %q", err.Error())
	}
}

func TestMakePinnedTLSConfig_NoPeerCertsRejected(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)
	cs := tls.ConnectionState{}
	if err := cfg.VerifyConnection(cs); err == nil {
		t.Fatal("expected error on empty PeerCertificates")
	}
}

func TestMakePinnedTLSConfig_InsecureSkipVerifyDefaultFalse(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, false)
	if cfg.InsecureSkipVerify {
		t.Fatal("default mode must keep InsecureSkipVerify=false so chain validation runs")
	}
}

func TestMakePinnedTLSConfig_SkipChainEnabledSetsInsecure(t *testing.T) {
	pins := map[[32]byte]struct{}{{1, 2, 3}: {}}
	cfg := makePinnedTLSConfig(pins, &tls.Config{}, true)
	if !cfg.InsecureSkipVerify {
		t.Fatal("skip-chain mode must set InsecureSkipVerify=true so leaf pin replaces CA validation")
	}
}

func TestMakePinnedTLSConfig_SkipChainStillRequiresPinMatch(t *testing.T) {
	// In skipChain=true mode the chain validation is bypassed, but the
	// leaf-pin check MUST still run — otherwise skipChain becomes a
	// silent "trust everything" flag, defeating the whole point of pinning.
	rootDER, leafDER := makeChain(t, time.Hour)
	_ = rootDER

	// Pin set deliberately doesn't include the leaf hash.
	wrongPins := map[[32]byte]struct{}{{0xDE, 0xAD, 0xBE, 0xEF}: {}}

	cfg := makePinnedTLSConfig(wrongPins, &tls.Config{}, true)

	leaf, _ := x509.ParseCertificate(leafDER)
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	err := cfg.VerifyConnection(cs)
	if err == nil {
		t.Fatal("skipChain=true must still require a leaf-pin match; expected error, got nil")
	}
	if !strings.Contains(err.Error(), "leaf") {
		t.Fatalf("expected error mentioning leaf, got %q", err.Error())
	}
}
