package main

import (
	"bytes"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

func TestNewZoneInfo_Basic(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	// Apex preserved.
	if z.apex.String() != apex.String() {
		t.Fatalf("apex %s, want %s", z.apex, apex)
	}
	// SOA name == apex.
	if z.soa.Name.String() != apex.String() {
		t.Fatalf("SOA owner %s, want apex %s", z.soa.Name, apex)
	}
	if z.soa.Type != dns.RRTypeSOA {
		t.Fatalf("SOA type %d, want %d", z.soa.Type, dns.RRTypeSOA)
	}
	if z.soa.Class != dns.ClassIN {
		t.Fatalf("SOA class %d, want %d", z.soa.Class, dns.ClassIN)
	}
	// NS name == apex, target == ns.<apex>.
	if z.ns.Name.String() != apex.String() {
		t.Fatalf("NS owner %s, want apex %s", z.ns.Name, apex)
	}
	if z.ns.Type != dns.RRTypeNS {
		t.Fatalf("NS type %d, want %d", z.ns.Type, dns.RRTypeNS)
	}
}

func TestSOARDataWireFormat(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	// SOA RDATA layout: mname-name + rname-name + 5*uint32.
	// mname = "ns.t.example.com." → labels: ns, t, example, com, root
	expectedMname := []byte{
		2, 'n', 's',
		1, 't',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	if !bytes.HasPrefix(z.soa.Data, expectedMname) {
		t.Fatalf("SOA mname encoding mismatch:\n got prefix %x\n want         %x",
			z.soa.Data[:len(expectedMname)], expectedMname)
	}
}

func TestNSRDataWireFormat(t *testing.T) {
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	z := newZoneInfo(apex)

	expectedNs := []byte{
		2, 'n', 's',
		1, 't',
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	if !bytes.Equal(z.ns.Data, expectedNs) {
		t.Fatalf("NS RDATA mismatch:\n got  %x\n want %x", z.ns.Data, expectedNs)
	}
}
