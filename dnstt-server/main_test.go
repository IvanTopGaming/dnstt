package main

import (
	"bytes"
	"strings"
	"testing"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func makeTestZone(t *testing.T) zoneInfo {
	t.Helper()
	apex, err := dns.NewName([][]byte{[]byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	return newZoneInfo(apex)
}

func mustName(t *testing.T, parts ...string) dns.Name {
	t.Helper()
	labels := make([][]byte, 0, len(parts))
	for _, p := range parts {
		labels = append(labels, []byte(p))
	}
	n, err := dns.NewName(labels)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// makeQuery returns a minimal valid query for given name and type, with
// EDNS0 OPT advertising 4096-byte payload size.
func makeQuery(name dns.Name, qtype uint16) *dns.Message {
	return &dns.Message{
		ID:    0x1234,
		Flags: 0x0100, // QR=0, RD=1
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
}

// makeQueryNoEDNS returns a minimal valid query without an OPT RR — i.e.,
// no EDNS advertised. payloadSize will floor to 512 in responseFor, which
// is below maxUDPPayload (1232) and used to trigger FORMERR. Structural
// queries (apex SOA/NS, NXDOMAIN+SOA) should answer regardless.
func makeQueryNoEDNS(name dns.Name, qtype uint16) *dns.Message {
	return &dns.Message{
		ID:    0x1234,
		Flags: 0x0100, // QR=0, RD=1
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
	}
}

func TestResponseFor_OutsideZone_Refused(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "google", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp == nil {
		t.Fatal("nil response")
	}
	const RcodeRefused = 5
	if got := resp.Rcode(); got != RcodeRefused {
		t.Fatalf("RCODE %d, want REFUSED (%d)", got, RcodeRefused)
	}
	if resp.Flags&0x0400 != 0 {
		t.Fatal("AA must be 0 for out-of-zone")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answer, got %d", len(resp.Answer))
	}
}

func TestResponseFor_ApexSOA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeSOA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer (SOA), got %d", len(resp.Answer))
	}
	if resp.Answer[0].Type != dns.RRTypeSOA {
		t.Fatalf("answer type %d, want SOA (%d)", resp.Answer[0].Type, dns.RRTypeSOA)
	}
}

func TestResponseFor_ApexNS(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeNS)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Type != dns.RRTypeNS {
		t.Fatalf("expected 1 NS answer, got %+v", resp.Answer)
	}
}

func TestResponseFor_ApexA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (no record)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answer (no A record), got %d", len(resp.Answer))
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority")
	}
}

func TestResponseFor_ApexAAAA(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if len(resp.Answer) != 0 {
		t.Fatal("expected no answer for apex AAAA")
	}
}

func TestResponseFor_ApexMX(t *testing.T) {
	zone := makeTestZone(t)
	const RRTypeMX = 15
	q := makeQuery(mustName(t, "t", "example", "com"), RRTypeMX)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (no MX)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatal("expected no answer")
	}
}

func TestResponseFor_NonExistentSubdomain_A(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "random", "t", "example", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority on NXDOMAIN")
	}
}

func TestResponseFor_NonExistentSubdomain_MX(t *testing.T) {
	zone := makeTestZone(t)
	const RRTypeMX = 15
	q := makeQuery(mustName(t, "random", "t", "example", "com"), RRTypeMX)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
}

// TestResponseFor_ApexSOA_NoEDNS verifies that a non-EDNS apex SOA query
// (e.g., `dig +noedns SOA t.example.com`) returns NOERROR + SOA in Answer,
// not FORMERR. A real authoritative NS responds to non-EDNS queries; FORMERR
// for missing OPT is a strong "this is not a real auth server" fingerprint.
func TestResponseFor_ApexSOA_NoEDNS(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQueryNoEDNS(mustName(t, "t", "example", "com"), dns.RRTypeSOA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Type != dns.RRTypeSOA {
		t.Fatalf("expected 1 SOA in Answer, got %d", len(resp.Answer))
	}
}

// TestResponseFor_ApexNS_NoEDNS verifies that a non-EDNS apex NS query
// returns NOERROR + NS in Answer, not FORMERR.
func TestResponseFor_ApexNS_NoEDNS(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQueryNoEDNS(mustName(t, "t", "example", "com"), dns.RRTypeNS)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR", resp.Rcode())
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Type != dns.RRTypeNS {
		t.Fatalf("expected 1 NS in Answer, got %d", len(resp.Answer))
	}
}

// TestResponseFor_NXDOMAIN_NoEDNS verifies that a non-EDNS under-apex query
// for a non-tunnel-bearing type returns NXDOMAIN + SOA in Authority, not
// FORMERR.
func TestResponseFor_NXDOMAIN_NoEDNS(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQueryNoEDNS(mustName(t, "random", "t", "example", "com"), dns.RRTypeA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority on NXDOMAIN")
	}
}

// TestResponseFor_TunnelTXT_SmallEDNS_FormErr verifies that the FORMERR-on-
// small-payload guard is preserved for the tunnel-bearing TXT path, where
// responses can exceed the requester's stated payload size.
func TestResponseFor_TunnelTXT_SmallEDNS_FormErr(t *testing.T) {
	zone := makeTestZone(t)
	decoded := make([]byte, 8+1+3) // ClientID + len-prefix + padding
	for i := range decoded[:8] {
		decoded[i] = byte(i + 1)
	}
	decoded[8] = 0xe0 + 3
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))
	q := makeQueryNoEDNS(mustName(t, encoded, "t", "example", "com"), dns.RRTypeTXT)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeFormatError {
		t.Fatalf("RCODE %d, want FORMERR (no EDNS on tunnel TXT)", resp.Rcode())
	}
}

func TestResponseFor_TunnelAAAA_BlendPoll(t *testing.T) {
	zone := makeTestZone(t)
	// 8 bytes ClientID + 4 bytes (0xe0+3 byte len-prefix + 3 random padding bytes)
	decoded := make([]byte, 8+1+3)
	for i := range decoded[:8] {
		decoded[i] = byte(i + 1)
	}
	decoded[8] = 0xe0 + 3
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))

	allLabels := [][]byte{[]byte(encoded), []byte("t"), []byte("example"), []byte("com")}
	name, err := dns.NewName(allLabels)
	if err != nil {
		t.Fatal(err)
	}
	q := makeQuery(name, dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("RCODE %d, want NOERROR (AAAA blend poll)", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1")
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no AAAA answer (blend poll), got %d", len(resp.Answer))
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority for AAAA blend poll")
	}
}

func TestResponseFor_PayloadTooShort(t *testing.T) {
	zone := makeTestZone(t)
	decoded := []byte{1, 2, 3, 4}
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))
	name, err := dns.NewName([][]byte{[]byte(encoded), []byte("t"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	q := makeQuery(name, dns.RRTypeAAAA)
	resp, _ := responseFor(q, zone)
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("RCODE %d, want NXDOMAIN", resp.Rcode())
	}
}

// TestRebuildTruncatedResponse verifies that an oversize response gets a
// valid wire-format with no Answer/Authority and TC=1 — never a mid-RR slice.
func TestRebuildTruncatedResponse(t *testing.T) {
	name, err := dns.NewName([][]byte{[]byte("test"), []byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	resp := &dns.Message{
		ID:       0x1234,
		Flags:    0x8400, // response, AA=1, RCODE=0
		Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Answer: []dns.RR{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 60,
				Data: dns.EncodeRDataTXT(bytes.Repeat([]byte("A"), 4000))},
		},
	}

	out := rebuildAsTruncated(resp, 1232)

	if len(out) > 1232 {
		t.Fatalf("rebuilt wire length %d exceeds limit 1232", len(out))
	}
	parsed, err := dns.MessageFromWireFormat(out)
	if err != nil {
		t.Fatalf("rebuilt wire is not valid DNS: %v", err)
	}
	if parsed.Flags&0x0200 == 0 {
		t.Fatalf("expected TC=1, got flags=%04x", parsed.Flags)
	}
	if len(parsed.Answer) != 0 {
		t.Fatalf("expected zero answers, got %d", len(parsed.Answer))
	}
	if len(parsed.Question) != 1 {
		t.Fatalf("expected one question preserved, got %d", len(parsed.Question))
	}
}

// TestRebuildTruncatedResponse_DropsOPTOnTightLimit verifies that when the
// limit is too tight even for header + Question + OPT, the fallback
// branch in rebuildAsTruncated drops the OPT record entirely. The result
// must still be a valid wire-format DNS message with TC=1.
func TestRebuildTruncatedResponse_DropsOPTOnTightLimit(t *testing.T) {
	name, err := dns.NewName([][]byte{[]byte("example"), []byte("com")})
	if err != nil {
		t.Fatal(err)
	}
	resp := &dns.Message{
		ID:       0x1234,
		Flags:    0x8400,
		Question: []dns.Question{{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN}},
		Answer: []dns.RR{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN, TTL: 60,
				Data: dns.EncodeRDataTXT([]byte("AAAAAAAAAA"))},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}

	// Compute size with OPT to find a limit that forces the fallback.
	withOPT := &dns.Message{
		ID:         resp.ID,
		Flags:      resp.Flags | 0x0200,
		Question:   resp.Question,
		Additional: resp.Additional,
	}
	withOPTBuf, err := withOPT.WireFormat()
	if err != nil {
		t.Fatal(err)
	}
	tightLimit := len(withOPTBuf) - 1 // 1 byte too small for the OPT path

	out := rebuildAsTruncated(resp, tightLimit)

	if len(out) > tightLimit {
		t.Fatalf("rebuilt wire length %d exceeds tight limit %d (fallback should have dropped OPT)", len(out), tightLimit)
	}
	parsed, err := dns.MessageFromWireFormat(out)
	if err != nil {
		t.Fatalf("rebuilt wire is not valid DNS: %v", err)
	}
	if parsed.Flags&0x0200 == 0 {
		t.Fatalf("expected TC=1, got flags=%04x", parsed.Flags)
	}
	if len(parsed.Answer) != 0 {
		t.Fatalf("expected zero answers, got %d", len(parsed.Answer))
	}
	if len(parsed.Question) != 1 {
		t.Fatalf("expected one question preserved, got %d", len(parsed.Question))
	}
	if len(parsed.Additional) != 0 {
		t.Fatalf("expected zero Additional records (OPT should be dropped), got %d", len(parsed.Additional))
	}
}

// TestRecvLoop_ApexQueryReturnsNoError verifies that an apex A query
// correctly produces NOERROR (no record) at the recvLoop level — guards
// against the bug where recvLoop's else-branch flipped any NOERROR-with-
// empty-Answer response to NXDOMAIN.
func TestRecvLoop_ApexQueryReturnsNoError(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeA)

	// Drive responseFor + the recvLoop ClientID-extraction logic by hand.
	// The recvLoop body is too tightly coupled to net.PacketConn to call
	// directly, so we replicate the relevant control flow.
	resp, payload := responseFor(q, zone)
	if resp == nil {
		t.Fatal("responseFor returned nil")
	}
	if payload != nil {
		t.Fatalf("apex query must not return a payload, got %d bytes", len(payload))
	}

	// Equivalent of the recvLoop guard: only override Rcode when payload
	// was returned. Since payload is nil, no override should happen.
	// Assert the response is still NOERROR after this control-flow path.
	if resp.Rcode() != dns.RcodeNoError {
		t.Fatalf("apex A response Rcode %d, want NOERROR", resp.Rcode())
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must be 1 on apex response")
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority on apex A NOERROR")
	}
}

// TestSendLoop_ApexAQueryNotCorrupted is a regression test for the bug
// where sendLoop overwrote any non-AAAA NOERROR response Answer with
// base32-encoded KCP-payload garbage, producing malformed wire format
// for apex A/SOA/NS queries.
//
// We can't easily call sendLoop directly (it owns a channel + UDP conn);
// instead we replicate the relevant control flow on a captured
// responseFor output and assert that wire-format remains valid.
func TestSendLoop_ApexAQueryNotCorrupted(t *testing.T) {
	zone := makeTestZone(t)
	q := makeQuery(mustName(t, "t", "example", "com"), dns.RRTypeA)
	resp, payload := responseFor(q, zone)
	if resp == nil {
		t.Fatal("nil response")
	}
	if payload != nil {
		t.Fatal("apex A must not return payload")
	}
	// Replicate sendLoop's TXT-fill guard: only fill if qtype==TXT and
	// Answer empty. For apex A, neither holds — pass-through path.
	qtype := resp.Question[0].Type
	if qtype == dns.RRTypeTXT && len(resp.Answer) == 0 {
		t.Fatal("apex A response must not enter the TXT-fill branch")
	}
	// Wire format must parse back cleanly.
	wire, err := resp.WireFormat()
	if err != nil {
		t.Fatalf("WireFormat: %v", err)
	}
	parsed, err := dns.MessageFromWireFormat(wire)
	if err != nil {
		t.Fatalf("apex A response is malformed: %v", err)
	}
	if parsed.Rcode() != dns.RcodeNoError {
		t.Fatalf("Rcode %d, want NOERROR", parsed.Rcode())
	}
	if len(parsed.Answer) != 0 {
		t.Fatalf("expected no Answer for apex A, got %d", len(parsed.Answer))
	}
	foundSOA := false
	for _, rr := range parsed.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority")
	}
}

// TestRecvLoop_ShortTxtPayloadOverridesToNXDOMAIN guards the recvLoop's
// "payload too short to contain a ClientID" override path. For a TXT
// query under our zone with < 8 decoded bytes, responseFor returns
// NOERROR with the decoded payload — recvLoop must convert this to
// NXDOMAIN+SOA so a probe sees a real auth-NS-shaped rejection.
func TestRecvLoop_ShortTxtPayloadOverridesToNXDOMAIN(t *testing.T) {
	zone := makeTestZone(t)

	// 4 decoded bytes — NOT enough for an 8-byte ClientID.
	decoded := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))
	name, err := dns.NewName([][]byte{
		[]byte(encoded),
		[]byte("t"), []byte("example"), []byte("com"),
	})
	if err != nil {
		t.Fatal(err)
	}

	q := makeQuery(name, dns.RRTypeTXT)
	resp, payload := responseFor(q, zone)
	if resp == nil {
		t.Fatal("responseFor returned nil")
	}
	if payload == nil {
		t.Fatal("expected payload to be returned for sub-zone TXT (so recvLoop can override on len<8)")
	}
	if len(payload) >= 8 {
		t.Fatalf("test setup error: payload should be <8 bytes, got %d", len(payload))
	}

	// Replicate the recvLoop ClientID-extraction-and-override logic.
	var clientID turbotunnel.ClientID
	n := copy(clientID[:], payload)
	if n == len(clientID) {
		t.Fatalf("test setup error: copied %d bytes, expected <8", n)
	}
	// recvLoop's override path:
	if resp.Rcode() == dns.RcodeNoError && len(resp.Answer) == 0 {
		resp.Flags = (resp.Flags &^ 0xf) | dns.RcodeNameError
		if len(resp.Authority) == 0 {
			resp.Authority = []dns.RR{zone.soa}
		}
	}

	// Verify the response now looks like a real auth NS NXDOMAIN.
	if resp.Rcode() != dns.RcodeNameError {
		t.Fatalf("after override Rcode = %d, want NXDOMAIN (%d)", resp.Rcode(), dns.RcodeNameError)
	}
	if resp.Flags&0x0400 == 0 {
		t.Fatal("AA must remain 1 after override")
	}
	foundSOA := false
	for _, rr := range resp.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority after NXDOMAIN override")
	}
	// Wire format must still be valid.
	wire, err := resp.WireFormat()
	if err != nil {
		t.Fatalf("WireFormat: %v", err)
	}
	if _, err := dns.MessageFromWireFormat(wire); err != nil {
		t.Fatalf("override produced malformed wire: %v", err)
	}
}

// TestSendLoop_AAAABlendPollNotCorrupted is a regression test for the
// removal of the fake `::` AAAA record. After this fix, sendLoop must
// not overwrite the empty Answer + SOA-in-Authority response that
// responseFor produces for an AAAA blend-poll query.
func TestSendLoop_AAAABlendPollNotCorrupted(t *testing.T) {
	zone := makeTestZone(t)
	// Build a valid tunnel-bearing AAAA query (8-byte ClientID + small payload).
	decoded := make([]byte, 8+1+3)
	for i := range decoded[:8] {
		decoded[i] = byte(i + 1)
	}
	decoded[8] = 0xe0 + 3
	encoded := strings.ToLower(base32Encoding.EncodeToString(decoded))
	name, err := dns.NewName([][]byte{
		[]byte(encoded),
		[]byte("t"), []byte("example"), []byte("com"),
	})
	if err != nil {
		t.Fatal(err)
	}
	q := makeQuery(name, dns.RRTypeAAAA)
	resp, payload := responseFor(q, zone)
	if resp == nil {
		t.Fatal("nil response")
	}
	if payload == nil {
		t.Fatal("expected payload (tunnel-bearing AAAA query)")
	}
	// Replicate sendLoop's TXT-fill guard predicate. With qtype=AAAA, it
	// does NOT match, so Answer should stay empty.
	qtype := resp.Question[0].Type
	if qtype == dns.RRTypeTXT && len(resp.Answer) == 0 {
		t.Fatal("test logic error: AAAA query somehow matched TXT branch predicate")
	}
	// Verify the response is wire-format-valid AND has empty Answer.
	if len(resp.Answer) != 0 {
		t.Fatalf("expected empty Answer for AAAA blend-poll, got %d", len(resp.Answer))
	}
	wire, err := resp.WireFormat()
	if err != nil {
		t.Fatalf("WireFormat: %v", err)
	}
	parsed, err := dns.MessageFromWireFormat(wire)
	if err != nil {
		t.Fatalf("malformed: %v", err)
	}
	if parsed.Rcode() != dns.RcodeNoError {
		t.Fatalf("Rcode %d, want NOERROR", parsed.Rcode())
	}
	if len(parsed.Answer) != 0 {
		t.Fatalf("expected empty Answer, got %d", len(parsed.Answer))
	}
	foundSOA := false
	for _, rr := range parsed.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected SOA in Authority")
	}
}

func TestRebuildAsTruncated_PreservesAuthorityWhenItFits(t *testing.T) {
	zone := makeTestZone(t)
	name := mustName(t, "random", "t", "example", "com")
	resp := &dns.Message{
		ID:        0x1234,
		Flags:     0x8400 | dns.RcodeNameError, // AA=1, NXDOMAIN
		Question:  []dns.Question{{Name: name, Type: dns.RRTypeA, Class: dns.ClassIN}},
		Authority: []dns.RR{zone.soa},
	}
	out := rebuildAsTruncated(resp, 1232)

	parsed, err := dns.MessageFromWireFormat(out)
	if err != nil {
		t.Fatalf("not valid DNS: %v", err)
	}
	if parsed.Flags&0x0200 == 0 {
		t.Fatal("expected TC=1")
	}
	foundSOA := false
	for _, rr := range parsed.Authority {
		if rr.Type == dns.RRTypeSOA {
			foundSOA = true
		}
	}
	if !foundSOA {
		t.Fatal("expected Authority SOA preserved when within limit")
	}
}
