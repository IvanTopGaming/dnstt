package dns

import "testing"

// FuzzMessageFromWireFormat is a native Go fuzz test (go test -fuzz=.) for the
// DNS message parser. It verifies that:
//  1. Any byte sequence either parses without error or returns an error.
//  2. Any message that parses successfully can be re-serialized without panic.
//  3. Serializing and re-parsing produces an identical message.
func FuzzMessageFromWireFormat(f *testing.F) {
	// Seed corpus: empty, minimal valid query, minimal valid response.
	f.Add([]byte{})
	// Minimal DNS query: ID=0x1234, FLAGS=0x0100 (RD), QDCOUNT=1,
	// question: "\x01a\x00" (name "a."), QTYPE=TXT(16), QCLASS=IN(1)
	f.Add([]byte{
		0x12, 0x34, // ID
		0x01, 0x00, // FLAGS: QR=0, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		0x01, 'a', 0x00, // QNAME: "a."
		0x00, 0x10, // QTYPE: TXT
		0x00, 0x01, // QCLASS: IN
	})
	// Minimal DNS response with a TXT record.
	f.Add([]byte{
		0x12, 0x34, // ID
		0x81, 0x80, // FLAGS: QR=1, AA=0, RD=1, RA=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x01, // ANCOUNT=1
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
		0x01, 'a', 0x00, // QNAME: "a."
		0x00, 0x10, // QTYPE: TXT
		0x00, 0x01, // QCLASS: IN
		0x01, 'a', 0x00, // ANAME: "a."
		0x00, 0x10, // TYPE: TXT
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0x3c, // TTL: 60
		0x00, 0x06, // RDLENGTH: 6
		0x05, 'h', 'e', 'l', 'l', 'o', // RDATA: TXT "hello"
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := MessageFromWireFormat(data)
		if err != nil {
			// Invalid input is fine; the parser should return an error,
			// not panic.
			return
		}
		// A successfully parsed message must serialize without error.
		buf, err := msg.WireFormat()
		if err != nil {
			t.Fatalf("WireFormat failed after successful parse: %v", err)
		}
		// Round-trip: re-parse the serialized bytes.
		msg2, err := MessageFromWireFormat(buf)
		if err != nil {
			t.Fatalf("MessageFromWireFormat failed on re-serialized message: %v", err)
		}
		// The re-serialized form must be stable (idempotent).
		buf2, err := msg2.WireFormat()
		if err != nil {
			t.Fatalf("second WireFormat failed: %v", err)
		}
		if string(buf) != string(buf2) {
			t.Fatalf("WireFormat not idempotent:\n  first:  %x\n  second: %x", buf, buf2)
		}
	})
}
