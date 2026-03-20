package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"sync/atomic"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// How many bytes of random padding to insert into queries.
	numPadding = 3
	// In an otherwise empty polling query, insert even more random padding,
	// to reduce the chance of a cache hit. Cannot be greater than 31,
	// because the prefix codes indicating padding start at 224.
	numPaddingForPoll = 8

	// sendLoop has a poll timer that automatically sends an empty polling
	// query when a certain amount of time has elapsed without a send. The
	// poll timer is initially set to initPollDelay. It increases by a
	// factor of pollDelayMultiplier every time the poll timer expires, up
	// to a maximum of maxPollDelay. The poll timer is reset to
	// initPollDelay whenever a send occurs that is not the result of the
	// poll timer expiring.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// minAdaptivePollDelay is the lower bound for the RTT-based adaptive
	// poll delay. Prevents polling faster than the round-trip time allows.
	minAdaptivePollDelay = 50 * time.Millisecond

	// A limit on the number of empty poll requests we may send in a burst
	// as a result of receiving data.
	pollLimit = 16

	// rttEWMAAlpha is the smoothing factor for the RTT exponentially
	// weighted moving average. Smaller values smooth more aggressively.
	rttEWMAAlpha = 0.125

	// decoyProbability is the 1-in-N chance that a decoy query is sent
	// after each real data query when obfuscation is enabled.
	decoyProbability = 5 // ~20% chance
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSPacketConn provides a packet-sending and -receiving interface over various
// forms of DNS. It handles the details of how packets and padding are encoded
// as a DNS name in the Question section of an upstream query, and as a TXT RR
// in downstream responses.
//
// DNSPacketConn does not handle the mechanics of actually sending and receiving
// encoded DNS messages. That is rather the responsibility of some other
// net.PacketConn such as net.UDPConn, HTTPPacketConn, or TLSPacketConn, one of
// which must be provided to NewDNSPacketConn.
//
// We don't have a need to match up a query and a response by ID. Queries and
// responses are vehicles for carrying data and for our purposes don't need to
// be correlated. When sending a query, we generate a random ID, and when
// receiving a response, we ignore the ID.
type DNSPacketConn struct {
	clientID  turbotunnel.ClientID
	domain    dns.Name
	obfuscate bool
	// pollChan permits sendLoop to send an empty polling query.
	pollChan chan struct{}
	// lastSendAt is updated (as Unix nanoseconds) just before each send,
	// for RTT measurement.
	lastSendAt atomic.Int64
	// rttEWMA stores the EWMA RTT in nanoseconds (0 = no data yet).
	rttEWMA atomic.Int64
	// QueuePacketConn is the direct receiver of ReadFrom and WriteTo calls.
	// recvLoop and sendLoop take the messages out of the receive and send
	// queues and actually put them on the network.
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport, through its WriteTo
// and ReadFrom methods, handles the actual sending and receiving the DNS
// messages encoded by DNSPacketConn. addr is the address to be passed to
// transport.WriteTo whenever a message needs to be sent. When obfuscate is
// true, decoy A/AAAA queries are interspersed among real queries to disguise
// traffic patterns.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, obfuscate bool) *DNSPacketConn {
	// Generate a new random ClientID.
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		obfuscate:       obfuscate,
		pollChan:        make(chan struct{}, pollLimit),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go func() {
		err := c.recvLoop(transport)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
		// Close the DNSPacketConn when either loop exits, so the KCP
		// session detects the failure and terminates promptly instead of
		// hanging until idleTimeout.
		c.Close()
	}()
	go func() {
		err := c.sendLoop(transport, addr)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
		c.Close()
	}()
	return c
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// into the RDATA of a TXT or AAAA RR. It returns nil if the message doesn't
// pass format checks, or if the name in its Question entry is not a subdomain
// of domain.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		// QR != 1, this is not a response.
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}

	if len(resp.Answer) == 0 {
		return nil
	}

	// Check the first answer to determine encoding type.
	answer := resp.Answer[0]
	_, ok := answer.Name.TrimSuffix(domain)
	if !ok {
		// Not the name we are expecting.
		return nil
	}

	switch answer.Type {
	case dns.RRTypeTXT:
		if len(resp.Answer) != 1 {
			return nil
		}
		payload, err := dns.DecodeRDataTXT(answer.Data)
		if err != nil {
			return nil
		}
		return payload
	case dns.RRTypeAAAA:
		// AAAA responses are blend-in polls and carry no payload.
		// Resolvers may reorder AAAA RRsets, so we never encode data in them.
		return nil
	default:
		return nil
	}
}

// nextPacket reads the next length-prefixed packet from r. It returns a nil
// error only when a complete packet was read. It returns io.EOF only when there
// were 0 bytes remaining to read from r. It returns io.ErrUnexpectedEOF when
// EOF occurs in the middle of an encoded packet.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		// We may return a real io.EOF only here.
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	// Here we must change io.EOF to io.ErrUnexpectedEOF.
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

// updateRTTEWMA updates the RTT EWMA from the recorded lastSendAt time.
func (c *DNSPacketConn) updateRTTEWMA() {
	t := c.lastSendAt.Load()
	if t == 0 {
		return
	}
	rtt := time.Duration(time.Now().UnixNano() - t)
	if rtt <= 0 {
		return
	}
	old := c.rttEWMA.Load()
	var next int64
	if old == 0 {
		next = int64(rtt)
	} else {
		next = int64(rttEWMAAlpha*float64(rtt) + (1-rttEWMAAlpha)*float64(old))
	}
	c.rttEWMA.Store(next)
}

// adaptivePollDelay returns an initPollDelay based on the measured RTT EWMA,
// or the default initPollDelay if no RTT measurement is available yet.
func (c *DNSPacketConn) adaptivePollDelay() time.Duration {
	if ewma := time.Duration(c.rttEWMA.Load()); ewma >= minAdaptivePollDelay {
		if ewma > maxPollDelay {
			return maxPollDelay
		}
		return ewma
	}
	return initPollDelay
}

// recvLoop repeatedly calls transport.ReadFrom to receive a DNS message,
// extracts its payload and breaks it into packets, and stores the packets in a
// queue to be returned from a future call to c.ReadFrom.
//
// Whenever we receive a DNS response containing at least one data packet, we
// send on c.pollChan to permit sendLoop to send an immediate polling queries.
// KCP itself will also send an ACK packet for incoming data, which is
// effectively a second poll. Therefore, each time we receive data, we send up
// to 2 polling queries (or 1 + f polling queries, if KCP only ACKs an f
// fraction of incoming data). We say "up to" because sendLoop will discard an
// empty polling query if it has an organic non-empty packet to send (this goes
// also for KCP's organic ACK packets).
//
// The intuition behind polling immediately after receiving is that if server
// has just had something to send, it may have more to send, and in order for
// the server to send anything, we must give it a query to respond to. The
// intuition behind polling *2 times* (or 1 + f times) is similar to TCP slow
// start: we want to maintain some number of queries "in flight", and the faster
// the server is sending, the higher that number should be. If we polled only
// once for each received packet, we would tend to have only one query in flight
// at a time, ping-pong style. The first polling query replaces the in-flight
// query that has just finished its duty in returning data to us; the second
// grows the effective in-flight window proportional to the rate at which
// data-carrying responses are being received. Compare to Eq. (2) of
// https://tools.ietf.org/html/rfc5681#section-3.1. The differences are that we
// count messages, not bytes, and we don't maintain an explicit window. If a
// response comes back without data, or if a query or response is dropped by the
// network, then we don't poll again, which decreases the effective in-flight
// window.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) error {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// Got a response. Try to parse it as a DNS message.
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("MessageFromWireFormat: %v", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domain)

		// Pull out the packets contained in the payload.
		r := bytes.NewReader(payload)
		any := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}

		// If the payload contained one or more packets, update RTT and
		// permit sendLoop to poll immediately.
		if any {
			c.updateRTTEWMA()
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes, greedily so that
// only final subslice has length < n.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send sends p as a single packet encoded into a DNS query, using
// transport.WriteTo(query, addr). The length of p must be less than 224 bytes.
//
// Here is an example of how a packet is encoded into a DNS name, using
//
//	p = "supercalifragilisticexpialidocious"
//	c.clientID = "CLIENTID"
//	domain = "t.example.com"
//
// as the input.
//
//  0. Start with the raw packet contents.
//
//	supercalifragilisticexpialidocious
//
//  1. Length-prefix the packet and add random padding. A length prefix L < 0xe0
//     means a data packet of L bytes. A length prefix L ≥ 0xe0 means padding
//     of L − 0xe0 bytes (not counting the length of the length prefix itself).
//
//	\xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
//
//  2. Prefix the ClientID.
//
//	CLIENTID\xe3\xd9\xa3\x15\x22supercalifragilisticexpialidocious
//
//  3. Base32-encode, without padding and in lower case.
//
//	ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3djmrxwg2lpovzq
//
//  4. Break into labels of at most 63 octets.
//
//	ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq
//
//  5. Append the domain.
//
//	ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq.t.example.com
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		// ClientID
		buf.Write(c.clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		// Padding / cache inhibition
		buf.WriteByte(byte(224 + n))
		io.CopyN(&buf, rand.Reader, int64(n))
		// Packet contents
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return fmt.Errorf("generating DNS query ID: %v", err)
	}

	// For empty poll queries, randomly use AAAA instead of TXT at ~50%
	// probability to blend in with normal DNS traffic. Data queries always
	// use TXT because resolvers (Cloudflare, BIND, etc.) may reorder AAAA
	// RRsets, which would corrupt multi-record payloads.
	qtype := uint16(dns.RRTypeTXT)
	if len(p) == 0 && mathrand.Intn(2) == 0 {
		qtype = dns.RRTypeAAAA
	}

	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{
				Name:  name,
				Type:  qtype,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0) with empty Data; padding will be added below.
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 4096, // requester's UDP payload size
				TTL:   0,    // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}

	// EDNS(0) Padding (RFC 8467): pad the query to a multiple of 128 bytes.
	// First serialize without padding to measure the current size.
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	// 4 = option-code (2 bytes) + option-length (2 bytes)
	paddingDataLen := (128 - (len(buf)+4)%128) % 128
	// Build padding option: code=12 (0x000C), length, then zero bytes.
	paddingOption := make([]byte, 4+paddingDataLen)
	paddingOption[0] = 0x00
	paddingOption[1] = 0x0C
	paddingOption[2] = byte(paddingDataLen >> 8)
	paddingOption[3] = byte(paddingDataLen)
	// paddingOption[4:] is already zero
	query.Additional[0].Data = paddingOption
	// Re-serialize with padding included.
	buf, err = query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(buf, addr)
	return err
}

// sendDecoy sends a fake A or AAAA query to a random-looking domain to obscure
// traffic patterns. Errors are silently ignored since decoys are best-effort.
func (c *DNSPacketConn) sendDecoy(transport net.PacketConn, addr net.Addr) {
	// Generate a random 8-character lowercase label.
	var labelBytes [8]byte
	io.ReadFull(rand.Reader, labelBytes[:])
	label := make([]byte, 8)
	const alpha = "abcdefghijklmnopqrstuvwxyz"
	for i, b := range labelBytes {
		label[i] = alpha[int(b)%len(alpha)]
	}

	// Pick a plausible-looking TLD.
	tlds := []string{"com", "net", "org", "io", "co"}
	tld := tlds[mathrand.Intn(len(tlds))]

	name, err := dns.ParseName(string(label) + "." + tld)
	if err != nil {
		return
	}

	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return
	}

	// Alternate between A (1) and AAAA (28).
	qtype := uint16(1)
	if mathrand.Intn(2) == 0 {
		qtype = uint16(28)
	}

	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return
	}
	transport.WriteTo(buf, addr) //nolint:errcheck
}

// sendLoop takes packets that have been written using c.WriteTo, and sends them
// on the network using send. It also does polling with empty packets when
// requested by pollChan or after a timeout.
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) error {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		// Prioritize sending an actual data packet from outgoing. Only
		// consider a poll when outgoing is empty.
		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			// A data-carrying packet displaces one pending poll
			// opportunity, if any.
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			// We're polling because it's been a while since we last
			// polled. Increase the poll delay.
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			// We're sending an actual data packet, or we're polling
			// in response to a received packet. Reset the poll delay
			// to the adaptive value based on measured RTT.
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = c.adaptivePollDelay()
		}
		pollTimer.Reset(pollDelay)

		// Record send time for RTT measurement.
		c.lastSendAt.Store(time.Now().UnixNano())

		// Unlike in the server, in the client we assume that because
		// the data capacity of queries is so limited, it's not worth
		// trying to send more than one packet per query.
		err := c.send(transport, p, addr)
		if err != nil {
			return err
		}

		// Obfuscation: occasionally send a decoy query after a real
		// data packet to disguise traffic patterns.
		if c.obfuscate && len(p) > 0 && mathrand.Intn(decoyProbability) == 0 {
			go c.sendDecoy(transport, addr)
		}
	}
}
