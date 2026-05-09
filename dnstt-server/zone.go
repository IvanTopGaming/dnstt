package main

import (
	"bytes"
	"encoding/binary"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// zoneInfo describes the zone the server is authoritative for, along with
// synthesized SOA and NS resource records that make non-tunnel responses
// look like a real auth NS to passive DPI and active probers.
type zoneInfo struct {
	apex dns.Name
	soa  dns.RR
	ns   dns.RR
}

// SOA timer values (BIND-defaults-ish).
const (
	soaRefresh = 3600
	soaRetry   = 1800
	soaExpire  = 604800
	soaMinimum = 60
)

// newZoneInfo constructs a zoneInfo for apex. mname = "ns.<apex>", rname =
// "hostmaster.<apex>", serial = YYYYMMDDnn at start time. SOA timer
// values follow BIND's typical "small zone" defaults.
func newZoneInfo(apex dns.Name) zoneInfo {
	mname := prependLabel(apex, []byte("ns"))
	rname := prependLabel(apex, []byte("hostmaster"))

	now := time.Now().UTC()
	serial := uint32(now.Year())*1000000 +
		uint32(now.Month())*10000 +
		uint32(now.Day())*100 +
		1

	soaRDATA := encodeRDataSOA(mname, rname, serial,
		soaRefresh, soaRetry, soaExpire, soaMinimum)

	nsRDATA := encodeName(mname)

	return zoneInfo{
		apex: apex,
		soa: dns.RR{
			Name:  apex,
			Type:  dns.RRTypeSOA,
			Class: dns.ClassIN,
			TTL:   responseTTL,
			Data:  soaRDATA,
		},
		ns: dns.RR{
			Name:  apex,
			Type:  dns.RRTypeNS,
			Class: dns.ClassIN,
			TTL:   responseTTL,
			Data:  nsRDATA,
		},
	}
}

// prependLabel returns label.<apex> as a new dns.Name.
func prependLabel(apex dns.Name, label []byte) dns.Name {
	out := make(dns.Name, 0, len(apex)+1)
	out = append(out, label)
	out = append(out, apex...)
	return out
}

// encodeName writes a DNS name in uncompressed wire format: each label
// prefixed by its 1-byte length, followed by a zero-length root label.
func encodeName(name dns.Name) []byte {
	var buf bytes.Buffer
	for _, label := range name {
		buf.WriteByte(byte(len(label)))
		buf.Write(label)
	}
	buf.WriteByte(0) // root terminator
	return buf.Bytes()
}

// encodeRDataSOA assembles the wire-format RDATA of an SOA record per
// RFC 1035 §3.3.13: mname, rname, serial, refresh, retry, expire, minimum.
func encodeRDataSOA(mname, rname dns.Name, serial, refresh, retry, expire, minimum uint32) []byte {
	var buf bytes.Buffer
	buf.Write(encodeName(mname))
	buf.Write(encodeName(rname))
	binary.Write(&buf, binary.BigEndian, serial)
	binary.Write(&buf, binary.BigEndian, refresh)
	binary.Write(&buf, binary.BigEndian, retry)
	binary.Write(&buf, binary.BigEndian, expire)
	binary.Write(&buf, binary.BigEndian, minimum)
	return buf.Bytes()
}
