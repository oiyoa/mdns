// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"errors"
	"net/netip"
)

// ResolverReportEntry is one DNS resolver the client is actively using.
type ResolverReportEntry struct {
	IP netip.Addr
}

const (
	resolverReportFamilyV4 = 4
	resolverReportFamilyV6 = 6
	// Sanity limit. Realistic client configs have a handful of resolvers; the
	// cap defends against malformed payloads with absurd counts.
	resolverReportMaxEntries = 64
)

var (
	ErrResolverReportEmpty          = errors.New("resolver report payload empty")
	ErrResolverReportShort          = errors.New("resolver report payload truncated")
	ErrResolverReportBadFamily      = errors.New("resolver report has unknown address family")
	ErrResolverReportTooManyEntries = errors.New("resolver report has too many entries")
)

// EncodeResolverReport produces the wire format used by PACKET_RESOLVER_REPORT:
//
//	byte 0           : entry count (uint8)
//	per entry        : family (uint8: 4 or 6), addr bytes (4 or 16)
//
// Invalid (zero-value) IPs are dropped silently. If the resulting list is
// empty an explicit zero-count payload is returned.
func EncodeResolverReport(entries []ResolverReportEntry) []byte {
	valid := make([]ResolverReportEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IP.IsValid() {
			continue
		}
		valid = append(valid, e)
		if len(valid) >= resolverReportMaxEntries {
			break
		}
	}
	if len(valid) == 0 {
		return []byte{0}
	}

	size := 1
	for _, e := range valid {
		if e.IP.Is4() || e.IP.Is4In6() {
			size += 1 + 4
		} else {
			size += 1 + 16
		}
	}

	buf := make([]byte, 0, size)
	buf = append(buf, byte(len(valid)))
	for _, e := range valid {
		ip := e.IP.Unmap()
		if ip.Is4() {
			buf = append(buf, resolverReportFamilyV4)
			arr := ip.As4()
			buf = append(buf, arr[:]...)
		} else {
			buf = append(buf, resolverReportFamilyV6)
			arr := ip.As16()
			buf = append(buf, arr[:]...)
		}
	}
	return buf
}

// DecodeResolverReport parses a payload encoded by EncodeResolverReport.
// Returns an error on truncation or unknown address family. Returns an empty
// slice (no error) for an explicit zero-entry payload.
func DecodeResolverReport(payload []byte) ([]ResolverReportEntry, error) {
	if len(payload) == 0 {
		return nil, ErrResolverReportEmpty
	}
	count := int(payload[0])
	if count == 0 {
		return nil, nil
	}
	if count > resolverReportMaxEntries {
		return nil, ErrResolverReportTooManyEntries
	}

	pos := 1
	entries := make([]ResolverReportEntry, 0, count)
	for i := 0; i < count; i++ {
		if pos+1 > len(payload) {
			return nil, ErrResolverReportShort
		}
		family := payload[pos]
		pos++

		var ip netip.Addr
		switch family {
		case resolverReportFamilyV4:
			if pos+4 > len(payload) {
				return nil, ErrResolverReportShort
			}
			var arr [4]byte
			copy(arr[:], payload[pos:pos+4])
			ip = netip.AddrFrom4(arr)
			pos += 4
		case resolverReportFamilyV6:
			if pos+16 > len(payload) {
				return nil, ErrResolverReportShort
			}
			var arr [16]byte
			copy(arr[:], payload[pos:pos+16])
			ip = netip.AddrFrom16(arr).Unmap()
			pos += 16
		default:
			return nil, ErrResolverReportBadFamily
		}

		if !ip.IsValid() {
			continue
		}
		entries = append(entries, ResolverReportEntry{IP: ip})
	}
	return entries, nil
}
