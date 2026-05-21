// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Wire-stable values; never renumber.
type ResolverReportV2Kind uint8

const (
	ResolverReportV2KindFull              ResolverReportV2Kind = 0
	ResolverReportV2KindIncremental       ResolverReportV2Kind = 1
	ResolverReportV2KindSessionCloseFlush ResolverReportV2Kind = 2
)

type ResolverReportV2Entry struct {
	IP             netip.Addr
	SuccessCount   uint16
	FailureCount   uint16
	EWMARttMs      uint16
	LastUsedAgeSec uint16
}

const (
	resolverReportV2FamilyV4 = 4
	resolverReportV2FamilyV6 = 6

	// Wire layout per entry:
	//   family (uint8) | addr (4 or 16 bytes) | success (uint16) | failure (uint16) | rtt (uint16) | age (uint16)
	// = 1 + (4|16) + 8 bytes per entry. Header is 2 bytes: kind + count.
	resolverReportV2EntryFixedSize = 1 + 8
	resolverReportV2HeaderSize     = 2
	resolverReportV2MaxEntries     = 64
)

var (
	ErrResolverReportV2Empty          = errors.New("resolver report v2 payload empty")
	ErrResolverReportV2Short          = errors.New("resolver report v2 payload truncated")
	ErrResolverReportV2BadFamily      = errors.New("resolver report v2 has unknown address family")
	ErrResolverReportV2TooManyEntries = errors.New("resolver report v2 has too many entries")
	ErrResolverReportV2BadKind        = errors.New("resolver report v2 has unknown kind")
)

// Wire layout: kind(u8) | count(u8) | [family(u8) | addr(4|16) | succ(u16) | fail(u16) | rtt(u16) | age(u16)] × count.
func EncodeResolverReportV2(kind ResolverReportV2Kind, entries []ResolverReportV2Entry) []byte {
	valid := make([]ResolverReportV2Entry, 0, len(entries))
	for _, e := range entries {
		if !e.IP.IsValid() {
			continue
		}
		valid = append(valid, e)
		if len(valid) >= resolverReportV2MaxEntries {
			break
		}
	}

	size := resolverReportV2HeaderSize
	for _, e := range valid {
		ip := e.IP.Unmap()
		if ip.Is4() {
			size += 1 + 4 + 8
		} else {
			size += 1 + 16 + 8
		}
	}

	buf := make([]byte, 0, size)
	buf = append(buf, byte(kind))
	buf = append(buf, byte(len(valid)))
	for _, e := range valid {
		ip := e.IP.Unmap()
		if ip.Is4() {
			buf = append(buf, resolverReportV2FamilyV4)
			arr := ip.As4()
			buf = append(buf, arr[:]...)
		} else {
			buf = append(buf, resolverReportV2FamilyV6)
			arr := ip.As16()
			buf = append(buf, arr[:]...)
		}
		buf = appendUint16BE(buf, e.SuccessCount)
		buf = appendUint16BE(buf, e.FailureCount)
		buf = appendUint16BE(buf, e.EWMARttMs)
		buf = appendUint16BE(buf, e.LastUsedAgeSec)
	}
	return buf
}

func DecodeResolverReportV2(payload []byte) (ResolverReportV2Kind, []ResolverReportV2Entry, error) {
	if len(payload) < resolverReportV2HeaderSize {
		return 0, nil, ErrResolverReportV2Empty
	}
	kind := ResolverReportV2Kind(payload[0])
	switch kind {
	case ResolverReportV2KindFull, ResolverReportV2KindIncremental, ResolverReportV2KindSessionCloseFlush:
	default:
		return 0, nil, ErrResolverReportV2BadKind
	}

	count := int(payload[1])
	if count > resolverReportV2MaxEntries {
		return 0, nil, ErrResolverReportV2TooManyEntries
	}
	if count == 0 {
		return kind, nil, nil
	}

	pos := resolverReportV2HeaderSize
	entries := make([]ResolverReportV2Entry, 0, count)
	for i := 0; i < count; i++ {
		if pos+1 > len(payload) {
			return 0, nil, ErrResolverReportV2Short
		}
		family := payload[pos]
		pos++

		var ip netip.Addr
		switch family {
		case resolverReportV2FamilyV4:
			if pos+4 > len(payload) {
				return 0, nil, ErrResolverReportV2Short
			}
			var arr [4]byte
			copy(arr[:], payload[pos:pos+4])
			ip = netip.AddrFrom4(arr)
			pos += 4
		case resolverReportV2FamilyV6:
			if pos+16 > len(payload) {
				return 0, nil, ErrResolverReportV2Short
			}
			var arr [16]byte
			copy(arr[:], payload[pos:pos+16])
			ip = netip.AddrFrom16(arr).Unmap()
			pos += 16
		default:
			return 0, nil, ErrResolverReportV2BadFamily
		}

		if pos+8 > len(payload) {
			return 0, nil, ErrResolverReportV2Short
		}
		entry := ResolverReportV2Entry{
			IP:             ip,
			SuccessCount:   binary.BigEndian.Uint16(payload[pos : pos+2]),
			FailureCount:   binary.BigEndian.Uint16(payload[pos+2 : pos+4]),
			EWMARttMs:      binary.BigEndian.Uint16(payload[pos+4 : pos+6]),
			LastUsedAgeSec: binary.BigEndian.Uint16(payload[pos+6 : pos+8]),
		}
		pos += 8

		if !ip.IsValid() {
			continue
		}
		entries = append(entries, entry)
	}
	return kind, entries, nil
}

func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
