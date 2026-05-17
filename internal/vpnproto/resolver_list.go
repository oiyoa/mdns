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

// ResolverListEntry is one (IP, port, opaque score) item the server returns
// to the client in PACKET_RESOLVER_LIST_RESPONSE.
type ResolverListEntry struct {
	IP    netip.Addr
	Port  uint16
	Score uint16
}

const (
	resolverListFamilyV4 = 4
	resolverListFamilyV6 = 6
	// Hard cap on entries the wire format can carry per response. Picked above
	// the server's intended top-25 so we have headroom.
	ResolverListMaxEntries = 64
)

var (
	ErrResolverListEmpty          = errors.New("resolver list payload empty")
	ErrResolverListShort          = errors.New("resolver list payload truncated")
	ErrResolverListBadFamily      = errors.New("resolver list has unknown address family")
	ErrResolverListTooManyEntries = errors.New("resolver list has too many entries")
)

// EncodeResolverList builds the PACKET_RESOLVER_LIST_RESPONSE payload:
//
//	byte 0           : entry count (uint8)
//	per entry        : family u8, addr (4 or 16 bytes), port u16 BE, score u16 BE
func EncodeResolverList(entries []ResolverListEntry) []byte {
	valid := make([]ResolverListEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IP.IsValid() {
			continue
		}
		valid = append(valid, e)
		if len(valid) >= ResolverListMaxEntries {
			break
		}
	}
	if len(valid) == 0 {
		return []byte{0}
	}

	size := 1
	for _, e := range valid {
		if e.IP.Is4() || e.IP.Is4In6() {
			size += 1 + 4 + 2 + 2
		} else {
			size += 1 + 16 + 2 + 2
		}
	}
	buf := make([]byte, 0, size)
	buf = append(buf, byte(len(valid)))
	for _, e := range valid {
		ip := e.IP.Unmap()
		if ip.Is4() {
			buf = append(buf, resolverListFamilyV4)
			arr := ip.As4()
			buf = append(buf, arr[:]...)
		} else {
			buf = append(buf, resolverListFamilyV6)
			arr := ip.As16()
			buf = append(buf, arr[:]...)
		}
		var portB [2]byte
		binary.BigEndian.PutUint16(portB[:], e.Port)
		buf = append(buf, portB[:]...)
		var scoreB [2]byte
		binary.BigEndian.PutUint16(scoreB[:], e.Score)
		buf = append(buf, scoreB[:]...)
	}
	return buf
}

func DecodeResolverList(payload []byte) ([]ResolverListEntry, error) {
	if len(payload) == 0 {
		return nil, ErrResolverListEmpty
	}
	count := int(payload[0])
	if count == 0 {
		return nil, nil
	}
	if count > ResolverListMaxEntries {
		return nil, ErrResolverListTooManyEntries
	}

	pos := 1
	entries := make([]ResolverListEntry, 0, count)
	for i := 0; i < count; i++ {
		if pos+1 > len(payload) {
			return nil, ErrResolverListShort
		}
		family := payload[pos]
		pos++

		var ip netip.Addr
		switch family {
		case resolverListFamilyV4:
			if pos+4+2+2 > len(payload) {
				return nil, ErrResolverListShort
			}
			var arr [4]byte
			copy(arr[:], payload[pos:pos+4])
			ip = netip.AddrFrom4(arr)
			pos += 4
		case resolverListFamilyV6:
			if pos+16+2+2 > len(payload) {
				return nil, ErrResolverListShort
			}
			var arr [16]byte
			copy(arr[:], payload[pos:pos+16])
			ip = netip.AddrFrom16(arr).Unmap()
			pos += 16
		default:
			return nil, ErrResolverListBadFamily
		}

		port := binary.BigEndian.Uint16(payload[pos : pos+2])
		pos += 2
		score := binary.BigEndian.Uint16(payload[pos : pos+2])
		pos += 2

		if !ip.IsValid() {
			continue
		}
		entries = append(entries, ResolverListEntry{IP: ip, Port: port, Score: score})
	}
	return entries, nil
}
