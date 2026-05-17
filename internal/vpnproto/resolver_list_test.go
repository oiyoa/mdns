// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"net/netip"
	"testing"
)

func mustListAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestResolverListRoundTripIPv4(t *testing.T) {
	entries := []ResolverListEntry{
		{IP: mustListAddr(t, "1.1.1.1"), Port: 53, Score: 65000},
		{IP: mustListAddr(t, "8.8.8.8"), Port: 53, Score: 32000},
	}
	payload := EncodeResolverList(entries)
	got, err := DecodeResolverList(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	for i := range entries {
		if got[i].IP != entries[i].IP || got[i].Port != entries[i].Port || got[i].Score != entries[i].Score {
			t.Fatalf("entry %d mismatch: got=%v want=%v", i, got[i], entries[i])
		}
	}
}

func TestResolverListRoundTripIPv6(t *testing.T) {
	entries := []ResolverListEntry{
		{IP: mustListAddr(t, "2606:4700:4700::1111"), Port: 53, Score: 50000},
	}
	payload := EncodeResolverList(entries)
	got, err := DecodeResolverList(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].IP != entries[0].IP || got[0].Port != entries[0].Port || got[0].Score != entries[0].Score {
		t.Fatalf("entry mismatch: got=%v want=%v", got[0], entries[0])
	}
}

func TestResolverListEmptyPayloadRejected(t *testing.T) {
	if _, err := DecodeResolverList(nil); err != ErrResolverListEmpty {
		t.Fatalf("expected ErrResolverListEmpty, got %v", err)
	}
}

func TestResolverListZeroCountIsEmpty(t *testing.T) {
	got, err := DecodeResolverList([]byte{0})
	if err != nil {
		t.Fatalf("decode zero-count: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %d entries", len(got))
	}
}

func TestResolverListEncodeRespectsCap(t *testing.T) {
	entries := make([]ResolverListEntry, 200)
	for i := range entries {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		entries[i] = ResolverListEntry{IP: ip, Port: 53, Score: uint16(i)}
	}
	payload := EncodeResolverList(entries)
	got, err := DecodeResolverList(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != ResolverListMaxEntries {
		t.Fatalf("expected %d entries after cap, got %d", ResolverListMaxEntries, len(got))
	}
}

func TestResolverListDecodeRejectsTruncated(t *testing.T) {
	if _, err := DecodeResolverList([]byte{2, 4, 1, 1}); err != ErrResolverListShort {
		t.Fatalf("expected ErrResolverListShort, got %v", err)
	}
}

func TestResolverListDecodeRejectsBadFamily(t *testing.T) {
	payload := []byte{1, 9, 1, 2, 3, 4, 0, 53, 0xFF, 0xFF}
	if _, err := DecodeResolverList(payload); err != ErrResolverListBadFamily {
		t.Fatalf("expected ErrResolverListBadFamily, got %v", err)
	}
}

func TestResolverListDecodeRejectsAbsurdCount(t *testing.T) {
	if _, err := DecodeResolverList([]byte{200}); err != ErrResolverListTooManyEntries {
		t.Fatalf("expected ErrResolverListTooManyEntries, got %v", err)
	}
}

func TestResolverListEncodeSkipsInvalid(t *testing.T) {
	entries := []ResolverListEntry{
		{IP: netip.Addr{}, Port: 53, Score: 1000},
		{IP: mustListAddr(t, "1.1.1.1"), Port: 53, Score: 2000},
	}
	payload := EncodeResolverList(entries)
	got, err := DecodeResolverList(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].Score != 2000 {
		t.Fatalf("expected the invalid entry to be dropped: got=%v", got)
	}
}
