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

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestResolverReportRoundTripIPv4(t *testing.T) {
	entries := []ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
		{IP: mustAddr(t, "149.112.112.112")},
	}
	payload := EncodeResolverReport(entries)

	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	for i := range entries {
		if got[i].IP != entries[i].IP {
			t.Fatalf("entry %d mismatch: got=%v want=%v", i, got[i], entries[i])
		}
	}
}

func TestResolverReportRoundTripIPv6(t *testing.T) {
	entries := []ResolverReportEntry{
		{IP: mustAddr(t, "2606:4700:4700::1111")},
		{IP: mustAddr(t, "2620:fe::fe")},
	}
	payload := EncodeResolverReport(entries)

	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	for i := range entries {
		if got[i].IP != entries[i].IP {
			t.Fatalf("entry %d mismatch: got=%v want=%v", i, got[i], entries[i])
		}
	}
}

func TestResolverReportEncodeSkipsInvalid(t *testing.T) {
	entries := []ResolverReportEntry{
		{IP: netip.Addr{}},
		{IP: mustAddr(t, "1.1.1.1")},
	}
	payload := EncodeResolverReport(entries)
	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 || got[0].IP != entries[1].IP {
		t.Fatalf("expected the invalid entry to be dropped: got=%v", got)
	}
}

func TestResolverReportEncodeEmptyList(t *testing.T) {
	payload := EncodeResolverReport(nil)
	if len(payload) != 1 || payload[0] != 0 {
		t.Fatalf("expected single zero-count byte, got %v", payload)
	}
	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode zero-count: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %d", len(got))
	}
}

func TestResolverReportEncodeRespectsCap(t *testing.T) {
	entries := make([]ResolverReportEntry, 100)
	for i := range entries {
		ip := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
		entries[i] = ResolverReportEntry{IP: ip}
	}
	payload := EncodeResolverReport(entries)
	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != resolverReportMaxEntries {
		t.Fatalf("expected %d entries after cap, got %d", resolverReportMaxEntries, len(got))
	}
}

func TestResolverReportDecodeRejectsTruncated(t *testing.T) {
	entries := []ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
		{IP: mustAddr(t, "8.8.8.8")},
	}
	full := EncodeResolverReport(entries)

	// Truncate just past the count + first family marker.
	truncated := full[:2]
	if _, err := DecodeResolverReport(truncated); err != ErrResolverReportShort {
		t.Fatalf("expected ErrResolverReportShort, got %v", err)
	}
}

func TestResolverReportDecodeRejectsBadFamily(t *testing.T) {
	payload := []byte{1, 9, 1, 2, 3, 4} // family 9 is invalid
	if _, err := DecodeResolverReport(payload); err != ErrResolverReportBadFamily {
		t.Fatalf("expected ErrResolverReportBadFamily, got %v", err)
	}
}

func TestResolverReportDecodeRejectsEmptyPayload(t *testing.T) {
	if _, err := DecodeResolverReport(nil); err != ErrResolverReportEmpty {
		t.Fatalf("expected ErrResolverReportEmpty, got %v", err)
	}
}

func TestResolverReportDecodeRejectsAbsurdCount(t *testing.T) {
	payload := []byte{200} // claims 200 entries
	if _, err := DecodeResolverReport(payload); err != ErrResolverReportTooManyEntries {
		t.Fatalf("expected ErrResolverReportTooManyEntries, got %v", err)
	}
}

func TestResolverReportV6IsUnmappedToV4WhenPossible(t *testing.T) {
	// Encode an IPv4-mapped IPv6 address. After roundtrip it should come back
	// as the plain IPv4 form.
	v4 := mustAddr(t, "1.1.1.1")
	entries := []ResolverReportEntry{{IP: v4}}
	payload := EncodeResolverReport(entries)

	got, err := DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got[0].IP.Is4() {
		t.Fatalf("expected IPv4 form after roundtrip, got %v", got[0].IP)
	}
}
