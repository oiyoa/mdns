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

func TestEncodeDecodeResolverReportV2RoundTrip(t *testing.T) {
	entries := []ResolverReportV2Entry{
		{
			IP:             netip.MustParseAddr("1.1.1.1"),
			SuccessCount:   1000,
			FailureCount:   12,
			EWMARttMs:      35,
			LastUsedAgeSec: 4,
		},
		{
			IP:             netip.MustParseAddr("2606:4700:4700::1111"),
			SuccessCount:   42,
			FailureCount:   0,
			EWMARttMs:      120,
			LastUsedAgeSec: 60,
		},
	}

	encoded := EncodeResolverReportV2(ResolverReportV2KindFull, entries)
	kind, decoded, err := DecodeResolverReportV2(encoded)
	if err != nil {
		t.Fatalf("DecodeResolverReportV2: %v", err)
	}
	if kind != ResolverReportV2KindFull {
		t.Fatalf("kind: got=%d want=%d", kind, ResolverReportV2KindFull)
	}
	if len(decoded) != len(entries) {
		t.Fatalf("len mismatch: got=%d want=%d", len(decoded), len(entries))
	}
	for i, want := range entries {
		got := decoded[i]
		if got.IP != want.IP ||
			got.SuccessCount != want.SuccessCount ||
			got.FailureCount != want.FailureCount ||
			got.EWMARttMs != want.EWMARttMs ||
			got.LastUsedAgeSec != want.LastUsedAgeSec {
			t.Fatalf("entry %d mismatch:\n  got=%+v\n  want=%+v", i, got, want)
		}
	}
}

func TestEncodeResolverReportV2DropsInvalidIPs(t *testing.T) {
	entries := []ResolverReportV2Entry{
		{IP: netip.Addr{}},                          // invalid
		{IP: netip.MustParseAddr("8.8.8.8")},
	}
	encoded := EncodeResolverReportV2(ResolverReportV2KindIncremental, entries)
	_, decoded, err := DecodeResolverReportV2(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(decoded) != 1 || decoded[0].IP.String() != "8.8.8.8" {
		t.Fatalf("expected 1 valid entry, got %d: %v", len(decoded), decoded)
	}
}

func TestEncodeResolverReportV2EmptyList(t *testing.T) {
	encoded := EncodeResolverReportV2(ResolverReportV2KindFull, nil)
	kind, decoded, err := DecodeResolverReportV2(encoded)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if kind != ResolverReportV2KindFull {
		t.Fatalf("kind: got=%d want=%d", kind, ResolverReportV2KindFull)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected zero entries, got %d", len(decoded))
	}
}

func TestDecodeResolverReportV2RejectsBadKind(t *testing.T) {
	bad := []byte{0xFE, 0}
	_, _, err := DecodeResolverReportV2(bad)
	if err != ErrResolverReportV2BadKind {
		t.Fatalf("expected ErrResolverReportV2BadKind, got %v", err)
	}
}

func TestDecodeResolverReportV2RejectsBadFamily(t *testing.T) {
	bad := []byte{
		byte(ResolverReportV2KindFull),
		1,        // count
		0x09,     // unknown family
		1, 2, 3, 4,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, _, err := DecodeResolverReportV2(bad)
	if err != ErrResolverReportV2BadFamily {
		t.Fatalf("expected ErrResolverReportV2BadFamily, got %v", err)
	}
}

func TestDecodeResolverReportV2RejectsTooManyEntries(t *testing.T) {
	bad := []byte{byte(ResolverReportV2KindFull), byte(resolverReportV2MaxEntries + 1)}
	_, _, err := DecodeResolverReportV2(bad)
	if err != ErrResolverReportV2TooManyEntries {
		t.Fatalf("expected ErrResolverReportV2TooManyEntries, got %v", err)
	}
}

func TestDecodeResolverReportV2RejectsTruncated(t *testing.T) {
	bad := []byte{byte(ResolverReportV2KindFull), 2, resolverReportV2FamilyV4, 1, 2, 3, 4} // entry 1 score bytes missing
	_, _, err := DecodeResolverReportV2(bad)
	if err != ErrResolverReportV2Short {
		t.Fatalf("expected ErrResolverReportV2Short, got %v", err)
	}
}

func TestDecodeResolverReportV2EmptyPayload(t *testing.T) {
	_, _, err := DecodeResolverReportV2(nil)
	if err != ErrResolverReportV2Empty {
		t.Fatalf("expected ErrResolverReportV2Empty, got %v", err)
	}
}
