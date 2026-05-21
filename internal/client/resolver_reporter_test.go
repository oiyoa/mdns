// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"net/netip"
	"testing"

	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestResolverV2EntriesEqualOrderSensitive(t *testing.T) {
	a := []VpnProto.ResolverReportV2Entry{
		{IP: netip.MustParseAddr("1.1.1.1")},
		{IP: netip.MustParseAddr("8.8.8.8")},
	}
	b := []VpnProto.ResolverReportV2Entry{
		{IP: netip.MustParseAddr("8.8.8.8")},
		{IP: netip.MustParseAddr("1.1.1.1")},
	}
	if resolverV2EntriesEqual(a, b) {
		t.Fatal("entries with different order should not compare equal — caller is expected to sort first")
	}
}

func TestResolverV2EntriesEqualHandlesNilAndEmpty(t *testing.T) {
	var a, b []VpnProto.ResolverReportV2Entry
	if !resolverV2EntriesEqual(a, b) {
		t.Fatal("two nil slices should compare equal")
	}
	if !resolverV2EntriesEqual([]VpnProto.ResolverReportV2Entry{}, []VpnProto.ResolverReportV2Entry{}) {
		t.Fatal("two empty slices should compare equal")
	}
	if resolverV2EntriesEqual(a, []VpnProto.ResolverReportV2Entry{{IP: netip.MustParseAddr("1.1.1.1")}}) {
		t.Fatal("nil vs non-empty should not compare equal")
	}
}

func TestBuildEntriesSortsAndDropsInvalid(t *testing.T) {
	r := &resolverReporter{}
	scores := []ResolverScoreSnapshot{
		{IP: netip.MustParseAddr("8.8.8.8"), SuccessCount: 10, FailureCount: 2, EWMARttMs: 25, HasRtt: true},
		{IP: netip.MustParseAddr("1.1.1.1"), SuccessCount: 100, FailureCount: 0, EWMARttMs: 5, HasRtt: true},
		{}, // invalid (zero netip.Addr)
	}
	got := r.buildEntries(scores)
	if len(got) != 2 {
		t.Fatalf("expected 2 valid entries, got %d (%v)", len(got), got)
	}
	if got[0].IP.String() != "1.1.1.1" || got[1].IP.String() != "8.8.8.8" {
		t.Fatalf("expected sorted order, got %v", got)
	}
	if got[0].SuccessCount != 100 || got[0].FailureCount != 0 || got[0].EWMARttMs != 5 {
		t.Fatalf("score not preserved on entry 0: %+v", got[0])
	}
}

func TestBuildEntriesClampsSaturatingCounters(t *testing.T) {
	r := &resolverReporter{}
	scores := []ResolverScoreSnapshot{
		{IP: netip.MustParseAddr("1.1.1.1"), SuccessCount: 1 << 40, FailureCount: 1 << 32, EWMARttMs: 0xFFFF, HasRtt: true},
	}
	got := r.buildEntries(scores)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].SuccessCount != 0xFFFF || got[0].FailureCount != 0xFFFF || got[0].EWMARttMs != 0xFFFF {
		t.Fatalf("expected uint16 saturation, got %+v", got[0])
	}
}

func TestBuildEntriesOmitsRttWhenHasRttFalse(t *testing.T) {
	r := &resolverReporter{}
	got := r.buildEntries([]ResolverScoreSnapshot{
		{IP: netip.MustParseAddr("1.1.1.1"), SuccessCount: 10, EWMARttMs: 99, HasRtt: false},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if got[0].EWMARttMs != 0 {
		t.Fatalf("HasRtt=false must zero EWMARttMs on the wire (sentinel for 'no info'), got %d", got[0].EWMARttMs)
	}
}

func TestBuildEntriesRoundTripsThroughCodec(t *testing.T) {
	r := &resolverReporter{}
	scores := []ResolverScoreSnapshot{
		{IP: netip.MustParseAddr("1.1.1.1"), SuccessCount: 100, FailureCount: 1, EWMARttMs: 5, HasRtt: true},
		{IP: netip.MustParseAddr("149.112.112.112"), SuccessCount: 42, FailureCount: 0, EWMARttMs: 12, HasRtt: true},
	}
	entries := r.buildEntries(scores)
	payload := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindFull, entries)
	kind, decoded, err := VpnProto.DecodeResolverReportV2(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if kind != VpnProto.ResolverReportV2KindFull {
		t.Fatalf("kind: got=%d want=%d", kind, VpnProto.ResolverReportV2KindFull)
	}
	if !resolverV2EntriesEqual(entries, decoded) {
		t.Fatalf("roundtrip mismatch: encoded=%v decoded=%v", entries, decoded)
	}
}

func TestResetLastSentClearsState(t *testing.T) {
	r := &resolverReporter{}
	r.lastSent = []VpnProto.ResolverReportV2Entry{{IP: netip.MustParseAddr("1.1.1.1"), SuccessCount: 1}}
	r.ResetLastSent()
	r.lastSentMu.Lock()
	defer r.lastSentMu.Unlock()
	if r.lastSent != nil {
		t.Fatalf("expected lastSent cleared, got %v", r.lastSent)
	}
}
