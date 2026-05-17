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

func TestResolverEntriesEqualOrderSensitive(t *testing.T) {
	a := []VpnProto.ResolverReportEntry{
		{IP: netip.MustParseAddr("1.1.1.1")},
		{IP: netip.MustParseAddr("8.8.8.8")},
	}
	b := []VpnProto.ResolverReportEntry{
		{IP: netip.MustParseAddr("8.8.8.8")},
		{IP: netip.MustParseAddr("1.1.1.1")},
	}
	if resolverEntriesEqual(a, b) {
		t.Fatal("entries with different order should not compare equal — caller is expected to sort first")
	}
}

func TestResolverEntriesEqualHandlesNilAndEmpty(t *testing.T) {
	var a, b []VpnProto.ResolverReportEntry
	if !resolverEntriesEqual(a, b) {
		t.Fatal("two nil slices should compare equal")
	}
	if !resolverEntriesEqual([]VpnProto.ResolverReportEntry{}, []VpnProto.ResolverReportEntry{}) {
		t.Fatal("two empty slices should compare equal")
	}
	if resolverEntriesEqual(a, []VpnProto.ResolverReportEntry{{IP: netip.MustParseAddr("1.1.1.1")}}) {
		t.Fatal("nil vs non-empty should not compare equal")
	}
}

func TestBuildEntriesSortsAndDedupes(t *testing.T) {
	r := &resolverReporter{}
	conns := []Connection{
		{Resolver: "8.8.8.8"},
		{Resolver: "1.1.1.1"},
		{Resolver: "1.1.1.1"}, // duplicate
		{Resolver: "not-an-ip"},
		{Resolver: ""},
	}
	got := r.buildEntries(conns)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (deduped, valid-only), got %d (%v)", len(got), got)
	}
	if got[0].IP.String() != "1.1.1.1" || got[1].IP.String() != "8.8.8.8" {
		t.Fatalf("expected sorted order, got %v", got)
	}
}

func TestBuildEntriesRoundTripsThroughCodec(t *testing.T) {
	r := &resolverReporter{}
	conns := []Connection{
		{Resolver: "1.1.1.1"},
		{Resolver: "149.112.112.112"},
	}
	entries := r.buildEntries(conns)
	payload := VpnProto.EncodeResolverReport(entries)
	decoded, err := VpnProto.DecodeResolverReport(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resolverEntriesEqual(entries, decoded) {
		t.Fatalf("roundtrip mismatch: encoded=%v decoded=%v", entries, decoded)
	}
}

func TestResetLastSentForcesResendOnNextTrigger(t *testing.T) {
	r := &resolverReporter{}
	r.lastSent = []VpnProto.ResolverReportEntry{{IP: netip.MustParseAddr("1.1.1.1")}}
	r.ResetLastSent()
	r.lastSentMu.Lock()
	defer r.lastSentMu.Unlock()
	if r.lastSent != nil {
		t.Fatalf("expected lastSent to be cleared, got %v", r.lastSent)
	}
}
