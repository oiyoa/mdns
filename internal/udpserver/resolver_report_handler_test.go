// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"net/netip"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func TestHandleResolverReportReplacesSet(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(11)
	s.sessions.byID[record.ID] = record

	// Seed with one IP via the API to make sure the handler REPLACES, not merges.
	record.setResolverSet([]netip.Addr{mustAddr(t, "203.0.113.1")})

	payload := VpnProto.EncodeResolverReport([]VpnProto.ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
		{IP: mustAddr(t, "149.112.112.112")},
	})

	ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_REPORT,
		Payload:    payload,
	})
	if !ok {
		t.Fatal("handler should return true")
	}

	got := record.resolverList()
	if len(got) != 2 {
		t.Fatalf("expected 2 resolvers after report, got %d (set=%v)", len(got), got)
	}
	want := map[netip.Addr]bool{
		mustAddr(t, "1.1.1.1"):         true,
		mustAddr(t, "149.112.112.112"): true,
	}
	for _, ip := range got {
		if !want[ip] {
			t.Fatalf("unexpected resolver in set after report: %v", ip)
		}
	}
	// The previously seeded 203.0.113.1 must be gone.
	for _, ip := range got {
		if ip == mustAddr(t, "203.0.113.1") {
			t.Fatal("previous resolver should have been replaced, not merged")
		}
	}
}

func TestHandleResolverReportIgnoresUnknownSession(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	payload := VpnProto.EncodeResolverReport([]VpnProto.ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
	})
	ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:  99,
		PacketType: Enums.PACKET_RESOLVER_REPORT,
		Payload:    payload,
	})
	// Should still return true (handled = "yes, recognized") and not panic.
	if !ok {
		t.Fatal("handler should return true for unknown session (no-op)")
	}
}

func TestHandleResolverReportToleratesAbsurdCount(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(12)
	s.sessions.byID[record.ID] = record

	// Pre-seed; handler should leave the set untouched on parse failure.
	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})

	// payload[0] = 0xFF claims 255 entries, well above the cap of 64.
	ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_REPORT,
		Payload:    []byte{0xFF},
	})
	if !ok {
		t.Fatal("handler should return true even on malformed payload")
	}
	got := record.resolverList()
	if len(got) != 1 || got[0] != mustAddr(t, "1.1.1.1") {
		t.Fatalf("malformed payload must not overwrite existing set, got %v", got)
	}
}

func TestHandleResolverReportToleratesTruncatedPayload(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(15)
	s.sessions.byID[record.ID] = record

	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})

	// Claims 2 entries but stops after the first family byte.
	ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_REPORT,
		Payload:    []byte{2, 4},
	})
	if !ok {
		t.Fatal("handler should return true even on truncated payload")
	}
	got := record.resolverList()
	if len(got) != 1 || got[0] != mustAddr(t, "1.1.1.1") {
		t.Fatalf("truncated payload must not overwrite existing set, got %v", got)
	}
}

func TestHandleResolverReportAcceptsEmptyList(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(13)
	s.sessions.byID[record.ID] = record

	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})

	// Encode an explicit zero-count payload — client telling us "no resolvers."
	payload := VpnProto.EncodeResolverReport(nil)
	ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_REPORT,
		Payload:    payload,
	})
	if !ok {
		t.Fatal("handler should return true on empty list")
	}
	if got := record.resolverList(); len(got) != 0 {
		t.Fatalf("expected empty resolver set, got %v", got)
	}
}
