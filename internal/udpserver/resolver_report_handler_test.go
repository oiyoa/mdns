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

func TestSetResolverSetReportsChange(t *testing.T) {
	record := newTestSessionRecord(50)

	if !record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")}) {
		t.Fatal("first setResolverSet must report changed=true")
	}
	if record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")}) {
		t.Fatal("identical setResolverSet must report changed=false")
	}
	if !record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1"), mustAddr(t, "8.8.8.8")}) {
		t.Fatal("adding an IP must report changed=true")
	}
	if !record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")}) {
		t.Fatal("removing an IP must report changed=true")
	}
	if !record.setResolverSet(nil) {
		t.Fatal("clearing must report changed=true")
	}
	if record.setResolverSet(nil) {
		t.Fatal("clearing twice must report changed=false")
	}
}

func TestAcceptResolverReportSeqDedupesFanout(t *testing.T) {
	record := newTestSessionRecord(51)

	if !record.acceptResolverReportSeq(7) {
		t.Fatal("first seq must be accepted")
	}
	if record.acceptResolverReportSeq(7) {
		t.Fatal("identical seq must be rejected (fanout copy)")
	}
	if record.acceptResolverReportSeq(7) {
		t.Fatal("identical seq must remain rejected on repeat")
	}
	if !record.acceptResolverReportSeq(8) {
		t.Fatal("novel seq must be accepted")
	}
	if record.acceptResolverReportSeq(8) {
		t.Fatal("seq 8 fanout copy must be rejected")
	}
	if !record.acceptResolverReportSeq(7) {
		t.Fatal("seq 7 reused after a different seq must be accepted (no LRU history)")
	}
}

func TestHandleResolverReportDropsDuplicateSeq(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(52)
	s.sessions.byID[record.ID] = record

	first := VpnProto.EncodeResolverReport([]VpnProto.ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
	})
	second := VpnProto.EncodeResolverReport([]VpnProto.ResolverReportEntry{
		{IP: mustAddr(t, "1.1.1.1")},
		{IP: mustAddr(t, "8.8.8.8")},
	})

	// First seq=42 lands and replaces the set.
	if ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:   record.ID,
		PacketType:  Enums.PACKET_RESOLVER_REPORT,
		SequenceNum: 42,
		Payload:     first,
	}); !ok {
		t.Fatal("handler should return true for seq=42")
	}
	if got := record.resolverList(); len(got) != 1 {
		t.Fatalf("after first report want 1 resolver, got %d", len(got))
	}

	// Fanout copy of seq=42 carrying *different* payload must be dropped
	// before the parser/setResolverSet runs — so the set must NOT change.
	if ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:   record.ID,
		PacketType:  Enums.PACKET_RESOLVER_REPORT,
		SequenceNum: 42,
		Payload:     second,
	}); !ok {
		t.Fatal("handler should return true even for duplicate seq")
	}
	if got := record.resolverList(); len(got) != 1 {
		t.Fatalf("dup-seq report must not mutate set, got %d resolvers", len(got))
	}

	// A new seq carrying the same expanded payload must land.
	if ok := s.handleResolverReportRequest(VpnProto.Packet{
		SessionID:   record.ID,
		PacketType:  Enums.PACKET_RESOLVER_REPORT,
		SequenceNum: 43,
		Payload:     second,
	}); !ok {
		t.Fatal("handler should return true for seq=43")
	}
	if got := record.resolverList(); len(got) != 2 {
		t.Fatalf("after seq=43 want 2 resolvers, got %d", len(got))
	}
}

func TestHandleResolverReportV2ReplacesSetAndScores(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(70)
	s.sessions.byID[record.ID] = record

	entries := []VpnProto.ResolverReportV2Entry{
		{IP: mustAddr(t, "1.1.1.1"), SuccessCount: 100, FailureCount: 1, EWMARttMs: 5},
		{IP: mustAddr(t, "8.8.8.8"), SuccessCount: 50, FailureCount: 10, EWMARttMs: 25},
	}
	payload := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindFull, entries)

	ok := s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID:   record.ID,
		PacketType:  Enums.PACKET_RESOLVER_REPORT_V2,
		SequenceNum: 1,
		Payload:     payload,
	})
	if !ok {
		t.Fatal("handler should return true")
	}

	got := record.resolverList()
	if len(got) != 2 {
		t.Fatalf("expected 2 resolvers, got %d (%v)", len(got), got)
	}
	scored := record.resolverScoreSnapshot()
	if len(scored) != 2 {
		t.Fatalf("expected 2 scored entries, got %d", len(scored))
	}
	if scored[mustAddr(t, "1.1.1.1")].SuccessCount != 100 {
		t.Fatalf("score not preserved: %+v", scored)
	}
}

func TestHandleResolverReportV2KindAlwaysReplaces(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(71)
	s.sessions.byID[record.ID] = record

	full := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindFull, []VpnProto.ResolverReportV2Entry{
		{IP: mustAddr(t, "1.1.1.1"), SuccessCount: 100},
	})
	if !s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID: record.ID, PacketType: Enums.PACKET_RESOLVER_REPORT_V2, SequenceNum: 1, Payload: full,
	}) {
		t.Fatal("first handler call should return true")
	}

	// Client always emits the full snapshot regardless of kind, so Incremental
	// must also REPLACE — otherwise stale entries linger after a resolver drops.
	inc := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindIncremental, []VpnProto.ResolverReportV2Entry{
		{IP: mustAddr(t, "8.8.8.8"), SuccessCount: 7},
	})
	if !s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID: record.ID, PacketType: Enums.PACKET_RESOLVER_REPORT_V2, SequenceNum: 2, Payload: inc,
	}) {
		t.Fatal("incremental handler call should return true")
	}

	scored := record.resolverScoreSnapshot()
	if _, exists := scored[mustAddr(t, "1.1.1.1")]; exists {
		t.Fatalf("incremental should replace, not merge — 1.1.1.1 should be gone, got %+v", scored)
	}
	if scored[mustAddr(t, "8.8.8.8")].SuccessCount != 7 {
		t.Fatalf("incremental's new entry must land, got %+v", scored)
	}
}

func TestHandleResolverReportV2DropsDuplicateSeq(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(72)
	s.sessions.byID[record.ID] = record

	first := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindFull, []VpnProto.ResolverReportV2Entry{
		{IP: mustAddr(t, "1.1.1.1"), SuccessCount: 10},
	})
	second := VpnProto.EncodeResolverReportV2(VpnProto.ResolverReportV2KindFull, []VpnProto.ResolverReportV2Entry{
		{IP: mustAddr(t, "8.8.8.8"), SuccessCount: 999},
	})

	if !s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID: record.ID, PacketType: Enums.PACKET_RESOLVER_REPORT_V2, SequenceNum: 7, Payload: first,
	}) {
		t.Fatal("first handler call should return true")
	}
	if !s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID: record.ID, PacketType: Enums.PACKET_RESOLVER_REPORT_V2, SequenceNum: 7, Payload: second,
	}) {
		t.Fatal("duplicate-seq handler call should return true (silent drop)")
	}

	scored := record.resolverScoreSnapshot()
	if _, exists := scored[mustAddr(t, "8.8.8.8")]; exists {
		t.Fatalf("duplicate-seq payload must not mutate state, got %+v", scored)
	}
	if scored[mustAddr(t, "1.1.1.1")].SuccessCount != 10 {
		t.Fatalf("first payload should still be in place, got %+v", scored)
	}
}

func TestHandleResolverReportV2RejectsMalformedPayload(t *testing.T) {
	s := newTestServerForStreamSyn("TCP")
	record := newTestSessionRecord(73)
	s.sessions.byID[record.ID] = record
	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})

	ok := s.handleResolverReportV2Request(VpnProto.Packet{
		SessionID:   record.ID,
		PacketType:  Enums.PACKET_RESOLVER_REPORT_V2,
		SequenceNum: 1,
		Payload:     []byte{0xFF, 1, 4, 1, 2, 3}, // truncated
	})
	if !ok {
		t.Fatal("malformed payload should still return true")
	}
	got := record.resolverList()
	if len(got) != 1 || got[0] != mustAddr(t, "1.1.1.1") {
		t.Fatalf("malformed payload must not overwrite set, got %v", got)
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
