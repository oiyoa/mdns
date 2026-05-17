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
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func newTestServerWithLeaderboard() *Server {
	s := newTestServerForStreamSyn("TCP")
	s.resolverLeaderboard = newResolverLeaderboard()
	return s
}

func TestHandleResolverListRequestEmptyLeaderboard(t *testing.T) {
	s := newTestServerWithLeaderboard()
	record := newTestSessionRecord(33)
	s.sessions.byID[record.ID] = record

	ok := s.handleResolverListRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_LIST_REQUEST,
	})
	if !ok {
		t.Fatal("handler should return true")
	}
}

func TestHandleResolverListRequestProducesPayload(t *testing.T) {
	s := newTestServerWithLeaderboard()
	record := newTestSessionRecord(34)
	s.sessions.byID[record.ID] = record

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		s.resolverLeaderboard.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")}, time.Minute*5, 1200)
	}
	s.resolverLeaderboard.RecordSession(now, []netip.Addr{mustAddr(t, "8.8.8.8")}, time.Minute, 900)

	ok := s.handleResolverListRequest(VpnProto.Packet{
		SessionID:  record.ID,
		PacketType: Enums.PACKET_RESOLVER_LIST_REQUEST,
	})
	if !ok {
		t.Fatal("handler should return true")
	}

	stream, exists := record.getStream(0)
	if !exists || stream == nil {
		t.Fatal("expected stream 0 to exist")
	}
	if stream.FastTXQueueSize() == 0 {
		t.Fatal("expected a response packet to be queued on stream 0")
	}
}

func TestHandleResolverListRequestRateLimited(t *testing.T) {
	s := newTestServerWithLeaderboard()
	record := newTestSessionRecord(35)
	s.sessions.byID[record.ID] = record

	s.resolverLeaderboard.RecordSession(time.Now(), []netip.Addr{mustAddr(t, "1.1.1.1")}, time.Minute, 1200)

	for i := 0; i < 3; i++ {
		if !s.handleResolverListRequest(VpnProto.Packet{
			SessionID:  record.ID,
			PacketType: Enums.PACKET_RESOLVER_LIST_REQUEST,
		}) {
			t.Fatal("handler should always return true")
		}
	}

	stream, _ := record.getStream(0)
	if stream == nil {
		t.Fatal("expected stream 0")
	}
	if size := stream.FastTXQueueSize(); size > 1 {
		t.Fatalf("expected at most 1 response within rate-limit window, got %d", size)
	}
}

func TestHandleResolverListRequestIgnoresUnknownSession(t *testing.T) {
	s := newTestServerWithLeaderboard()
	if !s.handleResolverListRequest(VpnProto.Packet{
		SessionID:  99,
		PacketType: Enums.PACKET_RESOLVER_LIST_REQUEST,
	}) {
		t.Fatal("handler should return true (no-op) for unknown session")
	}
}

func TestCleanupClosedSessionRespectsRealSessionThreshold(t *testing.T) {
	s := newTestServerWithLeaderboard()
	record := newTestSessionRecord(36)
	record.CreatedAt = time.Now().Add(-2 * time.Second)
	record.packetsReceived.Store(3)
	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})
	s.sessions.byID[record.ID] = record

	s.cleanupClosedSession(record.ID, record)

	if _, unique := s.resolverLeaderboard.snapshotTop(0); unique != 0 {
		t.Fatalf("short-lived session must not contribute to leaderboard, got %d unique", unique)
	}
}

func TestCleanupClosedSessionRecordsLongSession(t *testing.T) {
	s := newTestServerWithLeaderboard()
	record := newTestSessionRecord(37)
	record.CreatedAt = time.Now().Add(-time.Minute)
	record.packetsReceived.Store(uint64(resolverLeaderboardMinPacketsRX + 5))
	record.DownloadMTU = 1200
	record.setResolverSet([]netip.Addr{mustAddr(t, "1.1.1.1")})
	s.sessions.byID[record.ID] = record

	s.cleanupClosedSession(record.ID, record)

	top, unique := s.resolverLeaderboard.snapshotTop(0)
	if unique != 1 || len(top) != 1 {
		t.Fatalf("real session must contribute, got %d unique top=%v", unique, top)
	}
	if top[0].AddrPort.Port() != resolverDefaultPort {
		t.Fatalf("expected default port %d on leaderboard key, got %d", resolverDefaultPort, top[0].AddrPort.Port())
	}
}
