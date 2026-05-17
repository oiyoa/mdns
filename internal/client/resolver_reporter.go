// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// resolverReporter watches the balancer's active resolver set and, whenever it
// changes, sends a PACKET_RESOLVER_REPORT through Stream 0 telling the server
// the authoritative list of resolvers this client is using.
//
// Send policy:
//   - Initial send when the session becomes ready.
//   - Subsequent sends only when the active set differs from the last
//     successfully sent set (idempotent — no traffic when nothing has changed).
//   - Failures are silent and uncached: a failed send leaves lastSent unchanged
//     so the next trigger will retry.
type resolverReporter struct {
	client *Client
	log    *logger.Logger

	signal  chan struct{} // buffered size 1; coalesces multiple changes
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	nextSeq atomic.Uint32

	lastSentMu sync.Mutex
	lastSent   []VpnProto.ResolverReportEntry
}

func newResolverReporter(c *Client, log *logger.Logger) *resolverReporter {
	return &resolverReporter{
		client: c,
		log:    log,
		signal: make(chan struct{}, 1),
	}
}

// Trigger schedules a check. Non-blocking; safe to call from any goroutine
// (including under the balancer mutex).
func (r *resolverReporter) Trigger() {
	if r == nil {
		return
	}
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

// ResetLastSent clears the dedupe cache so the next Trigger will resend even
// if the active set looks identical. Called when the session is reset so the
// new server-side session record receives a fresh report.
func (r *resolverReporter) ResetLastSent() {
	if r == nil {
		return
	}
	r.lastSentMu.Lock()
	r.lastSent = nil
	r.lastSentMu.Unlock()
}

// Start launches the reporter loop. Calling Start while already running first
// tears down the previous goroutine, so the reporter can be cycled by the
// async runtime restart path.
func (r *resolverReporter) Start(parent context.Context) {
	if r == nil {
		return
	}
	r.Stop()
	r.ctx, r.cancel = context.WithCancel(parent)
	r.wg.Add(1)
	go r.run()
}

func (r *resolverReporter) Stop() {
	if r == nil || r.cancel == nil {
		return
	}
	r.cancel()
	r.wg.Wait()
	r.cancel = nil
	r.ctx = nil
}

func (r *resolverReporter) run() {
	defer r.wg.Done()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.signal:
			r.maybeSend()
		}
	}
}

func (r *resolverReporter) maybeSend() {
	if r == nil || r.client == nil || !r.client.SessionReady() {
		return
	}
	// Honor the per-client opt-out
	if !r.client.cfg.ResolverReportEnabled {
		return
	}

	connections := r.client.balancer.ActiveConnections()
	current := r.buildEntries(connections)

	r.lastSentMu.Lock()
	defer r.lastSentMu.Unlock()
	if resolverEntriesEqual(current, r.lastSent) {
		return
	}
	if r.sendReport(current) {
		r.lastSent = current
	}
}

func (r *resolverReporter) buildEntries(conns []Connection) []VpnProto.ResolverReportEntry {
	if len(conns) == 0 {
		return nil
	}
	entries := make([]VpnProto.ResolverReportEntry, 0, len(conns))
	seen := make(map[netip.Addr]struct{}, len(conns))
	for _, conn := range conns {
		ip, err := netip.ParseAddr(conn.Resolver)
		if err != nil || !ip.IsValid() {
			continue
		}
		ip = ip.Unmap()
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		entries = append(entries, VpnProto.ResolverReportEntry{IP: ip})
	}
	slices.SortFunc(entries, func(a, b VpnProto.ResolverReportEntry) int {
		return a.IP.Compare(b.IP)
	})
	return entries
}

func (r *resolverReporter) sendReport(entries []VpnProto.ResolverReportEntry) bool {
	if r == nil || r.client == nil {
		return false
	}

	r.client.streamsMu.RLock()
	s0 := r.client.active_streams[0]
	r.client.streamsMu.RUnlock()
	if s0 == nil {
		return false
	}

	payload := VpnProto.EncodeResolverReport(entries)
	seq := uint16(r.nextSeq.Add(1))

	ok := s0.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_RESOLVER_REPORT),
		Enums.PACKET_RESOLVER_REPORT,
		seq,
		0,
		0,
		0,
		0,
		payload,
	)
	if !ok {
		return false
	}
	if r.log != nil {
		r.log.Infof(
			"<green>\U0001F4E1 Resolver Report Sent</green> | <cyan>%d resolvers</cyan>",
			len(entries),
		)
	}
	return true
}

func resolverEntriesEqual(a, b []VpnProto.ResolverReportEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].IP != b[i].IP {
			return false
		}
	}
	return true
}
