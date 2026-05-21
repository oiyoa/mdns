// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

const resolverReporterPeriodicInterval = 90 * time.Second

type resolverReporter struct {
	client *Client
	log    *logger.Logger

	signal  chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	nextSeq atomic.Uint32

	lastSentMu sync.Mutex
	lastSent   []VpnProto.ResolverReportV2Entry
}

func newResolverReporter(c *Client, log *logger.Logger) *resolverReporter {
	return &resolverReporter{
		client: c,
		log:    log,
		signal: make(chan struct{}, 1),
	}
}

func (r *resolverReporter) Trigger() {
	if r == nil {
		return
	}
	select {
	case r.signal <- struct{}{}:
	default:
	}
}

func (r *resolverReporter) ResetLastSent() {
	if r == nil {
		return
	}
	r.lastSentMu.Lock()
	r.lastSent = nil
	r.lastSentMu.Unlock()
}

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

	ticker := time.NewTicker(resolverReporterPeriodicInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.signal:
			r.maybeSend(VpnProto.ResolverReportV2KindIncremental, false)
		case <-ticker.C:
			r.maybeSend(VpnProto.ResolverReportV2KindFull, true)
		}
	}
}

// forceSend bypasses dedupe so periodic ticks always emit fresh score deltas.
func (r *resolverReporter) maybeSend(kind VpnProto.ResolverReportV2Kind, forceSend bool) {
	if r == nil || r.client == nil || !r.client.SessionReady() {
		return
	}
	if !r.client.cfg.ResolverReportEnabled {
		return
	}

	scores := r.client.balancer.SnapshotResolverScores()
	current := r.buildEntries(scores)

	r.lastSentMu.Lock()
	prevSent := r.lastSent
	r.lastSentMu.Unlock()

	if !forceSend && resolverV2EntriesEqual(current, prevSent) {
		return
	}
	if !r.dispatch(kind, current) {
		return
	}
	r.lastSentMu.Lock()
	r.lastSent = current
	r.lastSentMu.Unlock()
}

func (r *resolverReporter) buildEntries(scores []ResolverScoreSnapshot) []VpnProto.ResolverReportV2Entry {
	if len(scores) == 0 {
		return nil
	}
	entries := make([]VpnProto.ResolverReportV2Entry, 0, len(scores))
	for _, s := range scores {
		if !s.IP.IsValid() {
			continue
		}
		// 0 = "no RTT info" sentinel; server skips its RTT contribution.
		var rttMs uint16
		if s.HasRtt {
			rttMs = s.EWMARttMs
		}
		entries = append(entries, VpnProto.ResolverReportV2Entry{
			IP:             s.IP,
			SuccessCount:   clampUint16(s.SuccessCount),
			FailureCount:   clampUint16(s.FailureCount),
			EWMARttMs:      rttMs,
			LastUsedAgeSec: 0,
		})
	}
	slices.SortFunc(entries, func(a, b VpnProto.ResolverReportV2Entry) int {
		return a.IP.Compare(b.IP)
	})
	return entries
}

func (r *resolverReporter) dispatch(kind VpnProto.ResolverReportV2Kind, entries []VpnProto.ResolverReportV2Entry) bool {
	r.client.streamsMu.RLock()
	s0 := r.client.active_streams[0]
	r.client.streamsMu.RUnlock()
	if s0 == nil {
		return false
	}

	payload := VpnProto.EncodeResolverReportV2(kind, entries)
	seq := uint16(r.nextSeq.Add(1))
	// Fire-and-forget: V2 is idempotent and re-emitted on the next trigger /
	// 90s tick. ARQ-tracked sends on stream 0 would tear down the session on
	// TTL expiry — unacceptable for a stats report.
	if !s0.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_RESOLVER_REPORT_V2),
		Enums.PACKET_RESOLVER_REPORT_V2,
		seq, 0, 0, 0, 0,
		payload,
	) {
		return false
	}
	if r.log != nil {
		r.log.Infof(
			"<green>\U0001F4E1 Resolver Report Sent</green> | <cyan>%s, %d resolvers</cyan>",
			v2KindName(kind), len(entries),
		)
	}
	return true
}

func v2KindName(k VpnProto.ResolverReportV2Kind) string {
	switch k {
	case VpnProto.ResolverReportV2KindFull:
		return "full"
	case VpnProto.ResolverReportV2KindIncremental:
		return "incremental"
	case VpnProto.ResolverReportV2KindSessionCloseFlush:
		return "flush"
	default:
		return "unknown"
	}
}

func clampUint16(v uint64) uint16 {
	if v > 0xFFFF {
		return 0xFFFF
	}
	return uint16(v)
}

func resolverV2EntriesEqual(a, b []VpnProto.ResolverReportV2Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
