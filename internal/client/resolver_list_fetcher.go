// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// ServerRecommendation is one entry in the server-pushed best-resolvers list.
// Exposed through Client.ServerRecommendedResolvers() so the Android bridge
// can read it.
type ServerRecommendation struct {
	IP    netip.Addr
	Port  uint16
	Score uint16
}

type resolverListFetcher struct {
	client *Client
	log    *logger.Logger

	signal  chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	nextSeq atomic.Uint32

	mu                sync.Mutex
	requestedThisSess bool
	lastReceived      []ServerRecommendation
	lastReceivedAt    time.Time
}

func newResolverListFetcher(c *Client, log *logger.Logger) *resolverListFetcher {
	return &resolverListFetcher{
		client: c,
		log:    log,
		signal: make(chan struct{}, 1),
	}
}

func (f *resolverListFetcher) Trigger() {
	if f == nil {
		return
	}
	select {
	case f.signal <- struct{}{}:
	default:
	}
}

// ResetForNewSession clears the per-session "already requested" flag so the
// next Trigger fires a fresh request against the new server-side session.
func (f *resolverListFetcher) ResetForNewSession() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.requestedThisSess = false
	f.mu.Unlock()
}

func (f *resolverListFetcher) Start(parent context.Context) {
	if f == nil {
		return
	}
	f.Stop()
	f.ctx, f.cancel = context.WithCancel(parent)
	f.wg.Add(1)
	go f.run()
}

func (f *resolverListFetcher) Stop() {
	if f == nil || f.cancel == nil {
		return
	}
	f.cancel()
	f.wg.Wait()
	f.cancel = nil
	f.ctx = nil
}

func (f *resolverListFetcher) run() {
	defer f.wg.Done()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-f.signal:
			f.maybeRequest()
		}
	}
}

func (f *resolverListFetcher) maybeRequest() {
	if f == nil || f.client == nil || !f.client.SessionReady() {
		return
	}
	f.mu.Lock()
	if f.requestedThisSess {
		f.mu.Unlock()
		return
	}
	f.requestedThisSess = true
	f.mu.Unlock()

	f.client.streamsMu.RLock()
	s0 := f.client.active_streams[0]
	f.client.streamsMu.RUnlock()
	if s0 == nil {
		f.mu.Lock()
		f.requestedThisSess = false
		f.mu.Unlock()
		return
	}

	seq := uint16(f.nextSeq.Add(1))
	ok := s0.PushTXPacket(
		Enums.DefaultPacketPriority(Enums.PACKET_RESOLVER_LIST_REQUEST),
		Enums.PACKET_RESOLVER_LIST_REQUEST,
		seq, 0, 0, 0, 0, nil,
	)
	if !ok {
		f.mu.Lock()
		f.requestedThisSess = false
		f.mu.Unlock()
		return
	}
	if f.log != nil {
		f.log.Infof("<green>\U0001F4E5 Resolver List Requested</green>")
	}
}

func (f *resolverListFetcher) ingestResponse(payload []byte) {
	if f == nil {
		return
	}
	entries, err := VpnProto.DecodeResolverList(payload)
	if err != nil {
		if f.log != nil {
			f.log.Warnf("<yellow>Resolver list response parse failed: %v</yellow>", err)
		}
		return
	}

	recs := make([]ServerRecommendation, 0, len(entries))
	for _, e := range entries {
		ip := e.IP.Unmap()
		if !ip.IsValid() {
			continue
		}
		recs = append(recs, ServerRecommendation{IP: ip, Port: e.Port, Score: e.Score})
	}
	slices.SortFunc(recs, func(a, b ServerRecommendation) int {
		if a.Score != b.Score {
			if a.Score > b.Score {
				return -1
			}
			return 1
		}
		return a.IP.Compare(b.IP)
	})

	f.mu.Lock()
	f.lastReceived = recs
	f.lastReceivedAt = time.Now()
	f.mu.Unlock()

	if f.log != nil {
		f.log.Infof(
			"<green>\U0001F4E5 Resolver List Received</green> | <cyan>%d resolvers</cyan>",
			len(recs),
		)
		for i, r := range recs {
			if i >= 5 {
				f.log.Infof("  <cyan>... %d more</cyan>", len(recs)-5)
				break
			}
			f.log.Infof("  <cyan>%s:%d</cyan> (score=<magenta>%d</magenta>)", r.IP, r.Port, r.Score)
		}
	}

	if added := f.integrateIntoBalancer(recs); len(added) > 0 {
		go f.probeNewConnections(added)
	}
}

func (f *resolverListFetcher) integrateIntoBalancer(recs []ServerRecommendation) []Connection {
	if f == nil || f.client == nil || f.client.balancer == nil {
		return nil
	}
	domains := f.client.cfg.Domains
	if len(domains) == 0 {
		return nil
	}
	candidates := make([]*Connection, 0, len(recs)*len(domains))
	for _, r := range recs {
		port := int(r.Port)
		if port == 0 {
			port = 53
		}
		ipStr := r.IP.String()
		for _, domain := range domains {
			label := formatResolverEndpoint(ipStr, port)
			key := makeConnectionKey(ipStr, port, domain)
			candidates = append(candidates, &Connection{
				Domain:        domain,
				Resolver:      ipStr,
				ResolverPort:  port,
				ResolverLabel: label,
				Key:           key,
				IsValid:       false,
			})
		}
	}
	return f.client.balancer.AddConnections(candidates)
}

func (f *resolverListFetcher) probeNewConnections(conns []Connection) {
	if f == nil || f.client == nil || len(conns) == 0 {
		return
	}
	parentCtx := f.ctx
	if parentCtx == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parentCtx, 2*time.Minute)
	defer cancel()

	uploadCaps := f.client.precomputeUploadCaps()
	counters := &mtuScanCounters{}
	if f.log != nil {
		f.log.Infof(
			"<cyan>\U0001F50E Probing %d server-recommended resolvers</cyan>",
			len(conns),
		)
	}
	for i := range conns {
		if ctx.Err() != nil {
			return
		}
		conn := conns[i]
		f.client.runConnectionMTUTest(ctx, conn, i+1, len(conns), uploadCaps[conn.Domain], counters)
	}
}

// Snapshot returns a copy of the latest received list, suitable for the
// Android bridge to read. Returns nil if no list has been received yet.
func (f *resolverListFetcher) Snapshot() []ServerRecommendation {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.lastReceived) == 0 {
		return nil
	}
	out := make([]ServerRecommendation, len(f.lastReceived))
	copy(out, f.lastReceived)
	return out
}

func (f *resolverListFetcher) SnapshotReceivedAt() time.Time {
	if f == nil {
		return time.Time{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReceivedAt
}

func (r ServerRecommendation) String() string {
	return fmt.Sprintf("%s:%d (score=%d)", r.IP, r.Port, r.Score)
}
