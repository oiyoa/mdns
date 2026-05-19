// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"
)

const (
	// statsActiveCountChangeRatio triggers an immediate active-count log when
	// the active session count changes by this fraction relative to the last
	// emitted snapshot (between scheduled stats ticks).
	statsActiveCountChangeRatio = 0.5
	// statsActiveCountChangeMin is the minimum absolute change required to
	// trigger a threshold emit even if the ratio is met.
	statsActiveCountChangeMin = 5
)

// statsState tracks server-wide stats counters and their last-emit snapshot for
// rate calculations. Snapshot fields are read/written only from the cleanup
// loop goroutine, so a single mutex guards them.
type statsState struct {
	mu                 sync.Mutex
	lastEmit           time.Time
	lastBytesRX        uint64
	lastBytesTX        uint64
	lastPacketsRX      uint64
	lastPacketsTX      uint64
	lastActiveCount    int
	peakActiveSessions int
}

func (s *Server) noteServerRX(payloadBytes int) {
	if s == nil {
		return
	}
	s.statsLifetimePacketsRX.Add(1)
	if payloadBytes > 0 {
		s.statsLifetimeBytesRX.Add(uint64(payloadBytes))
	}
}

func (s *Server) noteServerTX(payloadBytes int) {
	if s == nil {
		return
	}
	s.statsLifetimePacketsTX.Add(1)
	if payloadBytes > 0 {
		s.statsLifetimeBytesTX.Add(uint64(payloadBytes))
	}
}

// maybeEmitServerStats decides whether to emit a periodic server-wide stats
// line. It emits when at least interval has passed since the last emit, OR
// when the active session count has changed substantially (high-water mark,
// drop to zero, or large jump). Returns true if a log line was emitted.
func (s *Server) maybeEmitServerStats(now time.Time, interval time.Duration) bool {
	if s == nil || s.log == nil {
		return false
	}

	state := &s.stats
	state.mu.Lock()
	defer state.mu.Unlock()

	active := s.sessions.ActiveCount()
	scheduled := state.lastEmit.IsZero() || (interval > 0 && now.Sub(state.lastEmit) >= interval)
	threshold := s.activeCountCrossedThresholdLocked(state, active)

	if !scheduled && !threshold {
		return false
	}

	bytesRX := s.statsLifetimeBytesRX.Load()
	bytesTX := s.statsLifetimeBytesTX.Load()
	packetsRX := s.statsLifetimePacketsRX.Load()
	packetsTX := s.statsLifetimePacketsTX.Load()

	var elapsed time.Duration
	if !state.lastEmit.IsZero() {
		elapsed = now.Sub(state.lastEmit)
	}

	deltaBytesRX := bytesRX - state.lastBytesRX
	deltaBytesTX := bytesTX - state.lastBytesTX
	deltaPacketsRX := packetsRX - state.lastPacketsRX
	deltaPacketsTX := packetsTX - state.lastPacketsTX

	rateRX, rateTX := bytesPerSecond(deltaBytesRX, elapsed), bytesPerSecond(deltaBytesTX, elapsed)

	if active > state.peakActiveSessions {
		state.peakActiveSessions = active
	}
	peakActive := state.peakActiveSessions

	state.lastEmit = now
	state.lastBytesRX = bytesRX
	state.lastBytesTX = bytesTX
	state.lastPacketsRX = packetsRX
	state.lastPacketsTX = packetsTX
	state.lastActiveCount = active

	trigger := "scheduled"
	if !scheduled && threshold {
		trigger = "active-change"
	}

	queueDepth, queueSessions := s.sampleQueuePressure()
	latency := s.sampleLatencyAndRetx()
	memStats := readProcessStats()

	s.log.Infof(
		"\U0001F4CA <green>Server Stats</green> <magenta>|</magenta> <blue>Trigger</blue>: <cyan>%s</cyan> <magenta>|</magenta> <blue>Active</blue>: <cyan>%d</cyan> (peak <cyan>%d</cyan>) <magenta>|</magenta> <blue>RX</blue>: <cyan>%s</cyan> @ <cyan>%s/s</cyan> (<cyan>%d</cyan> pkts) <magenta>|</magenta> <blue>TX</blue>: <cyan>%s</cyan> @ <cyan>%s/s</cyan> (<cyan>%d</cyan> pkts) <magenta>|</magenta> <blue>Lifetime</blue>: RX <cyan>%s</cyan> / TX <cyan>%s</cyan> <magenta>|</magenta> <blue>Latency</blue>: SRTT p50 <cyan>%s</cyan> / p95 <cyan>%s</cyan> across <cyan>%d</cyan>/<cyan>%d</cyan> streams <magenta>|</magenta> <blue>Retx</blue>: data <cyan>%d</cyan>, ctrl <cyan>%d</cyan> <magenta>|</magenta> <blue>Queues</blue>: orphan-depth <cyan>%d</cyan> across <cyan>%d</cyan> sess <magenta>|</magenta> <blue>Runtime</blue>: goroutines <cyan>%d</cyan>, heap <cyan>%s</cyan>, sys <cyan>%s</cyan>, gc <cyan>%d</cyan>",
		trigger,
		active,
		peakActive,
		formatBytes(deltaBytesRX),
		formatBytes(rateRX),
		deltaPacketsRX,
		formatBytes(deltaBytesTX),
		formatBytes(rateTX),
		deltaPacketsTX,
		formatBytes(bytesRX),
		formatBytes(bytesTX),
		formatDurationShort(latency.medianSRTT),
		formatDurationShort(latency.p95SRTT),
		latency.streamSamples,
		latency.streamsObserved,
		latency.totalDataRetx,
		latency.totalCtrlRetx,
		queueDepth,
		queueSessions,
		memStats.goroutines,
		formatBytes(memStats.heapInUse),
		formatBytes(memStats.sys),
		memStats.numGC,
	)
	return true
}

// formatDurationShort prints a duration in the smallest unit that keeps the
// value readable (us / ms / s). Returns "-" when the duration is zero, which
// signals "no sample available" for SRTT.
func formatDurationShort(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fus", float64(d.Nanoseconds())/float64(time.Microsecond))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// activeCountCrossedThresholdLocked returns true if the change in active
// sessions since the last emit is large enough to warrant an immediate log,
// regardless of the scheduled interval.
func (s *Server) activeCountCrossedThresholdLocked(state *statsState, active int) bool {
	if state.lastEmit.IsZero() {
		return false
	}
	prev := state.lastActiveCount
	if prev == active {
		return false
	}
	if (prev == 0 && active > 0) || (prev > 0 && active == 0) {
		return true
	}
	diff := active - prev
	if diff < 0 {
		diff = -diff
	}
	if diff < statsActiveCountChangeMin {
		return false
	}
	base := prev
	if active > base {
		base = active
	}
	if base == 0 {
		return false
	}
	return float64(diff)/float64(base) >= statsActiveCountChangeRatio
}

// sampleQueuePressure walks the active sessions and returns the aggregate
// orphan queue depth and how many sessions have non-empty orphan queues.
func (s *Server) sampleQueuePressure() (totalDepth int, sessionsWithBacklog int) {
	if s == nil || s.sessions == nil {
		return 0, 0
	}
	s.sessions.mu.RLock()
	defer s.sessions.mu.RUnlock()
	for _, record := range s.sessions.byID {
		if record == nil {
			continue
		}
		if record.OrphanQueue == nil {
			continue
		}
		depth := record.OrphanQueue.FastSize()
		if depth > 0 {
			totalDepth += depth
			sessionsWithBacklog++
		}
	}
	return totalDepth, sessionsWithBacklog
}

type latencySample struct {
	medianSRTT      time.Duration
	p95SRTT         time.Duration
	streamSamples   int
	totalDataRetx   uint64
	totalCtrlRetx   uint64
	totalDataPkts   uint64
	streamsObserved int
}

// sampleLatencyAndRetx walks all active streams across all active sessions,
// reads each ARQ's smoothed RTT and lifetime retransmit counters, and returns
// median/p95 SRTT plus aggregate retransmits. Streams that have not yet
// received an RTT sample (no acks observed) are skipped for the SRTT
// distribution but still contribute to retransmit totals.
func (s *Server) sampleLatencyAndRetx() latencySample {
	var out latencySample
	if s == nil || s.sessions == nil {
		return out
	}

	s.sessions.mu.RLock()
	records := make([]*sessionRecord, 0, 16)
	for _, record := range s.sessions.byID {
		if record != nil {
			records = append(records, record)
		}
	}
	s.sessions.mu.RUnlock()

	srtts := make([]time.Duration, 0, 64)
	for _, record := range records {
		record.StreamsMu.RLock()
		streams := make([]*Stream_server, 0, len(record.Streams))
		for _, stream := range record.Streams {
			if stream != nil && stream.ARQ != nil {
				streams = append(streams, stream)
			}
		}
		record.StreamsMu.RUnlock()

		for _, stream := range streams {
			out.streamsObserved++
			if srtt := stream.ARQ.DataSRTT(); srtt > 0 {
				srtts = append(srtts, srtt)
			}
			data, ctrl := stream.ARQ.RetransmitCounts()
			out.totalDataRetx += data
			out.totalCtrlRetx += ctrl
		}
		out.totalDataPkts += record.packetsReceived.Load() + record.packetsSent.Load()
	}

	out.streamSamples = len(srtts)
	if out.streamSamples == 0 {
		return out
	}

	slices.Sort(srtts)
	out.medianSRTT = srtts[len(srtts)/2]
	p95Idx := (len(srtts) * 95) / 100
	if p95Idx >= len(srtts) {
		p95Idx = len(srtts) - 1
	}
	out.p95SRTT = srtts[p95Idx]
	return out
}

type processStats struct {
	goroutines int
	heapInUse  uint64
	sys        uint64
	numGC      uint32
}

func readProcessStats() processStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return processStats{
		goroutines: runtime.NumGoroutine(),
		heapInUse:  ms.HeapInuse,
		sys:        ms.Sys,
		numGC:      ms.NumGC,
	}
}

func bytesPerSecond(deltaBytes uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 || deltaBytes == 0 {
		return 0
	}
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		return 0
	}
	return uint64(float64(deltaBytes) / seconds)
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffix := "KMGTPE"[exp]
	return fmt.Sprintf("%.2f%ciB", float64(n)/float64(div), suffix)
}

func formatThroughput(bytes uint64, duration time.Duration) string {
	if duration <= 0 || bytes == 0 {
		return "0B/s"
	}
	rate := bytesPerSecond(bytes, duration)
	return formatBytes(rate) + "/s"
}

