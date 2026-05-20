// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"fmt"
	"slices"
	"strings"
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
	// statsHeartbeatInterval forces a stats line even when nothing has changed,
	// so admins watching the log can confirm the server is alive.
	statsHeartbeatInterval = 1 * time.Hour
)

// statsState tracks the last sampled snapshot of server-wide counters so the
// next emit can compute deltas, plus the timestamp of the last *actual* log
// line so heartbeats and idle-skip can be decided independently of how often
// we sample. Guarded by mu.
type statsState struct {
	mu                 sync.Mutex
	initialized        bool
	lastSnapshotAt     time.Time
	lastLogAt          time.Time
	lastBytesRX        uint64
	lastBytesTX        uint64
	lastPacketsRX      uint64
	lastPacketsTX      uint64
	lastDataRetx       uint64
	lastCtrlRetx       uint64
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

// maybeEmitServerStats samples server-wide counters and decides whether to log
// a stats line this tick. The snapshot is always advanced so delta math stays
// correct, but the log itself is suppressed when nothing interesting has
// happened: zero active sessions and zero packets since the last sample. A
// heartbeat line is forced at most once per hour so admins know the process is
// alive even when fully idle. The line itself is built from conditional
// segments — fields that have nothing to say are simply omitted instead of
// being logged as zeros.
func (s *Server) maybeEmitServerStats(now time.Time, interval time.Duration) bool {
	if s == nil || s.log == nil {
		return false
	}

	state := &s.stats
	state.mu.Lock()
	defer state.mu.Unlock()

	active := s.sessions.ActiveCount()
	scheduled := !state.initialized || (interval > 0 && now.Sub(state.lastSnapshotAt) >= interval)
	threshold := s.activeCountCrossedThresholdLocked(state, active)

	if !scheduled && !threshold {
		return false
	}

	bytesRX := s.statsLifetimeBytesRX.Load()
	bytesTX := s.statsLifetimeBytesTX.Load()
	packetsRX := s.statsLifetimePacketsRX.Load()
	packetsTX := s.statsLifetimePacketsTX.Load()

	var deltaBytesRX, deltaBytesTX, deltaPacketsRX, deltaPacketsTX uint64
	var elapsed time.Duration
	if state.initialized {
		elapsed = now.Sub(state.lastSnapshotAt)
		deltaBytesRX = bytesRX - state.lastBytesRX
		deltaBytesTX = bytesTX - state.lastBytesTX
		deltaPacketsRX = packetsRX - state.lastPacketsRX
		deltaPacketsTX = packetsTX - state.lastPacketsTX
	}

	idle := active == 0
	heartbeatDue := state.initialized && !state.lastLogAt.IsZero() && now.Sub(state.lastLogAt) >= statsHeartbeatInterval
	startup := !state.initialized
	shouldLog := threshold || heartbeatDue || startup || !idle

	if active > state.peakActiveSessions {
		state.peakActiveSessions = active
	}

	state.initialized = true
	state.lastSnapshotAt = now
	state.lastBytesRX = bytesRX
	state.lastBytesTX = bytesTX
	state.lastPacketsRX = packetsRX
	state.lastPacketsTX = packetsTX
	state.lastActiveCount = active

	if !shouldLog {
		return false
	}

	latency := s.sampleLatencyAndRetx()
	queueDepth, queueSessions := s.sampleQueuePressure()

	deltaDataRetx := latency.totalDataRetx
	deltaCtrlRetx := latency.totalCtrlRetx
	if state.initialized {
		if latency.totalDataRetx >= state.lastDataRetx {
			deltaDataRetx = latency.totalDataRetx - state.lastDataRetx
		}
		if latency.totalCtrlRetx >= state.lastCtrlRetx {
			deltaCtrlRetx = latency.totalCtrlRetx - state.lastCtrlRetx
		}
	}
	state.lastDataRetx = latency.totalDataRetx
	state.lastCtrlRetx = latency.totalCtrlRetx
	state.lastLogAt = now

	trigger := pickTrigger(threshold, heartbeatDue, startup)
	line := buildStatsLine(trigger, active, state.peakActiveSessions, elapsed,
		deltaBytesRX, deltaBytesTX, deltaPacketsRX, deltaPacketsTX,
		latency, deltaDataRetx, deltaCtrlRetx,
		queueDepth, queueSessions)

	s.log.Infof("%s", line)
	return true
}

func pickTrigger(threshold, heartbeat, startup bool) string {
	switch {
	case startup:
		return "startup"
	case threshold:
		return "active-change"
	case heartbeat:
		return "heartbeat"
	default:
		return ""
	}
}

// buildStatsLine assembles the log line from conditional segments. Each
// segment is appended only when its data is non-trivial — idle ticks that get
// past the suppression check (heartbeat, startup) end up showing just the
// liveness signals (active count, heap) without padding zeros for every
// counter.
func buildStatsLine(trigger string, active, peak int, elapsed time.Duration,
	deltaBytesRX, deltaBytesTX, deltaPacketsRX, deltaPacketsTX uint64,
	latency latencySample, deltaDataRetx, deltaCtrlRetx uint64,
	queueDepth, queueSessions int) string {

	segments := make([]string, 0, 8)

	if trigger != "" && trigger != "scheduled" {
		segments = append(segments, fmt.Sprintf("<blue>Trigger</blue>: <cyan>%s</cyan>", trigger))
	}

	activeSeg := fmt.Sprintf("<blue>Active</blue>: <cyan>%d</cyan>", active)
	if peak > 0 && peak != active {
		activeSeg += fmt.Sprintf(" (peak <cyan>%d</cyan>)", peak)
	}
	segments = append(segments, activeSeg)

	if latency.streamsObserved > 0 {
		segments = append(segments, fmt.Sprintf("<blue>Streams</blue>: <cyan>%d</cyan>", latency.streamsObserved))
	}

	if deltaBytesRX > 0 || deltaBytesTX > 0 {
		rateRX := bytesPerSecond(deltaBytesRX, elapsed)
		rateTX := bytesPerSecond(deltaBytesTX, elapsed)
		segments = append(segments, fmt.Sprintf("<blue>RX</blue>: <cyan>%s/s</cyan> (<cyan>%d</cyan> pkts) <magenta>·</magenta> <blue>TX</blue>: <cyan>%s/s</cyan> (<cyan>%d</cyan> pkts)",
			formatBytes(rateRX), deltaPacketsRX, formatBytes(rateTX), deltaPacketsTX))
	}

	if latency.streamSamples > 0 {
		segments = append(segments, fmt.Sprintf("<blue>SRTT</blue>: p50 <cyan>%s</cyan>, p95 <cyan>%s</cyan>",
			formatDurationShort(latency.medianSRTT), formatDurationShort(latency.p95SRTT)))
	}

	if deltaDataRetx > 0 || deltaCtrlRetx > 0 {
		segments = append(segments, fmt.Sprintf("<blue>Retx</blue>: data <cyan>+%d</cyan>, ctrl <cyan>+%d</cyan>", deltaDataRetx, deltaCtrlRetx))
	}

	if queueDepth > 0 {
		segments = append(segments, fmt.Sprintf("<blue>Queues</blue>: <cyan>%d</cyan> across <cyan>%d</cyan> sess", queueDepth, queueSessions))
	}

	return "\U0001F4CA <green>Server Stats</green> <magenta>|</magenta> " + strings.Join(segments, " <magenta>|</magenta> ")
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
	if !state.initialized {
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
