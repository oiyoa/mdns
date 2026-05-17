// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
)

const (
	resolverLeaderboardWindowDays   = 7
	resolverLeaderboardBucketCap    = 10000
	resolverLeaderboardTopN         = 10
	resolverLeaderboardSaveInterval = 10 * time.Minute
	resolverLeaderboardSchema       = 1
	resolverLeaderboardDayLayout    = "2006-01-02"

	resolverLeaderboardMinSessionDuration = 30 * time.Second
	resolverLeaderboardMinPacketsRX       = 20

	resolverDefaultPort = 53

	resolverScoreDurationCap = 30 * time.Minute
	resolverScoreMTUCap      = 2000.0
	resolverScoreWeightPop   = 0.5
	resolverScoreWeightDur   = 0.25
	resolverScoreWeightMTU   = 0.25
)

type resolverDailyEntry struct {
	Sessions       uint64
	DurationSumNS  uint64
	DownloadMTUSum uint64
}

type resolverDailyBucket struct {
	day     time.Time
	entries map[netip.AddrPort]*resolverDailyEntry
}

type resolverLeaderboard struct {
	mu             sync.Mutex
	buckets        []*resolverDailyBucket
	lastEmitHour   time.Time
	snapshotPath   string
	dirtySinceSave bool
	lastSaveTime   time.Time
	log            *logger.Logger
}

func newResolverLeaderboard() *resolverLeaderboard {
	return &resolverLeaderboard{
		buckets: make([]*resolverDailyBucket, 0, resolverLeaderboardWindowDays),
	}
}

func (l *resolverLeaderboard) ConfigurePersistence(snapshotPath string, log *logger.Logger) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.snapshotPath = snapshotPath
	l.log = log
}

func buildResolverLeaderboard(cfg config.ServerConfig, log *logger.Logger) *resolverLeaderboard {
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(cfg.ResolverStatsPath(), log)
	lb.LoadSnapshot(time.Now())
	return lb
}

// RecordSession folds one closed session's contribution into the current
// daily bucket. The caller is responsible for the real-session threshold.
func (l *resolverLeaderboard) RecordSession(now time.Time, resolvers []netip.Addr, duration time.Duration, downloadMTU uint16) {
	if l == nil || len(resolvers) == 0 {
		return
	}
	day := truncToUTCDay(now)
	durationNS := uint64(0)
	if duration > 0 {
		durationNS = uint64(duration.Nanoseconds())
	}
	mtu := uint64(downloadMTU)

	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.ensureCurrentBucketLocked(day)
	for _, ip := range resolvers {
		if !isPubliclyRoutableIP(ip) {
			continue
		}
		key := netip.AddrPortFrom(ip.Unmap(), resolverDefaultPort)
		entry, exists := bucket.entries[key]
		if !exists {
			if len(bucket.entries) >= resolverLeaderboardBucketCap {
				continue
			}
			entry = &resolverDailyEntry{}
			bucket.entries[key] = entry
		}
		entry.Sessions++
		entry.DurationSumNS += durationNS
		entry.DownloadMTUSum += mtu
		l.dirtySinceSave = true
	}
}

func (l *resolverLeaderboard) MaybeEmit(now time.Time, log *logger.Logger) bool {
	if l == nil || log == nil {
		return false
	}
	hour := now.UTC().Truncate(time.Hour)

	l.mu.Lock()
	if !l.lastEmitHour.IsZero() && !hour.After(l.lastEmitHour) {
		l.mu.Unlock()
		return false
	}
	top, uniqueIPs := l.snapshotTopLocked(resolverLeaderboardTopN)
	l.lastEmitHour = hour
	l.mu.Unlock()

	if len(top) == 0 {
		return false
	}

	parts := make([]string, 0, len(top))
	for _, entry := range top {
		parts = append(parts, fmt.Sprintf("<cyan>%s</cyan>: <magenta>%d</magenta> sess (score=<magenta>%d</magenta>)", entry.AddrPort, entry.Sessions, entry.Score))
	}
	log.Infof(
		"\U0001F4CA <green>Top Resolvers (7d, %d unique)</green> | %s",
		uniqueIPs,
		strings.Join(parts, " | "),
	)
	return true
}

type resolverLeaderboardEntry struct {
	AddrPort       netip.AddrPort
	Sessions       uint64
	AvgDuration    time.Duration
	AvgDownloadMTU uint16
	Score          uint16
}

// TopForDistribution returns up to n best-ranked (IP,port) entries across the
// whole window, with composite scores. Used to build the response to the
// client's resolver-list request.
func (l *resolverLeaderboard) TopForDistribution(n int) []resolverLeaderboardEntry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	top, _ := l.snapshotTopLocked(n)
	return top
}

func (l *resolverLeaderboard) ensureCurrentBucketLocked(day time.Time) *resolverDailyBucket {
	if n := len(l.buckets); n > 0 {
		last := l.buckets[n-1]
		if last.day.Equal(day) {
			return last
		}
	}
	fresh := &resolverDailyBucket{
		day:     day,
		entries: make(map[netip.AddrPort]*resolverDailyEntry, 64),
	}
	l.buckets = append(l.buckets, fresh)
	l.pruneBucketsLocked(day)
	return fresh
}

func (l *resolverLeaderboard) pruneBucketsLocked(currentDay time.Time) {
	cutoff := currentDay.AddDate(0, 0, -(resolverLeaderboardWindowDays - 1))
	keepFrom := 0
	for i, bucket := range l.buckets {
		if bucket.day.Before(cutoff) {
			keepFrom = i + 1
			continue
		}
		break
	}
	if keepFrom > 0 {
		l.buckets = l.buckets[keepFrom:]
	}
}

func (l *resolverLeaderboard) snapshotTopLocked(n int) ([]resolverLeaderboardEntry, int) {
	if len(l.buckets) == 0 {
		return nil, 0
	}

	type agg struct {
		sessions       uint64
		durationSumNS  uint64
		downloadMTUSum uint64
	}
	totals := make(map[netip.AddrPort]*agg, 128)
	for _, bucket := range l.buckets {
		for k, e := range bucket.entries {
			a := totals[k]
			if a == nil {
				a = &agg{}
				totals[k] = a
			}
			a.sessions += e.Sessions
			a.durationSumNS += e.DurationSumNS
			a.downloadMTUSum += e.DownloadMTUSum
		}
	}
	if len(totals) == 0 {
		return nil, 0
	}

	var maxSessions uint64
	for _, a := range totals {
		if a.sessions > maxSessions {
			maxSessions = a.sessions
		}
	}

	entries := make([]resolverLeaderboardEntry, 0, len(totals))
	for k, a := range totals {
		avgDuration := time.Duration(0)
		avgMTU := uint16(0)
		if a.sessions > 0 {
			avgDuration = time.Duration(a.durationSumNS / a.sessions)
			avgMTU = uint16(a.downloadMTUSum / a.sessions)
		}
		entries = append(entries, resolverLeaderboardEntry{
			AddrPort:       k,
			Sessions:       a.sessions,
			AvgDuration:    avgDuration,
			AvgDownloadMTU: avgMTU,
			Score:          composeRankScore(a.sessions, maxSessions, avgDuration, avgMTU),
		})
	}
	slices.SortFunc(entries, func(a, b resolverLeaderboardEntry) int {
		if a.Score != b.Score {
			if a.Score > b.Score {
				return -1
			}
			return 1
		}
		if a.Sessions != b.Sessions {
			if a.Sessions > b.Sessions {
				return -1
			}
			return 1
		}
		return a.AddrPort.Compare(b.AddrPort)
	})
	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}
	return entries, len(totals)
}

// composeRankScore maps (popularity, avg duration, avg MTU) into a [0..65535]
// rank. Caller-opaque; clients sort descending. Tweaking weights or caps
// changes the leaderboard without touching the wire format.
func composeRankScore(sessions, maxSessions uint64, avgDuration time.Duration, avgMTU uint16) uint16 {
	popularity := 0.0
	if maxSessions > 0 {
		popularity = float64(sessions) / float64(maxSessions)
	}
	durationNorm := float64(avgDuration) / float64(resolverScoreDurationCap)
	if durationNorm > 1 {
		durationNorm = 1
	}
	mtuNorm := float64(avgMTU) / resolverScoreMTUCap
	if mtuNorm > 1 {
		mtuNorm = 1
	}
	score := resolverScoreWeightPop*popularity +
		resolverScoreWeightDur*durationNorm +
		resolverScoreWeightMTU*mtuNorm
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return uint16(score * 65535)
}

func truncToUTCDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

type leaderboardSnapshotFile struct {
	Version int                         `json:"version"`
	Buckets []leaderboardSnapshotBucket `json:"buckets"`
}

type leaderboardSnapshotBucket struct {
	Day     string                                `json:"day"`
	Entries map[string]leaderboardSnapshotMetrics `json:"entries"`
}

type leaderboardSnapshotMetrics struct {
	Sessions       uint64 `json:"sessions"`
	DurationSumNS  uint64 `json:"duration_ns"`
	DownloadMTUSum uint64 `json:"mtu_sum"`
}

func (l *resolverLeaderboard) LoadSnapshot(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	path := l.snapshotPath
	log := l.log
	l.mu.Unlock()
	if path == "" {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return
		}
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Load Failed, Path: <cyan>%s</cyan>, Error: <cyan>%v</cyan></yellow>",
				path, err,
			)
		}
		return
	}

	var snap leaderboardSnapshotFile
	if err := json.Unmarshal(data, &snap); err != nil {
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Snapshot Corrupt, Path: <cyan>%s</cyan>, Error: <cyan>%v</cyan> — starting fresh</yellow>",
				path, err,
			)
		}
		return
	}
	if snap.Version != resolverLeaderboardSchema {
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Snapshot Version Mismatch, Got: <cyan>%d</cyan>, Want: <cyan>%d</cyan> — starting fresh</yellow>",
				snap.Version, resolverLeaderboardSchema,
			)
		}
		return
	}

	today := truncToUTCDay(now)
	cutoff := today.AddDate(0, 0, -(resolverLeaderboardWindowDays - 1))

	buckets := make([]*resolverDailyBucket, 0, len(snap.Buckets))
	loadedEntries := 0
	for _, sb := range snap.Buckets {
		day, err := time.ParseInLocation(resolverLeaderboardDayLayout, sb.Day, time.UTC)
		if err != nil {
			continue
		}
		if day.Before(cutoff) || day.After(today) {
			continue
		}
		entries := make(map[netip.AddrPort]*resolverDailyEntry, len(sb.Entries))
		for keyStr, m := range sb.Entries {
			ap, err := netip.ParseAddrPort(keyStr)
			if err != nil || !ap.Addr().IsValid() {
				continue
			}
			if len(entries) >= resolverLeaderboardBucketCap {
				break
			}
			entries[ap] = &resolverDailyEntry{
				Sessions:       m.Sessions,
				DurationSumNS:  m.DurationSumNS,
				DownloadMTUSum: m.DownloadMTUSum,
			}
		}
		if len(entries) == 0 {
			continue
		}
		buckets = append(buckets, &resolverDailyBucket{day: day, entries: entries})
		loadedEntries += len(entries)
	}
	slices.SortFunc(buckets, func(a, b *resolverDailyBucket) int {
		return a.day.Compare(b.day)
	})

	l.mu.Lock()
	l.buckets = buckets
	l.dirtySinceSave = false
	l.mu.Unlock()

	if log != nil && len(buckets) > 0 {
		log.Infof(
			"\U0001F4CA <green>Resolver Stats Restored, Buckets: <cyan>%d</cyan>, Entries: <cyan>%d</cyan></green>",
			len(buckets), loadedEntries,
		)
	}
}

func (l *resolverLeaderboard) MaybeSaveSnapshot(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.snapshotPath == "" || !l.dirtySinceSave {
		l.mu.Unlock()
		return
	}
	if !l.lastSaveTime.IsZero() && now.Sub(l.lastSaveTime) < resolverLeaderboardSaveInterval {
		l.mu.Unlock()
		return
	}
	payload, err := l.serializeLocked()
	if err != nil {
		log := l.log
		l.mu.Unlock()
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Serialize Failed, Error: <cyan>%v</cyan></yellow>",
				err,
			)
		}
		return
	}
	path := l.snapshotPath
	log := l.log
	l.lastSaveTime = now
	l.dirtySinceSave = false
	l.mu.Unlock()

	if err := writeFileAtomic(path, payload); err != nil {
		l.mu.Lock()
		l.dirtySinceSave = true
		l.mu.Unlock()
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Save Failed, Path: <cyan>%s</cyan>, Error: <cyan>%v</cyan></yellow>",
				path, err,
			)
		}
	}
}

func (l *resolverLeaderboard) FlushSnapshot(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.snapshotPath == "" {
		l.mu.Unlock()
		return
	}
	payload, err := l.serializeLocked()
	if err != nil {
		log := l.log
		l.mu.Unlock()
		if log != nil {
			log.Warnf(
				"\U0001F4CA <yellow>Resolver Stats Final Save Serialize Failed, Error: <cyan>%v</cyan></yellow>",
				err,
			)
		}
		return
	}
	path := l.snapshotPath
	log := l.log
	l.lastSaveTime = now
	l.dirtySinceSave = false
	l.mu.Unlock()

	if err := writeFileAtomic(path, payload); err != nil && log != nil {
		log.Warnf(
			"\U0001F4CA <yellow>Resolver Stats Final Save Failed, Path: <cyan>%s</cyan>, Error: <cyan>%v</cyan></yellow>",
			path, err,
		)
	}
}

func (l *resolverLeaderboard) serializeLocked() ([]byte, error) {
	snap := leaderboardSnapshotFile{
		Version: resolverLeaderboardSchema,
		Buckets: make([]leaderboardSnapshotBucket, 0, len(l.buckets)),
	}
	for _, b := range l.buckets {
		entry := leaderboardSnapshotBucket{
			Day:     b.day.Format(resolverLeaderboardDayLayout),
			Entries: make(map[string]leaderboardSnapshotMetrics, len(b.entries)),
		}
		for ap, e := range b.entries {
			entry.Entries[ap.String()] = leaderboardSnapshotMetrics{
				Sessions:       e.Sessions,
				DurationSumNS:  e.DurationSumNS,
				DownloadMTUSum: e.DownloadMTUSum,
			}
		}
		snap.Buckets = append(snap.Buckets, entry)
	}
	return json.Marshal(snap)
}

// writeFileAtomic uses a deterministic tmp path + rename so a kill-9 between
// Write and Rename cannot leak an unbounded number of orphan files: the next
// successful save unlinks any prior tmp via os.Remove. O_EXCL defends against
// a symlink planted at tmpPath between the Remove and the Open.
func writeFileAtomic(path string, data []byte) error {
	tmpPath := path + ".tmp"

	if err := os.Remove(tmpPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
