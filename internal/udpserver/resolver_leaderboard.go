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
)

type resolverDailyBucket struct {
	day    time.Time
	counts map[netip.Addr]uint64
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

// ConfigurePersistence sets the snapshot file path and a logger used to report
// save/load errors. snapshotPath="" disables persistence. Safe to call once
// during server construction.
func (l *resolverLeaderboard) ConfigurePersistence(snapshotPath string, log *logger.Logger) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.snapshotPath = snapshotPath
	l.log = log
}

// buildResolverLeaderboard wires persistence from the server config and
// restores any prior snapshot. The returned leaderboard is ready to use.
func buildResolverLeaderboard(cfg config.ServerConfig, log *logger.Logger) *resolverLeaderboard {
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(cfg.ResolverStatsPath(), log)
	lb.LoadSnapshot(time.Now())
	return lb
}

// RecordSession increments the count for each distinct resolver IP observed in a
// closed session. Safe to call from any goroutine. A nil receiver is a no-op.
func (l *resolverLeaderboard) RecordSession(now time.Time, resolvers []netip.Addr) {
	if l == nil || len(resolvers) == 0 {
		return
	}
	day := truncToUTCDay(now)
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket := l.ensureCurrentBucketLocked(day)
	for _, ip := range resolvers {
		if !ip.IsValid() {
			continue
		}
		if _, exists := bucket.counts[ip]; !exists && len(bucket.counts) >= resolverLeaderboardBucketCap {
			continue
		}
		bucket.counts[ip]++
		l.dirtySinceSave = true
	}
}

// MaybeEmit logs the top-N resolvers across the 7-day window, but at most once
// per UTC hour. Returns true if an entry was emitted, false otherwise.
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
		parts = append(parts, fmt.Sprintf("<cyan>%s</cyan>: <magenta>%d</magenta>", entry.ip, entry.count))
	}
	log.Infof(
		"\U0001F4CA <green>Top Resolvers (7d, %d unique)</green> | %s",
		uniqueIPs,
		strings.Join(parts, " | "),
	)
	return true
}

type resolverLeaderboardEntry struct {
	ip    netip.Addr
	count uint64
}

func (l *resolverLeaderboard) ensureCurrentBucketLocked(day time.Time) *resolverDailyBucket {
	if n := len(l.buckets); n > 0 {
		last := l.buckets[n-1]
		if last.day.Equal(day) {
			return last
		}
	}

	fresh := &resolverDailyBucket{
		day:    day,
		counts: make(map[netip.Addr]uint64, 64),
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

	totals := make(map[netip.Addr]uint64, 128)
	for _, bucket := range l.buckets {
		for ip, c := range bucket.counts {
			totals[ip] += c
		}
	}
	if len(totals) == 0 {
		return nil, 0
	}

	entries := make([]resolverLeaderboardEntry, 0, len(totals))
	for ip, c := range totals {
		entries = append(entries, resolverLeaderboardEntry{ip: ip, count: c})
	}
	slices.SortFunc(entries, func(a, b resolverLeaderboardEntry) int {
		if a.count != b.count {
			if a.count > b.count {
				return -1
			}
			return 1
		}
		return a.ip.Compare(b.ip)
	})
	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}
	return entries, len(totals)
}

func truncToUTCDay(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

type leaderboardSnapshotFile struct {
	Version int                          `json:"version"`
	Buckets []leaderboardSnapshotBucket  `json:"buckets"`
}

type leaderboardSnapshotBucket struct {
	Day    string            `json:"day"`
	Counts map[string]uint64 `json:"counts"`
}

// LoadSnapshot reads the snapshot from snapshotPath (if configured) and
// replaces the in-memory state. Buckets older than the 7-day window are
// dropped. A missing file is not an error; a corrupt file is logged and the
// state is left empty. Should be called once at startup before any Record.
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
		counts := make(map[netip.Addr]uint64, len(sb.Counts))
		for ipStr, c := range sb.Counts {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil || !ip.IsValid() {
				continue
			}
			if len(counts) >= resolverLeaderboardBucketCap {
				break
			}
			counts[ip.Unmap()] = c
		}
		if len(counts) == 0 {
			continue
		}
		buckets = append(buckets, &resolverDailyBucket{day: day, counts: counts})
		loadedEntries += len(counts)
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

// MaybeSaveSnapshot writes a snapshot to disk if persistence is configured,
// the state is dirty, and at least resolverLeaderboardSaveInterval has elapsed
// since the last save. Errors are logged, not returned.
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
		// Snapshot write failed; mark dirty again so we retry next tick.
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

// FlushSnapshot forces a save regardless of dirtiness or save interval. Used on
// graceful shutdown so the final state is persisted.
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
			Day:    b.day.Format(resolverLeaderboardDayLayout),
			Counts: make(map[string]uint64, len(b.counts)),
		}
		for ip, c := range b.counts {
			entry.Counts[ip.String()] = c
		}
		snap.Buckets = append(snap.Buckets, entry)
	}
	return json.Marshal(snap)
}

// writeFileAtomic writes data to path via a temp file + rename so readers never
// observe a partial write. The temp file path is deterministic (path+".tmp")
// so a kill-9 between Write and Rename never leaks an unbounded number of
// orphan files: the next successful save unlinks any prior tmp via os.Remove
// before recreating it.
func writeFileAtomic(path string, data []byte) error {
	tmpPath := path + ".tmp"

	// Unlink any stale tmp file from a prior crashed save. Errors other than
	// "file does not exist" are returned: a stuck tmp file (permission denied,
	// is-a-directory, etc.) means the next steps would fail too, so surface it
	// now with a clear error.
	if err := os.Remove(tmpPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	// O_EXCL guarantees we won't follow a symlink planted at tmpPath between
	// the Remove above and this call. If we lose the race we return an error
	// and retry next tick.
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
