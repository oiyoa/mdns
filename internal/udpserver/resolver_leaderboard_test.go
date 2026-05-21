// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

const (
	testDefaultDuration = time.Minute
	testDefaultMTU      = uint16(1200)
)

func recordOne(lb *resolverLeaderboard, now time.Time, ips []netip.Addr) {
	lb.RecordSession(now, ips, testDefaultDuration, testDefaultMTU, nil)
}

func TestLeaderboardRecordsAndRanks(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	cloudflare := mustAddr(t, "1.1.1.1")
	google := mustAddr(t, "8.8.8.8")
	quad9 := mustAddr(t, "9.9.9.9")

	for i := 0; i < 5; i++ {
		recordOne(lb, now, []netip.Addr{cloudflare})
	}
	for i := 0; i < 3; i++ {
		recordOne(lb, now, []netip.Addr{google})
	}
	recordOne(lb, now, []netip.Addr{quad9, cloudflare})

	top, unique := lb.snapshotTop(0)
	if unique != 3 {
		t.Fatalf("expected 3 unique resolvers, got %d", unique)
	}
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}
	if top[0].AddrPort.Addr() != cloudflare || top[0].Sessions != 6 {
		t.Fatalf("expected cloudflare=6 first, got %v sessions=%d", top[0].AddrPort, top[0].Sessions)
	}
	if top[1].AddrPort.Addr() != google || top[1].Sessions != 3 {
		t.Fatalf("expected google=3 second, got %v sessions=%d", top[1].AddrPort, top[1].Sessions)
	}
	if top[2].AddrPort.Addr() != quad9 || top[2].Sessions != 1 {
		t.Fatalf("expected quad9=1 third, got %v sessions=%d", top[2].AddrPort, top[2].Sessions)
	}
}

func TestLeaderboardIgnoresInvalidIPsAndNilArgs(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	recordOne(lb, now, nil)
	recordOne(lb, now, []netip.Addr{{}})
	if _, unique := lb.snapshotTop(0); unique != 0 {
		t.Fatalf("expected empty leaderboard, got %d unique", unique)
	}

	var nilLB *resolverLeaderboard
	nilLB.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")}, time.Minute, 1200, nil)
	if nilLB.MaybeEmit(now, nil) {
		t.Fatal("expected nil receiver MaybeEmit to return false")
	}
}

func TestLeaderboardFiltersNonPublicIPs(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	recordOne(lb, now, []netip.Addr{
		mustAddr(t, "192.168.1.1"),
		mustAddr(t, "10.0.0.53"),
		mustAddr(t, "127.0.0.1"),
		mustAddr(t, "169.254.1.1"),
		mustAddr(t, "1.1.1.1"),
	})
	top, unique := lb.snapshotTop(0)
	if unique != 1 || len(top) != 1 || top[0].AddrPort.Addr() != mustAddr(t, "1.1.1.1") {
		t.Fatalf("expected only the public IP to survive sanitization, got %v", top)
	}
}

func TestLeaderboardSlidingWindowDropsOldBuckets(t *testing.T) {
	lb := newResolverLeaderboard()
	day0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	old := mustAddr(t, "1.0.0.1")
	recent := mustAddr(t, "8.8.4.4")

	recordOne(lb, day0, []netip.Addr{old})

	tenDaysLater := day0.AddDate(0, 0, 10)
	recordOne(lb, tenDaysLater, []netip.Addr{recent})

	top, unique := lb.snapshotTop(0)
	if unique != 1 || len(top) != 1 || top[0].AddrPort.Addr() != recent {
		t.Fatalf("expected only recent entry, got top=%v unique=%d", top, unique)
	}
	if got := len(lb.buckets); got != 1 {
		t.Fatalf("expected 1 bucket retained, got %d", got)
	}
}

func TestLeaderboardKeepsAllSevenDays(t *testing.T) {
	lb := newResolverLeaderboard()
	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	ip := mustAddr(t, "1.1.1.1")

	for d := 0; d < resolverLeaderboardWindowDays; d++ {
		recordOne(lb, base.AddDate(0, 0, d), []netip.Addr{ip})
	}

	if got := len(lb.buckets); got != resolverLeaderboardWindowDays {
		t.Fatalf("expected %d buckets, got %d", resolverLeaderboardWindowDays, got)
	}
	top, _ := lb.snapshotTop(0)
	if len(top) != 1 || top[0].Sessions != uint64(resolverLeaderboardWindowDays) {
		t.Fatalf("expected ip sessions=%d, got %v", resolverLeaderboardWindowDays, top)
	}
}

func TestLeaderboardBucketCapDropsExcessIPs(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	for i := 0; i < resolverLeaderboardBucketCap; i++ {
		// 11.0.0.0/8 is public, so sanitization doesn't reject these.
		ip := netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)})
		recordOne(lb, now, []netip.Addr{ip})
	}
	overflowIP := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	recordOne(lb, now, []netip.Addr{overflowIP})

	_, unique := lb.snapshotTop(0)
	if unique != resolverLeaderboardBucketCap {
		t.Fatalf("expected unique=%d (cap), got %d", resolverLeaderboardBucketCap, unique)
	}

	existingIP := netip.AddrFrom4([4]byte{11, 0, 0, 0})
	before := lb.bucketSessionsFor(now, existingIP)
	recordOne(lb, now, []netip.Addr{existingIP})
	after := lb.bucketSessionsFor(now, existingIP)
	if after != before+1 {
		t.Fatalf("expected existing-ip count to grow past cap: before=%d after=%d", before, after)
	}
}

func TestLeaderboardHourlyThrottle(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	recordOne(lb, now, []netip.Addr{mustAddr(t, "1.1.1.1")})

	if !lb.tryAdvanceHour(now) {
		t.Fatal("first call should advance the throttle")
	}
	if lb.tryAdvanceHour(now.Add(30 * time.Minute)) {
		t.Fatal("same hour must not advance")
	}
	if !lb.tryAdvanceHour(now.Add(time.Hour)) {
		t.Fatal("next hour must advance")
	}
}

func TestLeaderboardConcurrentRecording(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	ip := mustAddr(t, "1.1.1.1")

	const workers = 16
	const perWorker = 100
	done := make(chan struct{}, workers)
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < perWorker; i++ {
				recordOne(lb, now, []netip.Addr{ip})
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	top, _ := lb.snapshotTop(0)
	if len(top) != 1 || top[0].Sessions != workers*perWorker {
		t.Fatalf("expected sessions=%d, got %v", workers*perWorker, top)
	}
}

func TestLeaderboardPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	lb1 := newResolverLeaderboard()
	lb1.ConfigurePersistence(path, nil)

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	cloudflare := mustAddr(t, "1.1.1.1")
	google := mustAddr(t, "8.8.8.8")
	recordOne(lb1, now, []netip.Addr{cloudflare, cloudflare})
	recordOne(lb1, now, []netip.Addr{google})
	recordOne(lb1, now.AddDate(0, 0, -1), []netip.Addr{cloudflare})

	lb1.FlushSnapshot(now)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot file not written: %v", err)
	}

	lb2 := newResolverLeaderboard()
	lb2.ConfigurePersistence(path, nil)
	lb2.LoadSnapshot(now)

	top, unique := lb2.snapshotTop(0)
	if unique != 2 {
		t.Fatalf("expected 2 unique IPs after load, got %d", unique)
	}
	var cfCount, gCount uint64
	for _, e := range top {
		switch e.AddrPort.Addr() {
		case cloudflare:
			cfCount = e.Sessions
		case google:
			gCount = e.Sessions
		}
	}
	if cfCount != 3 {
		t.Fatalf("expected cloudflare count=3 after load, got %d", cfCount)
	}
	if gCount != 1 {
		t.Fatalf("expected google count=1 after load, got %d", gCount)
	}
}

func TestLeaderboardLoadDropsStaleBuckets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	old := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	snap := leaderboardSnapshotFile{
		Version: resolverLeaderboardSchema,
		Buckets: []leaderboardSnapshotBucket{
			{
				Day: old.Format(resolverLeaderboardDayLayout),
				Entries: map[string]leaderboardSnapshotMetrics{
					"1.1.1.1:53": {Sessions: 99},
				},
			},
		},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)
	lb.LoadSnapshot(time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC))

	_, unique := lb.snapshotTop(0)
	if unique != 0 {
		t.Fatalf("expected stale bucket dropped, got %d unique", unique)
	}
}

func TestLeaderboardLoadMissingFileIsNoOp(t *testing.T) {
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(filepath.Join(t.TempDir(), "does-not-exist.json"), nil)
	lb.LoadSnapshot(time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC))

	if _, unique := lb.snapshotTop(0); unique != 0 {
		t.Fatalf("expected empty leaderboard, got %d unique", unique)
	}
}

func TestLeaderboardLoadCorruptFileStartsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)
	lb.LoadSnapshot(time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC))

	if _, unique := lb.snapshotTop(0); unique != 0 {
		t.Fatalf("expected empty leaderboard after corrupt load, got %d unique", unique)
	}
}

func TestLeaderboardMaybeSaveSkipsWhenClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	lb.MaybeSaveSnapshot(time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no snapshot file when clean, got err=%v", err)
	}
}

func TestLeaderboardMaybeSaveThrottlesByInterval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	t0 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	ip1 := mustAddr(t, "1.1.1.1")
	ip2 := mustAddr(t, "8.8.8.8")

	recordOne(lb, t0, []netip.Addr{ip1})
	lb.MaybeSaveSnapshot(t0)
	content1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("first save did not happen: %v", err)
	}

	// Add a new IP and try to save again within the interval. The throttle
	// should skip the write so file content stays the same. Asserting on
	// file contents (not mtime) sidesteps filesystem mtime-granularity flakes.
	recordOne(lb, t0.Add(time.Minute), []netip.Addr{ip2})
	lb.MaybeSaveSnapshot(t0.Add(time.Minute))
	content2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after throttled save: %v", err)
	}
	if !bytes.Equal(content1, content2) {
		t.Fatal("second save should have been throttled out within the interval")
	}

	// After the interval, save proceeds and the second IP appears on disk.
	lb.MaybeSaveSnapshot(t0.Add(resolverLeaderboardSaveInterval + time.Second))
	content3, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after post-interval save: %v", err)
	}
	if bytes.Equal(content3, content1) {
		t.Fatal("save after interval should have updated the file")
	}
}

func TestLeaderboardSaveCleansUpOrphanTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, []byte("garbage from crashed write"), 0o644); err != nil {
		t.Fatalf("plant tmp: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	recordOne(lb, now, []netip.Addr{mustAddr(t, "1.1.1.1")})
	lb.MaybeSaveSnapshot(now)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot not written: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("orphan tmp file still present after save: err=%v", err)
	}
}

func TestLeaderboardSaveRecreatesAfterRuntimeDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	t0 := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	recordOne(lb, t0, []netip.Addr{mustAddr(t, "1.1.1.1")})
	lb.MaybeSaveSnapshot(t0)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	recordOne(lb, t0.Add(resolverLeaderboardSaveInterval+time.Second), []netip.Addr{mustAddr(t, "8.8.8.8")})
	lb.MaybeSaveSnapshot(t0.Add(resolverLeaderboardSaveInterval + time.Second))

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot was not recreated after runtime deletion: %v", err)
	}
}

func TestLeaderboardLoadSkipsFutureDayEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	future := now.AddDate(0, 0, 3)
	snap := leaderboardSnapshotFile{
		Version: resolverLeaderboardSchema,
		Buckets: []leaderboardSnapshotBucket{
			{
				Day: future.Format(resolverLeaderboardDayLayout),
				Entries: map[string]leaderboardSnapshotMetrics{
					"1.1.1.1:53": {Sessions: 99},
				},
			},
		},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)
	lb.LoadSnapshot(now)

	if _, unique := lb.snapshotTop(0); unique != 0 {
		t.Fatalf("expected future-dated entries to be skipped, got %d unique", unique)
	}
}

func TestLeaderboardLoadSkipsInvalidIPsInOtherwiseValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	snap := leaderboardSnapshotFile{
		Version: resolverLeaderboardSchema,
		Buckets: []leaderboardSnapshotBucket{
			{
				Day: now.Format(resolverLeaderboardDayLayout),
				Entries: map[string]leaderboardSnapshotMetrics{
					"1.1.1.1:53":     {Sessions: 5},
					"":               {Sessions: 3},
					"not-an-ip":      {Sessions: 2},
					"999.999.0.1:53": {Sessions: 1},
				},
			},
		},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)
	lb.LoadSnapshot(now)

	top, unique := lb.snapshotTop(0)
	if unique != 1 || len(top) != 1 || top[0].Sessions != 5 {
		t.Fatalf("expected only valid IP to load: got top=%v unique=%d", top, unique)
	}
}

func TestLeaderboardFlushSnapshotAlwaysWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lb.FlushSnapshot(now)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("flush should have created the file even when empty: %v", err)
	}
}

func TestLeaderboardRecordsScoredEntries(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	good := mustAddr(t, "1.1.1.1")
	bad := mustAddr(t, "8.8.8.8")

	// Both resolvers used in the same number of sessions, same duration/MTU.
	// good has 99% success; bad has 30% success. Score must put good above bad.
	for i := 0; i < 5; i++ {
		lb.RecordSession(now, []netip.Addr{good}, time.Minute*10, 1200, SessionResolverScores{
			good: {SuccessCount: 99, FailureCount: 1},
		})
		lb.RecordSession(now, []netip.Addr{bad}, time.Minute*10, 1200, SessionResolverScores{
			bad: {SuccessCount: 30, FailureCount: 70},
		})
	}

	top := lb.TopForDistribution(5)
	if len(top) != 2 {
		t.Fatalf("expected 2 entries, got %d (%v)", len(top), top)
	}
	if top[0].AddrPort.Addr() != good {
		t.Fatalf("higher success rate should rank first, got order: %v", top)
	}
}

func TestLeaderboardMixesV1AndV2Sessions(t *testing.T) {
	// One V1 session for IP A, one V2 session for IP B with 100% success.
	// The V2 score-rate term should make B rank competitively against A even
	// though they share the same popularity / duration / MTU. Specifically
	// B should not be dragged down by "missing" V2 data — A is missing it too
	// (V1 path), so both go through the redistribute branch.
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	a := mustAddr(t, "1.1.1.1")
	b := mustAddr(t, "8.8.8.8")

	lb.RecordSession(now, []netip.Addr{a}, time.Minute*5, 1200, nil) // V1
	lb.RecordSession(now, []netip.Addr{b}, time.Minute*5, 1200, SessionResolverScores{
		b: {SuccessCount: 100, FailureCount: 0},
	})

	top := lb.TopForDistribution(5)
	if len(top) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(top))
	}
	// B has V2 100% success, A has no V2 data. B should rank at least as high.
	scoreA, scoreB := uint16(0), uint16(0)
	for _, e := range top {
		switch e.AddrPort.Addr() {
		case a:
			scoreA = e.Score
		case b:
			scoreB = e.Score
		}
	}
	if scoreB < scoreA {
		t.Fatalf("V2 100%% success should not rank below V1 unknown: scoreA=%d scoreB=%d", scoreA, scoreB)
	}
}

func TestLeaderboardSnapshotV1MigrationKeepsHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	// Write a synthetic v1 snapshot (no scored fields).
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	v1 := leaderboardSnapshotFile{
		Version: 1,
		Buckets: []leaderboardSnapshotBucket{{
			Day: now.UTC().Format(resolverLeaderboardDayLayout),
			Entries: map[string]leaderboardSnapshotMetrics{
				"1.1.1.1:53": {Sessions: 10, DurationSumNS: uint64(time.Minute * 30), DownloadMTUSum: 12000},
			},
		}},
	}
	data, err := json.Marshal(v1)
	if err != nil {
		t.Fatalf("marshal v1: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)
	lb.LoadSnapshot(now)

	top := lb.TopForDistribution(5)
	if len(top) != 1 || top[0].AddrPort.Addr() != mustAddr(t, "1.1.1.1") {
		t.Fatalf("v1 snapshot history must survive migration, got %v", top)
	}
	if top[0].Sessions != 10 {
		t.Fatalf("session count must survive v1->v2 migration, got %d", top[0].Sessions)
	}
}

func TestLeaderboardSnapshotRoundTripScoredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	first := newResolverLeaderboard()
	first.ConfigurePersistence(path, nil)
	first.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")}, time.Minute*5, 1200, SessionResolverScores{
		mustAddr(t, "1.1.1.1"): {SuccessCount: 42, FailureCount: 3},
	})
	first.FlushSnapshot(now)

	// Reload into a fresh leaderboard and confirm scored fields survived.
	second := newResolverLeaderboard()
	second.ConfigurePersistence(path, nil)
	second.LoadSnapshot(now)

	second.mu.Lock()
	defer second.mu.Unlock()
	if len(second.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(second.buckets))
	}
	entry := second.buckets[0].entries[netip.AddrPortFrom(mustAddr(t, "1.1.1.1"), resolverDefaultPort)]
	if entry == nil {
		t.Fatal("entry missing after reload")
	}
	if entry.ReportedSuccessSum != 42 || entry.ReportedFailureSum != 3 || entry.SuccessSampleN != 1 {
		t.Fatalf("scored fields lost on round-trip: %+v", entry)
	}

	// Confirm the on-disk file uses schema 2.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"version":2`)) {
		t.Fatalf("snapshot should be schema 2, got: %s", raw)
	}
}

func TestComposeRankScoreOrdering(t *testing.T) {
	a := composeRankScore(100, 100, time.Minute, 1200, 0, false, 0, false)
	b := composeRankScore(10, 100, time.Minute, 1200, 0, false, 0, false)
	if a <= b {
		t.Fatalf("more sessions should win: a=%d b=%d", a, b)
	}
	c := composeRankScore(50, 100, time.Hour, 9999, 0, false, 0, false)
	d := composeRankScore(50, 100, time.Hour, 4000, 0, false, 0, false)
	if c != d {
		t.Fatalf("MTU above cap should clamp: c=%d d=%d", c, d)
	}
}

func TestComposeRankScoreFactorsInSuccessRate(t *testing.T) {
	bad := composeRankScore(50, 100, time.Minute, 1200, 0.10, true, 0, false)
	good := composeRankScore(50, 100, time.Minute, 1200, 0.99, true, 0, false)
	if good <= bad {
		t.Fatalf("higher success rate should rank higher: good=%d bad=%d", good, bad)
	}
}

func TestComposeRankScoreFactorsInRtt(t *testing.T) {
	slow := composeRankScore(50, 100, time.Minute, 1200, 0.5, true, 250, true)
	fast := composeRankScore(50, 100, time.Minute, 1200, 0.5, true, 20, true)
	if fast <= slow {
		t.Fatalf("lower RTT should rank higher: fast=%d slow=%d", fast, slow)
	}
}

func TestComposeRankScoreRedistributesWhenNoSuccessRate(t *testing.T) {
	noData := composeRankScore(100, 100, time.Minute, 1200, 0, false, 0, false)
	zeroRate := composeRankScore(100, 100, time.Minute, 1200, 0, true, 0, false)
	if noData <= zeroRate {
		t.Fatalf("absent V2 data should out-rank an explicit 0-success-rate report: noData=%d zeroRate=%d", noData, zeroRate)
	}
}

func TestComposeRankScoreRedistributesWhenNoRtt(t *testing.T) {
	noRtt := composeRankScore(100, 100, time.Minute, 1200, 0.5, true, 0, false)
	worstRtt := composeRankScore(100, 100, time.Minute, 1200, 0.5, true, 0xFFFF, true)
	if noRtt <= worstRtt {
		t.Fatalf("absent RTT data should out-rank an explicit max-RTT report: noRtt=%d worstRtt=%d", noRtt, worstRtt)
	}
}

func (l *resolverLeaderboard) snapshotTop(n int) ([]resolverLeaderboardEntry, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotTopLocked(n)
}

func (l *resolverLeaderboard) bucketSessionsFor(now time.Time, ip netip.Addr) uint64 {
	day := truncToUTCDay(now)
	key := netip.AddrPortFrom(ip.Unmap(), resolverDefaultPort)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.buckets {
		if b.day.Equal(day) {
			if e := b.entries[key]; e != nil {
				return e.Sessions
			}
			return 0
		}
	}
	return 0
}

func (l *resolverLeaderboard) tryAdvanceHour(now time.Time) bool {
	hour := now.UTC().Truncate(time.Hour)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lastEmitHour.IsZero() && !hour.After(l.lastEmitHour) {
		return false
	}
	l.lastEmitHour = hour
	return true
}
