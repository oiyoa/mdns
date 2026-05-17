// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"net/netip"
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

func TestLeaderboardRecordsAndRanks(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	cloudflare := mustAddr(t, "1.1.1.1")
	google := mustAddr(t, "8.8.8.8")
	quad9 := mustAddr(t, "9.9.9.9")

	for i := 0; i < 5; i++ {
		lb.RecordSession(now, []netip.Addr{cloudflare})
	}
	for i := 0; i < 3; i++ {
		lb.RecordSession(now, []netip.Addr{google})
	}
	lb.RecordSession(now, []netip.Addr{quad9, cloudflare})

	top, unique := lb.snapshotTop(0)
	if unique != 3 {
		t.Fatalf("expected 3 unique resolvers, got %d", unique)
	}
	if len(top) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(top))
	}
	if top[0].ip != cloudflare || top[0].count != 6 {
		t.Fatalf("expected cloudflare=6 first, got %v=%d", top[0].ip, top[0].count)
	}
	if top[1].ip != google || top[1].count != 3 {
		t.Fatalf("expected google=3 second, got %v=%d", top[1].ip, top[1].count)
	}
	if top[2].ip != quad9 || top[2].count != 1 {
		t.Fatalf("expected quad9=1 third, got %v=%d", top[2].ip, top[2].count)
	}
}

func TestLeaderboardIgnoresInvalidIPsAndNilArgs(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lb.RecordSession(now, nil)
	lb.RecordSession(now, []netip.Addr{{}})
	if _, unique := lb.snapshotTop(0); unique != 0 {
		t.Fatalf("expected empty leaderboard, got %d unique", unique)
	}

	var nilLB *resolverLeaderboard
	nilLB.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")})
	if nilLB.MaybeEmit(now, nil) {
		t.Fatal("expected nil receiver MaybeEmit to return false")
	}
}

func TestLeaderboardSlidingWindowDropsOldBuckets(t *testing.T) {
	lb := newResolverLeaderboard()
	day0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	old := mustAddr(t, "1.0.0.1")
	recent := mustAddr(t, "8.8.4.4")

	lb.RecordSession(day0, []netip.Addr{old})

	tenDaysLater := day0.AddDate(0, 0, 10)
	lb.RecordSession(tenDaysLater, []netip.Addr{recent})

	top, unique := lb.snapshotTop(0)
	if unique != 1 || len(top) != 1 || top[0].ip != recent {
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
		lb.RecordSession(base.AddDate(0, 0, d), []netip.Addr{ip})
	}

	if got := len(lb.buckets); got != resolverLeaderboardWindowDays {
		t.Fatalf("expected %d buckets, got %d", resolverLeaderboardWindowDays, got)
	}
	top, _ := lb.snapshotTop(0)
	if len(top) != 1 || top[0].count != uint64(resolverLeaderboardWindowDays) {
		t.Fatalf("expected ip count=%d, got %v", resolverLeaderboardWindowDays, top)
	}
}

func TestLeaderboardBucketCapDropsExcessIPs(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)

	// Fill the bucket exactly to the cap, then try to add one more distinct IP.
	for i := 0; i < resolverLeaderboardBucketCap; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		lb.RecordSession(now, []netip.Addr{ip})
	}
	overflowIP := netip.AddrFrom4([4]byte{192, 0, 2, 1})
	lb.RecordSession(now, []netip.Addr{overflowIP})

	_, unique := lb.snapshotTop(0)
	if unique != resolverLeaderboardBucketCap {
		t.Fatalf("expected unique=%d (cap), got %d", resolverLeaderboardBucketCap, unique)
	}

	// Existing IPs still increment after cap is reached.
	existingIP := netip.AddrFrom4([4]byte{10, 0, 0, 0})
	before := lb.bucketCountFor(now, existingIP)
	lb.RecordSession(now, []netip.Addr{existingIP})
	after := lb.bucketCountFor(now, existingIP)
	if after != before+1 {
		t.Fatalf("expected existing-ip count to grow past cap: before=%d after=%d", before, after)
	}
}

func TestLeaderboardHourlyThrottle(t *testing.T) {
	lb := newResolverLeaderboard()
	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lb.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")})

	// MaybeEmit with a nil logger returns false even on first call. Use the
	// internal flag check instead: drive the throttle directly.
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
				lb.RecordSession(now, []netip.Addr{ip})
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	top, _ := lb.snapshotTop(0)
	if len(top) != 1 || top[0].count != workers*perWorker {
		t.Fatalf("expected count=%d, got %v", workers*perWorker, top)
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
	lb1.RecordSession(now, []netip.Addr{cloudflare, cloudflare}) // duplicates within one call still increment
	lb1.RecordSession(now, []netip.Addr{google})
	lb1.RecordSession(now.AddDate(0, 0, -1), []netip.Addr{cloudflare})

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
		switch e.ip {
		case cloudflare:
			cfCount = e.count
		case google:
			gCount = e.count
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

	old := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC) // way outside the 7d window
	snap := leaderboardSnapshotFile{
		Version: resolverLeaderboardSchema,
		Buckets: []leaderboardSnapshotBucket{
			{Day: old.Format(resolverLeaderboardDayLayout), Counts: map[string]uint64{"1.1.1.1": 99}},
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
	ip := mustAddr(t, "1.1.1.1")

	lb.RecordSession(t0, []netip.Addr{ip})
	lb.MaybeSaveSnapshot(t0)
	stat1, err := os.Stat(path)
	if err != nil {
		t.Fatalf("first save did not happen: %v", err)
	}

	// Record more, but advance time only slightly. Save must skip.
	lb.RecordSession(t0.Add(time.Minute), []netip.Addr{ip})
	lb.MaybeSaveSnapshot(t0.Add(time.Minute))
	stat2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !stat2.ModTime().Equal(stat1.ModTime()) {
		t.Fatal("second save should have been throttled out within the interval")
	}

	// Advance past the interval; save should now go through.
	lb.MaybeSaveSnapshot(t0.Add(resolverLeaderboardSaveInterval + time.Second))
	stat3, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if stat3.ModTime().Equal(stat1.ModTime()) {
		t.Fatal("save after interval should have updated the file")
	}
}

func TestLeaderboardSaveCleansUpOrphanTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	tmpPath := path + ".tmp"

	// Plant an orphan tmp file as if a previous run crashed mid-write.
	if err := os.WriteFile(tmpPath, []byte("garbage from crashed write"), 0o644); err != nil {
		t.Fatalf("plant tmp: %v", err)
	}

	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lb.RecordSession(now, []netip.Addr{mustAddr(t, "1.1.1.1")})
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
	lb.RecordSession(t0, []netip.Addr{mustAddr(t, "1.1.1.1")})
	lb.MaybeSaveSnapshot(t0)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	// Operator deletes the file out from under the running server.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// New activity arrives; next save (after interval) recreates the file.
	lb.RecordSession(t0.Add(resolverLeaderboardSaveInterval+time.Second), []netip.Addr{mustAddr(t, "8.8.8.8")})
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
			{Day: future.Format(resolverLeaderboardDayLayout), Counts: map[string]uint64{"1.1.1.1": 99}},
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
				Counts: map[string]uint64{
					"1.1.1.1":     5,
					"":            3,
					"not-an-ip":   2,
					"999.999.0.1": 1,
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
	if unique != 1 || len(top) != 1 || top[0].count != 5 {
		t.Fatalf("expected only valid IP to load: got top=%v unique=%d", top, unique)
	}
}

func TestLeaderboardFlushSnapshotAlwaysWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	lb := newResolverLeaderboard()
	lb.ConfigurePersistence(path, nil)

	now := time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC)
	lb.FlushSnapshot(now) // empty state is still serialized
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("flush should have created the file even when empty: %v", err)
	}
}

// test helpers exposed via _test.go-only methods on the leaderboard.

func (l *resolverLeaderboard) snapshotTop(n int) ([]resolverLeaderboardEntry, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshotTopLocked(n)
}

func (l *resolverLeaderboard) bucketCountFor(now time.Time, ip netip.Addr) uint64 {
	day := truncToUTCDay(now)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, b := range l.buckets {
		if b.day.Equal(day) {
			return b.counts[ip]
		}
	}
	return 0
}

// tryAdvanceHour mimics MaybeEmit's throttle decision without requiring a Logger.
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
