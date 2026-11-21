/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
	"time"
)

// watchPuller drives complete artifact pulls (lease, record, hold, release)
// into one cache, each under its own key and manifest, so a test can root any
// set of blobs at any hook point of a prune pass.
type watchPuller struct {
	t   *testing.T
	f   *gcFixture
	x   *FileIndex
	pid PodID
	n   int
}

func newWatchPuller(t *testing.T, f *gcFixture) *watchPuller {
	t.Helper()
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatalf("NewFileIndex: %v", err)
	}
	return &watchPuller{t: t, f: f, x: x, pid: f.pod("pod-watch")}
}

// pull leases digests, writes a record and a hold that root all of them, and
// releases the lease, exactly as an artifact pull does: the lease is gone by
// the time the executor looks, so only the record and hold keep the blobs.
func (p *watchPuller) pull(digests ...string) {
	p.t.Helper()
	p.n++
	lease := p.f.cache.AcquireLease(digests, time.Minute)
	defer lease.Release()
	sum := sha256.Sum256([]byte("watch manifest " + string(rune('a'+p.n))))
	manifest := "sha256:" + hex.EncodeToString(sum[:])
	key := "registry.example/models/watch:v" + string(rune('a'+p.n)) + "@" + testModelType
	putTypedArtifact(p.t, p.x, key, testModelType, digests[0], digests...)
	if err := p.x.AddArtifactHoldManifest(context.Background(), p.pid, HeldManifest{
		Digest: manifest, Config: digests[0], Layers: digests,
	}); err != nil {
		p.t.Errorf("AddArtifactHoldManifest: %v", err)
	}
}

// pinnedReason returns the reason rep's pin set kept digest for, or "".
func pinnedReason(rep *ExecuteReport, digest string) PruneReason {
	for _, k := range rep.pinned {
		if k.Digest == digest {
			return k.Reason
		}
	}
	return ""
}

// TestExecutePruneWatchResetKeepsAnotherNamedDigest pins what the watch reset
// relies on: one pull roots BOTH planned blobs just before the first one's
// critical section, so the watch names both. That section resets the whole
// watch (dropping the second blob's entry) and the executor re-reads the
// pins. The second blob is then kept only because the fresh pin set, which
// replaced the batch set, already names it; no second re-read is due. An
// unrooted blob examined last is unlinked, so the pass is not vacuous.
func TestExecutePruneWatchResetKeepsAnotherNamedDigest(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("watch reset blob A", 24*time.Hour)
	b := f.blob("watch reset blob B", 24*time.Hour)
	stray := f.blob("watch reset unrooted blob", 24*time.Hour)
	p := newWatchPuller(t, f)

	pulled := false
	f.cache.beforePruneLock = func(digest string) {
		if pulled || digest != a {
			return
		}
		pulled = true
		p.pull(a, b)
	}
	reads := 0
	pinned := func() (map[string]PruneReason, error) {
		reads++
		return f.cache.pinnedNow(nil)
	}
	rep, err := f.cache.executePrune(planOf(a, b, stray), 0, f.clock, nil, pinned)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !pulled {
		t.Fatal("the hook never ran, so the window was not driven")
	}
	for _, d := range []string{a, b} {
		if !f.exists(d) {
			t.Errorf("blob %s rooted before A's critical section was deleted", d)
		}
		if got := pinnedReason(rep, d); got != ReasonKeptInUse {
			t.Errorf("blob %s kept for reason %q; want %q", d, got, ReasonKeptInUse)
		}
	}
	if f.exists(stray) {
		t.Error("the unrooted blob survived, so the pass proved nothing")
	}
	if reads != 2 {
		t.Errorf("pin reads = %d; want 2 (the batch read and one re-read)", reads)
	}
}

// TestExecutePruneKeepsABlobLeasedDuringTheRepin pins that the watch reset
// happens BEFORE the re-read: a pull of a later planned blob C leases, roots
// and releases it while the re-read triggered for blob A is running, after
// that read took its snapshot. The fresh pin set does not name C, so C is kept
// only because the reset watch caught the lease and forces another re-read at
// C's critical section.
func TestExecutePruneKeepsABlobLeasedDuringTheRepin(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("repin window blob A", 24*time.Hour)
	c := f.blob("repin window blob C", 24*time.Hour)
	p := newWatchPuller(t, f)

	fired := false
	f.cache.beforePruneLock = func(digest string) {
		if fired || digest != a {
			return
		}
		fired = true
		f.cache.AcquireLease([]string{a}, time.Minute).Release()
	}
	reads := 0
	pulled := false
	pinned := func() (map[string]PruneReason, error) {
		reads++
		pins, err := f.cache.pinnedNow(nil)
		if reads == 2 {
			pulled = true
			p.pull(c)
		}
		return pins, err
	}
	rep, err := f.cache.executePrune(planOf(a, c), 0, f.clock, nil, pinned)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !fired || !pulled {
		t.Fatalf("hook fired = %v, pull during re-read = %v; the window was not driven", fired, pulled)
	}
	if !f.exists(c) {
		t.Fatal("a blob a pull rooted during the pin re-read was deleted")
	}
	if got := pinnedReason(rep, c); got != ReasonKeptInUse {
		t.Errorf("blob C kept for reason %q; want %q", got, ReasonKeptInUse)
	}
	if f.exists(a) {
		t.Error("blob A, leased with no root, survived, so the pass proved nothing")
	}
	if reads != 3 {
		t.Errorf("pin reads = %d; want 3 (batch, A's re-read, C's re-read)", reads)
	}
}

// TestExecutePruneExhaustionLeavesTheWatchForLaterEntries pins that hitting
// the re-read bound does not reset the watch: blob A is re-named by a bare
// lease (no root) before every one of its critical sections, and just before
// A's last one a pull roots the later blob B. A is kept and skipped at the
// bound; B is kept only because the watch still names it and forces a fresh
// re-read at B's critical section.
func TestExecutePruneExhaustionLeavesTheWatchForLaterEntries(t *testing.T) {
	f := newGCFixture(t)
	a := f.blob("exhaustion blob A", 24*time.Hour)
	b := f.blob("exhaustion blob B", 24*time.Hour)
	p := newWatchPuller(t, f)

	locks := 0
	f.cache.beforePruneLock = func(digest string) {
		if digest != a {
			return
		}
		locks++
		if locks == 1+maxPruneRepins {
			p.pull(b)
		}
		f.cache.AcquireLease([]string{a}, time.Minute).Release()
	}
	reads := 0
	pinned := func() (map[string]PruneReason, error) {
		reads++
		return f.cache.pinnedNow(nil)
	}
	rep, err := f.cache.executePrune(planOf(a, b), 0, f.clock, nil, pinned)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if locks != 1+maxPruneRepins {
		t.Fatalf("critical sections for A = %d; want %d", locks, 1+maxPruneRepins)
	}
	if !f.exists(a) {
		t.Error("blob A, named on every attempt, was deleted")
	}
	skipped := false
	for _, s := range rep.Skipped {
		if s.Digest == a {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("rep.Skipped = %+v; want A skipped after the bound", rep.Skipped)
	}
	if !f.exists(b) {
		t.Fatal("blob B, rooted before A's last attempt, was deleted")
	}
	if got := pinnedReason(rep, b); got != ReasonKeptInUse {
		t.Errorf("blob B kept for reason %q; want %q", got, ReasonKeptInUse)
	}
	if want := 1 + maxPruneRepins + 1; reads != want {
		t.Errorf("pin reads = %d; want %d (batch, %d for A, one for B)", reads, want, maxPruneRepins)
	}
}

// TestExecutePruneKnownLimitExpiredLeaseDoesNotProtect documents a KNOWN
// LIMIT, not a guarantee (the RESIDUAL in executePrune's doc): a lease counts
// only until its TTL passes on the cache's clock. A blob whose lease has
// expired, with no record or hold written, is unlinked like any unrooted
// blob. A blob under a still-live lease in the same pass is kept, so the
// difference is the TTL alone. If this test starts failing because the
// expired blob survives, the limit has been closed: update the doc, then
// this test.
func TestExecutePruneKnownLimitExpiredLeaseDoesNotProtect(t *testing.T) {
	f := newGCFixture(t)
	expired := f.blob("blob under an expired lease", 24*time.Hour)
	live := f.blob("blob under a live lease", 24*time.Hour)

	short := f.cache.AcquireLease([]string{expired}, time.Minute)
	defer short.Release()
	long := f.cache.AcquireLease([]string{live}, time.Hour)
	defer long.Release()
	f.clock = f.clock.Add(2 * time.Minute)

	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	rep, err := f.cache.executePrune(planOf(expired, live), 0, f.clock, nil, pinned)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if f.exists(expired) || !slices.Contains(rep.Removed, expired) {
		t.Errorf("blob under an expired lease: exists = %v, removed = %v; want unlinked (the known limit)",
			f.exists(expired), rep.Removed)
	}
	if !f.exists(live) {
		t.Error("blob under a live lease was deleted")
	}
	if got := pinnedReason(rep, live); got != ReasonKeptLeased {
		t.Errorf("live-leased blob kept for reason %q; want %q", got, ReasonKeptLeased)
	}
}

// TestExportedExecutePruneConsultsNoLease pins the documented behaviour of the
// offline entry point: ExecutePrune has no pin set, no watch and no lease
// check, so a planned blob under a live lease is unlinked like any other.
// Callers that must honour leases go through reclaim, never through this.
func TestExportedExecutePruneConsultsNoLease(t *testing.T) {
	f := newGCFixture(t)
	b := f.blob("planned blob under a live lease", 24*time.Hour)
	lease := f.cache.AcquireLease([]string{b}, time.Hour)
	defer lease.Release()

	rep, err := f.cache.ExecutePrune(planOf(b), 0, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecutePrune: %v", err)
	}
	if f.exists(b) {
		t.Error("ExecutePrune kept a leased blob; its documented contract consults no lease")
	}
	if !slices.Contains(rep.Removed, b) || rep.Deleted != 1 {
		t.Errorf("report Removed = %v, Deleted = %d; want [%s], 1", rep.Removed, rep.Deleted, b)
	}
}
