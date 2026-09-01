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
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// gcFixture is a store with a controllable clock, plus helpers to put blobs and
// pod reachability records on disk. Everything lives under t.TempDir().
type gcFixture struct {
	t     *testing.T
	cache *Cache
	clock time.Time
}

func newGCFixture(t *testing.T) *gcFixture {
	t.Helper()
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	f := &gcFixture{t: t, cache: c, clock: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)}
	c.now = func() time.Time { return f.clock }
	return f
}

// blob commits content and back-dates it by age so the grace window is not the
// thing under test unless a case says so. It returns the digest.
func (f *gcFixture) blob(content string, age time.Duration) string {
	f.t.Helper()
	sum := sha256.Sum256([]byte(content))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := f.cache.CommitBlob(digest, int64(len(content)), func(w io.Writer) error {
		_, err := io.WriteString(w, content)
		return err
	}); err != nil {
		f.t.Fatalf("CommitBlob(%s): %v", digest, err)
	}
	p, err := f.cache.BlobPath(digest)
	if err != nil {
		f.t.Fatalf("BlobPath: %v", err)
	}
	old := f.clock.Add(-age)
	if err := os.Chtimes(p, old, old); err != nil {
		f.t.Fatalf("Chtimes: %v", err)
	}
	return digest
}

// pod creates a pod dir and records roots for it, exactly as the daemon does.
func (f *gcFixture) pod(id string, roots ...ImageRoot) PodID {
	f.t.Helper()
	pid, err := ParsePodID(id)
	if err != nil {
		f.t.Fatalf("ParsePodID(%q): %v", id, err)
	}
	if err := os.MkdirAll(f.cache.PodRootfs(pid), 0o755); err != nil {
		f.t.Fatalf("mkdir pod rootfs: %v", err)
	}
	if err := f.cache.EnsurePodReferences(pid); err != nil {
		f.t.Fatalf("EnsurePodReferences: %v", err)
	}
	for _, r := range roots {
		if err := f.cache.RecordPodImage(pid, r); err != nil {
			f.t.Fatalf("RecordPodImage: %v", err)
		}
	}
	return pid
}

func (f *gcFixture) exists(digest string) bool {
	f.t.Helper()
	return f.cache.Has(digest)
}

// fakeFree is a FreeBytesFunc whose readings are scripted: it returns free[i]
// for the i-th call and repeats the last value thereafter. That is what lets a
// test assert the reclaim loop RE-MEASURES between unlinks instead of spending a
// precomputed budget.
type fakeFree struct {
	mu      sync.Mutex
	free    []uint64
	calls   int
	err     error
	errFrom int
}

func (f *fakeFree) sample(string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil && f.calls >= f.errFrom {
		return 0, f.err
	}
	i := f.calls - 1
	if i >= len(f.free) {
		i = len(f.free) - 1
	}
	return f.free[i], nil
}

func (f *fakeFree) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestDiskPressureReclaim is B130b's named GATE: the daemon-side disk-pressure
// image GC.
//
// It asserts the four properties that make the trigger a trigger rather than a
// timer, and it is written so that removing any one of them turns a subtest red:
//
//	(1) no pressure, no reclaim — above the free-space floor nothing is deleted,
//	    and no root is even enumerated;
//	(2) under pressure, unreferenced content IS reclaimed;
//	(3) the loop stops on a measured target, re-sampling between unlinks rather
//	    than spending a precomputed byte budget (the APFS-clonefile constraint:
//	    an unlink whose extents are still shared frees nothing);
//	(4) a free-space sample that FAILS refuses the whole pass — fail-closed on
//	    ignorance, because statfs breaking is the first symptom of the volume
//	    this GC is defending going bad.
//
// The liveness half of the contract has its own gate, TestLivePodBlobsSurviveReclaim.
func TestDiskPressureReclaim(t *testing.T) {
	t.Parallel()

	t.Run("above the floor nothing is reclaimed", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		orphan := f.blob("unreferenced payload", time.Hour)
		f.pod("pod-a")

		free := &fakeFree{free: []uint64{200}}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes:   100,
			TargetFreeBytes: 150,
			Grace:           time.Minute,
			FreeBytes:       free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if rep.Triggered {
			t.Errorf("Triggered = true above the pressure floor; want false")
		}
		if len(rep.Removed) != 0 {
			t.Errorf("Removed = %v above the pressure floor; want none", rep.Removed)
		}
		if !f.exists(orphan) {
			t.Errorf("unreferenced blob was deleted with no disk pressure")
		}
	})

	t.Run("under pressure unreferenced content is reclaimed", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		orphanA := f.blob("orphan a", time.Hour)
		orphanB := f.blob("orphan b", time.Hour)
		f.pod("pod-a")

		free := &fakeFree{free: []uint64{10}} // always below target: drain the plan
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes:   100,
			TargetFreeBytes: 150,
			Grace:           time.Minute,
			FreeBytes:       free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !rep.Triggered {
			t.Fatalf("Triggered = false under the pressure floor; want true")
		}
		if f.exists(orphanA) || f.exists(orphanB) {
			t.Errorf("unreferenced blobs survived a triggered reclaim")
		}
		if got := len(rep.Removed); got != 2 {
			t.Errorf("Removed = %v (%d); want both orphans", rep.Removed, got)
		}
		if rep.ReachedTarget {
			t.Errorf("ReachedTarget = true while every sample stayed below the target")
		}
	})

	t.Run("a live pod's content is never in the delete set", func(t *testing.T) {
		t.Parallel()
		// The named gate carries the liveness assertion too, not only the trigger
		// mechanics: a GC that reclaims correctly and unroots a running pod while
		// doing it has not passed. TestLivePodBlobsSurviveReclaim is the
		// adversarial expansion of this one line.
		f := newGCFixture(t)
		live := f.blob("live layer", time.Hour)
		orphan := f.blob("orphan layer", time.Hour)
		f.pod("pod-live", ImageRoot{Reference: "app:v1", Config: live})

		free := &fakeFree{free: []uint64{10}}
		_, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes: 100, TargetFreeBytes: 150, Grace: time.Minute, FreeBytes: free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(live) {
			t.Fatalf("a live pod's blob was reclaimed under disk pressure")
		}
		if f.exists(orphan) {
			t.Errorf("the unreferenced blob survived, so this case proved nothing")
		}
	})

	t.Run("stops on a measured target, not a byte budget", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		// Three equally-sized orphans. A byte-budget implementation, told it needs
		// 140 bytes and seeing 8-byte blobs, would delete all three. The measured
		// loop deletes exactly one, because the sample taken after the first unlink
		// already reports the target met.
		var orphans []string
		for _, c := range []string{"orphan-1", "orphan-2", "orphan-3"} {
			orphans = append(orphans, f.blob(c, time.Hour))
		}
		f.pod("pod-a")

		// call 1: the pressure check (10, under the floor)
		// call 2: the pre-unlink stop check for blob #1 (10, keep going)
		// call 3+: the target is met, so the loop stops before blob #2
		free := &fakeFree{free: []uint64{10, 10, 150}}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes:   100,
			TargetFreeBytes: 150,
			Grace:           time.Minute,
			FreeBytes:       free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if got := len(rep.Removed); got != 1 {
			t.Fatalf("Removed %d blobs; want exactly 1 (the loop must stop on the MEASURED target)", got)
		}
		alive := 0
		for _, d := range orphans {
			if f.exists(d) {
				alive++
			}
		}
		if alive != 2 {
			t.Errorf("%d orphans survived; want 2 — the loop kept deleting past its measured target", alive)
		}
		if !rep.ReachedTarget {
			t.Errorf("ReachedTarget = false after the closing sample met the target")
		}
		if free.count() < 3 {
			t.Errorf("free space sampled %d times; the loop must RE-MEASURE between unlinks", free.count())
		}
	})

	t.Run("an unsamplable volume refuses the pass", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		orphan := f.blob("orphan", time.Hour)
		f.pod("pod-a")

		free := &fakeFree{free: []uint64{10}, err: errors.New("statfs: input/output error"), errFrom: 1}
		_, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes:   100,
			TargetFreeBytes: 150,
			Grace:           time.Minute,
			FreeBytes:       free.sample,
		})
		if !errors.Is(err, ErrFreeSpaceUnknown) {
			t.Fatalf("err = %v; want ErrFreeSpaceUnknown", err)
		}
		if !f.exists(orphan) {
			t.Errorf("a blob was deleted on a pass that could not measure free space")
		}
	})

	t.Run("a stale ingest temp file is reclaimed, a fresh one is not", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		f.pod("pod-a")
		dir := filepath.Join(f.cache.Root(), "blobs", "sha256")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		stale, fresh := filepath.Join(dir, ".blob-1"), filepath.Join(dir, ".blob-2")
		for _, p := range []string{stale, fresh} {
			if err := os.WriteFile(p, []byte("partial"), 0o644); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
		}
		old := f.clock.Add(-time.Hour)
		if err := os.Chtimes(stale, old, old); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}

		free := &fakeFree{free: []uint64{10}}
		if _, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes: 100, TargetFreeBytes: 150, Grace: time.Minute, FreeBytes: free.sample,
		}); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("stale temp file survived reclaim (err %v)", err)
		}
		if _, err := os.Lstat(fresh); err != nil {
			t.Errorf("temp file younger than grace was deleted: %v", err)
		}
	})

	t.Run("a forced prune drains the plan and ignores the target", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		var orphans []string
		for _, c := range []string{"o1", "o2", "o3"} {
			orphans = append(orphans, f.blob(c, time.Hour))
		}
		f.pod("pod-a")
		// Free space is way above the floor, so the pressure trigger would do
		// nothing at all. Force is a different request — "delete what nothing
		// references" — and must answer that one, in full.
		free := &fakeFree{free: []uint64{1 << 40}}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes: 100, TargetFreeBytes: 150, Grace: time.Minute,
			Force: true, FreeBytes: free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if got := len(rep.Removed); got != len(orphans) {
			t.Fatalf("Removed %d of %d orphans; a forced prune drains the plan", got, len(orphans))
		}
		for _, d := range orphans {
			if f.exists(d) {
				t.Errorf("orphan %s survived a forced prune", d)
			}
		}
	})

	t.Run("dry run reports without deleting", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		orphan := f.blob("orphan", time.Hour)
		f.pod("pod-a")

		free := &fakeFree{free: []uint64{10}}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
			HighFreeBytes: 100, TargetFreeBytes: 150, Grace: time.Minute,
			DryRun: true, FreeBytes: free.sample,
		})
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if len(rep.Removed) != 1 || rep.Removed[0] != orphan {
			t.Errorf("dry-run Removed = %v; want [%s]", rep.Removed, orphan)
		}
		if !f.exists(orphan) {
			t.Fatalf("dry run DELETED a blob")
		}
	})
}

// TestLivePodBlobsSurviveReclaim is the load-bearing safety gate: an image GC
// that unlinks a live pod's content is data loss, so this is written to be
// ADVERSARIAL rather than incidental.
//
// Every case puts the store under maximum pressure (free far below the floor,
// target unreachable), sets grace to zero so no age window can accidentally save
// anything, and then asserts the live pod's blobs are still there. The only
// thing standing between the blob and the unlink in each case is the property
// being tested.
func TestLivePodBlobsSurviveReclaim(t *testing.T) {
	t.Parallel()

	// maximal pressure: nothing is ever above the target, so the loop drains the
	// entire delete plan and grace saves nothing.
	press := func(f *gcFixture) ReclaimConfig {
		return ReclaimConfig{
			HighFreeBytes: 1 << 40, TargetFreeBytes: 1 << 40, Grace: 0,
			FreeBytes: (&fakeFree{free: []uint64{0}}).sample,
		}
	}

	t.Run("a running pod's config and layers are never deleted", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		cfg := f.blob("live config", 24*time.Hour)
		l1 := f.blob("live layer 1", 24*time.Hour)
		l2 := f.blob("live layer 2", 24*time.Hour)
		orphan := f.blob("nobody's blob", 24*time.Hour)
		f.pod("pod-live", ImageRoot{Reference: "example.test/app:v1", Config: cfg, Layers: []string{l1, l2}})

		rep, err := f.cache.ReclaimUnderPressure(context.Background(), press(f))
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		for _, d := range []string{cfg, l1, l2} {
			if !f.exists(d) {
				t.Errorf("live pod blob %s was DELETED", d)
			}
		}
		if f.exists(orphan) {
			t.Errorf("the unreferenced blob survived, so this case proved nothing")
		}
		for _, k := range rep.Kept {
			if k.Digest == cfg && k.Reason != ReasonKeptInUse {
				t.Errorf("live blob kept for reason %q; want %q", k.Reason, ReasonKeptInUse)
			}
		}
	})

	t.Run("a base layer shared with an unreferenced image survives", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		shared := f.blob("shared base layer", 24*time.Hour)
		liveCfg := f.blob("live config", 24*time.Hour)
		deadCfg := f.blob("dead config", 24*time.Hour)
		f.pod("pod-live", ImageRoot{Reference: "app:v2", Config: liveCfg, Layers: []string{shared}})

		if _, err := f.cache.ReclaimUnderPressure(context.Background(), press(f)); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(shared) {
			t.Errorf("a base layer shared with a live pod's image was deleted")
		}
		if f.exists(deadCfg) {
			t.Errorf("the unreferenced image's config survived, so this case proved nothing")
		}
	})

	t.Run("a hostile record cannot unroot another pod's blobs", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		victim := f.blob("victim layer", 24*time.Hour)
		f.pod("pod-victim", ImageRoot{Reference: "victim:v1", Config: victim})
		// A second pod records an empty root set. Reachability is a union, so no
		// record can ever subtract from another's — there is no negative fact to
		// author. If it could, this is the shape that would exploit it.
		f.pod("pod-attacker")

		if _, err := f.cache.ReclaimUnderPressure(context.Background(), press(f)); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(victim) {
			t.Errorf("another pod's record unrooted the victim pod's blob")
		}
	})

	t.Run("a blob whose pod dir has no record aborts the whole prune", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		orphan := f.blob("orphan", 24*time.Hour)
		pid := f.pod("pod-live", ImageRoot{Reference: "app:v1", Config: f.blob("cfg", 24*time.Hour)})
		// Simulate a pod dir whose record is gone — the state in which every blob
		// that pod uses looks unreferenced. The prune must refuse ENTIRELY.
		if err := os.Remove(filepath.Join(f.cache.PodDir(pid), PodReferencesName)); err != nil {
			t.Fatalf("remove record: %v", err)
		}

		_, err := f.cache.ReclaimUnderPressure(context.Background(), press(f))
		if !errors.Is(err, ErrRootsIncomplete) {
			t.Fatalf("err = %v; want ErrRootsIncomplete", err)
		}
		if !f.exists(orphan) {
			t.Errorf("a blob was deleted from an incomplete root set")
		}
	})

	t.Run("an in-flight pull's blobs are pinned by its lease", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		// The exact race: the blob is committed (or found already present) but the
		// pod that will reference it has not recorded it yet. It is old, so grace
		// saves nothing. Only the lease stands between it and the unlink.
		inflight := f.blob("in-flight layer", 24*time.Hour)
		f.pod("pod-a")
		lease := f.cache.AcquireLease([]string{inflight}, time.Hour)

		rep, err := f.cache.ReclaimUnderPressure(context.Background(), press(f))
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(inflight) {
			t.Fatalf("a leased in-flight blob was deleted")
		}
		var reason PruneReason
		for _, k := range rep.Kept {
			if k.Digest == inflight {
				reason = k.Reason
			}
		}
		if reason != ReasonKeptLeased {
			t.Errorf("leased blob kept for reason %q; want %q", reason, ReasonKeptLeased)
		}

		// Once the lease is released and no record names it, the same blob IS
		// collectable — otherwise the pin above would prove nothing.
		lease.Release()
		if _, err := f.cache.ReclaimUnderPressure(context.Background(), press(f)); err != nil {
			t.Fatalf("second ReclaimUnderPressure: %v", err)
		}
		if f.exists(inflight) {
			t.Errorf("the blob survived after its lease was released, so the pin proved nothing")
		}
	})

	t.Run("an expired lease does not pin the store forever", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		abandoned := f.blob("abandoned in-flight layer", 24*time.Hour)
		f.pod("pod-a")
		f.cache.AcquireLease([]string{abandoned}, time.Minute) // never released
		f.clock = f.clock.Add(time.Hour)

		if _, err := f.cache.ReclaimUnderPressure(context.Background(), press(f)); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if f.exists(abandoned) {
			t.Errorf("an EXPIRED lease still pinned a blob; a forgotten lease must not disable the GC forever")
		}
	})

	t.Run("a symlink planted at a blob path is never followed or deleted", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		f.pod("pod-a")
		target := filepath.Join(t.TempDir(), "precious")
		if err := os.WriteFile(target, []byte("do not delete me"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		dir := filepath.Join(f.cache.Root(), "blobs", "sha256")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		link := filepath.Join(dir, strings.Repeat("a", 64))
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		if _, err := f.cache.ReclaimUnderPressure(context.Background(), press(f)); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Errorf("a non-regular node in the blobs tree was deleted: %v", err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Errorf("the symlink's TARGET was deleted — the executor followed the link: %v", err)
		}
	})

	t.Run("a record arriving during the pass is not deleted out from under the pod", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		// The pass reads the inventory FIRST and the roots second, so a reference
		// recorded while it runs is still honored. The reverse order is a real hole,
		// not a theoretical one: it plans a deletion for a blob whose root arrived
		// a microsecond after the root read. afterInventory drives exactly that
		// interleaving — swap the two reads in ReclaimUnderPressure and this fails.
		late := f.blob("late-rooted layer", 24*time.Hour)
		pid := f.pod("pod-late")
		cfg := press(f)
		cfg.afterInventory = func() {
			if err := f.cache.RecordPodImage(pid, ImageRoot{Reference: "late:v1", Config: late}); err != nil {
				t.Errorf("RecordPodImage: %v", err)
			}
		}
		if _, err := f.cache.ReclaimUnderPressure(context.Background(), cfg); err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(late) {
			t.Errorf("a blob rooted during the pass was deleted")
		}
	})
}
