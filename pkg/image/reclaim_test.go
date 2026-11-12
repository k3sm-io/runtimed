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
	"slices"
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

	t.Run("a record-less pod dir is skipped only when the daemon clears it", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			untracked UntrackedPodFunc
			malformed bool
			wantErr   bool
		}{
			{"no predicate stays fatal", nil, false, true},
			{"a tracked pod stays fatal", func(PodID) bool { return false }, false, true},
			{"an untracked pod is skipped", func(PodID) bool { return true }, false, false},
			{"a malformed record stays fatal even untracked", func(PodID) bool { return true }, true, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newGCFixture(t)
				orphan := f.blob("orphan", 24*time.Hour)
				pid := f.pod("pod-gone")
				rec := filepath.Join(f.cache.PodDir(pid), PodReferencesName)
				var err error
				if tc.malformed {
					err = os.WriteFile(rec, []byte("{"), 0o644)
				} else {
					err = os.Remove(rec)
				}
				if err != nil {
					t.Fatalf("prepare record: %v", err)
				}
				cfg := press(f)
				cfg.UntrackedPod = tc.untracked
				_, err = f.cache.ReclaimUnderPressure(context.Background(), cfg)
				if tc.wantErr {
					if !errors.Is(err, ErrRootsIncomplete) {
						t.Fatalf("err = %v; want ErrRootsIncomplete", err)
					}
					if !f.exists(orphan) {
						t.Errorf("a blob was deleted from an incomplete root set")
					}
					return
				}
				if err != nil {
					t.Fatalf("reclaim: %v", err)
				}
				if f.exists(orphan) {
					t.Errorf("the unreferenced blob survived a prune past an untracked pod dir")
				}
			})
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

// TestReclaimKeepsBlobHeldBetweenPlanAndUnlink drives an artifact cache hit
// into the window between the pass's root and lease reads and its first
// unlink. The plan condemns the blob before the pull touches it, so only the
// executor's re-check before the unlink can keep it, and each subtest proves
// one of its two protections on its own:
//
//   - the roots re-read: the pull leases the blob, rewrites its record, writes
//     the pod's hold and releases the lease, all before the executor runs, so
//     only the root it wrote can keep the blob (ReasonKeptInUse);
//   - the lease re-read: the pull leases the blob and still holds the lease
//     when the executor reaches it, with no root naming the blob, so only the
//     live lease can keep it (ReasonKeptLeased). Released, a second pass
//     removes it, so the pin is not vacuous. The executor reads leases twice
//     (once per batch in pinnedNow, once per unlink via leaseHas), and this
//     case fails only when both reads are gone.
//
// An unreferenced blob next to it is removed, so neither pass is vacuous.
func TestReclaimKeepsBlobHeldBetweenPlanAndUnlink(t *testing.T) {
	t.Parallel()

	t.Run("a root written between plan and unlink keeps the blob after its lease is released", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		held := f.blob("artifact layer hit from cache", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		pid := f.pod("pod-artifact")
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		sum := sha256.Sum256([]byte("held artifact manifest"))
		manifest := "sha256:" + hex.EncodeToString(sum[:])
		key := "registry.example/models/m:v1@" + testModelType

		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			lease := f.cache.AcquireLease([]string{held}, time.Minute)
			defer lease.Release()
			if !f.cache.Has(held) {
				t.Errorf("the cache hit found its blob absent before the unlink")
			}
			putTypedArtifact(t, x, key, testModelType, held, held)
			if err := x.AddArtifactHoldManifest(context.Background(), pid, HeldManifest{
				Digest: manifest, Config: held, Layers: []string{held},
			}); err != nil {
				t.Errorf("AddArtifactHoldManifest: %v", err)
			}
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !f.exists(held) {
			t.Errorf("a blob a hold and a record named before the unlink was deleted")
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
		if reason := keptReason(rep, held); reason != ReasonKeptInUse {
			t.Errorf("held blob kept for reason %q; want %q", reason, ReasonKeptInUse)
		}
	})

	t.Run("a lease taken between plan and unlink and still held keeps the blob with no root", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		held := f.blob("artifact layer leased mid-pass", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		f.pod("pod-artifact")

		var lease *Lease
		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			// The plan's lease read is already done and saw no lease; no record
			// or hold names the blob. The lease outlives the whole pass.
			lease = f.cache.AcquireLease([]string{held}, time.Hour)
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if lease == nil {
			t.Fatalf("afterRoots never ran, so the window was not driven")
		}
		if !f.exists(held) {
			t.Errorf("a blob leased between plan and unlink was deleted while the lease was held")
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
		if reason := keptReason(rep, held); reason != ReasonKeptLeased {
			t.Errorf("leased blob kept for reason %q; want %q", reason, ReasonKeptLeased)
		}

		// Released, with no root naming it, the same blob IS collectable, so the
		// lease above is what kept it.
		lease.Release()
		if _, err := f.cache.ReclaimUnderPressure(context.Background(), midPassReclaimConfig()); err != nil {
			t.Fatalf("second ReclaimUnderPressure: %v", err)
		}
		if f.exists(held) {
			t.Errorf("the blob survived after its lease was released, so the pin proved nothing")
		}
	})
}

// TestReclaimHeldBlobEdges drives two edges of the same plan-to-unlink window
// TestReclaimKeepsBlobHeldBetweenPlanAndUnlink covers:
//
//   - a blob shared by two pods' artifact holds, one of which is released
//     inside the window, whose artifact record still stands: it is kept
//     (ReasonKeptInUse) while an unreferenced blob in the same pass goes. The
//     record alone roots it (artifactRoots: a record is a root while it
//     exists), as the control with BOTH holds released shows, so this edge
//     does not isolate pod-b's remaining hold;
//   - a hold, record and lease all taken AND released inside the window, with
//     no root left behind: the blob is reclaimed in that same pass, so the
//     executor's re-check does not over-retain.
func TestReclaimHeldBlobEdges(t *testing.T) {
	t.Parallel()

	manifestDigest := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	t.Run("a shared blob stays while its record stands and one of its two holds is released", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		shared := f.blob("layer shared by two artifacts", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		podA := f.pod("pod-a")
		podB := f.pod("pod-b")
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		key := "registry.example/models/shared:v1@" + testModelType

		ran := false
		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			ran = true
			lease := f.cache.AcquireLease([]string{shared}, time.Minute)
			defer lease.Release()
			putTypedArtifact(t, x, key, testModelType, shared, shared)
			for _, h := range []struct {
				pod  PodID
				name string
			}{{podA, "manifest a"}, {podB, "manifest b"}} {
				if err := x.AddArtifactHoldManifest(context.Background(), h.pod, HeldManifest{
					Digest: manifestDigest(h.name), Config: shared, Layers: []string{shared},
				}); err != nil {
					t.Errorf("AddArtifactHoldManifest(%s): %v", h.pod, err)
				}
			}
			// One holder goes away before the executor runs; the other stays.
			if err := x.RemoveArtifactHold(podA); err != nil {
				t.Errorf("RemoveArtifactHold: %v", err)
			}
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !ran {
			t.Fatalf("afterRoots never ran, so the window was not driven")
		}
		if !f.exists(shared) {
			t.Errorf("a blob one live hold still names was deleted when the other hold was released")
		}
		if reason := keptReason(rep, shared); reason != ReasonKeptInUse {
			t.Errorf("shared blob kept for reason %q; want %q", reason, ReasonKeptInUse)
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
	})

	t.Run("a recorded blob stays when both of its holds are released", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		shared := f.blob("layer whose two holds both go", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		podA := f.pod("pod-a")
		podB := f.pod("pod-b")
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		key := "registry.example/models/shared:v1@" + testModelType

		ran := false
		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			ran = true
			lease := f.cache.AcquireLease([]string{shared}, time.Minute)
			defer lease.Release()
			putTypedArtifact(t, x, key, testModelType, shared, shared)
			for _, h := range []struct {
				pod  PodID
				name string
			}{{podA, "manifest a"}, {podB, "manifest b"}} {
				if err := x.AddArtifactHoldManifest(context.Background(), h.pod, HeldManifest{
					Digest: manifestDigest(h.name), Config: shared, Layers: []string{shared},
				}); err != nil {
					t.Errorf("AddArtifactHoldManifest(%s): %v", h.pod, err)
				}
			}
			// Both holders go away before the executor runs; the record stays.
			for _, pid := range []PodID{podA, podB} {
				if err := x.RemoveArtifactHold(pid); err != nil {
					t.Errorf("RemoveArtifactHold(%s): %v", pid, err)
				}
			}
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !ran {
			t.Fatalf("afterRoots never ran, so the window was not driven")
		}
		// The artifact record is a root on its own, so with no hold left the
		// blob is still kept: in the subtest above it is the record, not
		// pod-b's remaining hold, that keeps the shared blob.
		if !f.exists(shared) {
			t.Errorf("a blob its artifact record still names was deleted once both holds were released")
		}
		if reason := keptReason(rep, shared); reason != ReasonKeptInUse {
			t.Errorf("recorded blob kept for reason %q; want %q", reason, ReasonKeptInUse)
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
	})

	t.Run("a blob stays on one pod's hold after its record is removed", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		shared := f.blob("layer held by pod-b alone", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		podA := f.pod("pod-a")
		podB := f.pod("pod-b")
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		key := "registry.example/models/shared:v1@" + testModelType

		ran := false
		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			ran = true
			lease := f.cache.AcquireLease([]string{shared}, time.Minute)
			putTypedArtifact(t, x, key, testModelType, shared, shared)
			for _, h := range []struct {
				pod  PodID
				name string
			}{{podA, "manifest a"}, {podB, "manifest b"}} {
				if err := x.AddArtifactHoldManifest(context.Background(), h.pod, HeldManifest{
					Digest: manifestDigest(h.name), Config: shared, Layers: []string{shared},
				}); err != nil {
					t.Errorf("AddArtifactHoldManifest(%s): %v", h.pod, err)
				}
			}
			// pod-a's hold and the record both go before the executor runs, and
			// the lease is released: pod-b's hold is the only root left.
			if err := x.RemoveArtifactHold(podA); err != nil {
				t.Errorf("RemoveArtifactHold: %v", err)
			}
			if _, err := x.RemoveArtifactRecord(context.Background(), key); err != nil {
				t.Errorf("RemoveArtifactRecord: %v", err)
			}
			lease.Release()
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !ran {
			t.Fatalf("afterRoots never ran, so the window was not driven")
		}
		// With no record and no lease, only pod-b's hold (artifactHoldRoots)
		// can keep the blob, so this isolates the hold as a root.
		if !f.exists(shared) {
			t.Errorf("a blob pod-b's live hold still names was deleted once its record was removed")
		}
		if reason := keptReason(rep, shared); reason != ReasonKeptInUse {
			t.Errorf("held blob kept for reason %q; want %q", reason, ReasonKeptInUse)
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
	})

	t.Run("a hold taken and released inside the window leaves the blob collectable", func(t *testing.T) {
		t.Parallel()
		f := newGCFixture(t)
		transient := f.blob("layer held only inside the window", 24*time.Hour)
		stray := f.blob("unreferenced layer", 24*time.Hour)
		pid := f.pod("pod-transient")
		x, err := NewFileIndex(f.cache)
		if err != nil {
			t.Fatalf("NewFileIndex: %v", err)
		}
		key := "registry.example/models/transient:v1@" + testModelType

		ran := false
		cfg := midPassReclaimConfig()
		cfg.afterRoots = func() {
			ran = true
			lease := f.cache.AcquireLease([]string{transient}, time.Minute)
			putTypedArtifact(t, x, key, testModelType, transient, transient)
			if err := x.AddArtifactHoldManifest(context.Background(), pid, HeldManifest{
				Digest: manifestDigest("transient manifest"), Config: transient, Layers: []string{transient},
			}); err != nil {
				t.Errorf("AddArtifactHoldManifest: %v", err)
			}
			// Everything the pull wrote is undone before the executor runs.
			if err := x.RemoveArtifactHold(pid); err != nil {
				t.Errorf("RemoveArtifactHold: %v", err)
			}
			if _, err := x.RemoveArtifactRecord(context.Background(), key); err != nil {
				t.Errorf("RemoveArtifactRecord: %v", err)
			}
			lease.Release()
		}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), cfg)
		if err != nil {
			t.Fatalf("ReclaimUnderPressure: %v", err)
		}
		if !ran {
			t.Fatalf("afterRoots never ran, so the window was not driven")
		}
		if f.exists(transient) {
			t.Errorf("a blob with no hold, record or lease left was kept (reason %q): over-retention",
				keptReason(rep, transient))
		}
		if f.exists(stray) {
			t.Errorf("the unreferenced blob survived, so the pass proved nothing")
		}
	})
}

// midPassReclaimConfig is a pass under permanent pressure with no grace, so
// every blob nothing protects is condemned.
func midPassReclaimConfig() ReclaimConfig {
	return ReclaimConfig{
		HighFreeBytes: 1 << 40, TargetFreeBytes: 1 << 40, Grace: 0,
		FreeBytes: (&fakeFree{free: []uint64{0}}).sample,
	}
}

// keptReason returns the reason rep kept digest for, or "" if it did not.
func keptReason(rep *ReclaimReport, digest string) PruneReason {
	for _, k := range rep.Kept {
		if k.Digest == digest {
			return k.Reason
		}
	}
	return ""
}

// TestReclaimKeepsBlobRootedMidBatch drives a complete artifact cache hit
// (lease, record, hold, release) into one batch after its pin read and before
// the executor reaches the pulled blob, which is queued later in that batch.
// The stale pin set does not name it and its lease is gone by the time the
// executor examines it, so only a re-read of the pins triggered by the lease
// watch can see the record and hold that root it. The unrooted blob
// examined first is still unlinked, so the batch is not vacuous.
func TestReclaimKeepsBlobRootedMidBatch(t *testing.T) {
	f := newGCFixture(t)
	stray := f.blob("unreferenced layer examined first", 24*time.Hour)
	held := f.blob("artifact layer pulled mid-batch", 24*time.Hour)
	pid := f.pod("pod-artifact")
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatalf("NewFileIndex: %v", err)
	}
	sum := sha256.Sum256([]byte("mid-batch artifact manifest"))
	manifest := "sha256:" + hex.EncodeToString(sum[:])
	key := "registry.example/models/m:mid@" + testModelType

	pulled := false
	f.cache.beforePruneBlob = func(digest string) {
		if pulled || digest != stray {
			return
		}
		pulled = true
		lease := f.cache.AcquireLease([]string{held}, time.Minute)
		if !f.cache.Has(held) {
			t.Errorf("the cache hit found its blob absent before the executor reached it")
		}
		putTypedArtifact(t, x, key, testModelType, held, held)
		if err := x.AddArtifactHoldManifest(context.Background(), pid, HeldManifest{
			Digest: manifest, Config: held, Layers: []string{held},
		}); err != nil {
			t.Errorf("AddArtifactHoldManifest: %v", err)
		}
		lease.Release()
	}
	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	rep, err := f.cache.executePrune(planOf(stray, held), 0, f.clock, nil, pinned, f.cache.leaseHasLocked)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !pulled {
		t.Fatal("the hook never ran, so the window was not driven")
	}
	if !f.exists(held) {
		t.Errorf("a blob a record and a hold rooted mid-batch was deleted")
	}
	if f.exists(stray) {
		t.Errorf("the unrooted blob survived, so the batch proved nothing")
	}
	var reason PruneReason
	for _, k := range rep.pinned {
		if k.Digest == held {
			reason = k.Reason
		}
	}
	if reason != ReasonKeptInUse {
		t.Errorf("held blob kept for reason %q; want %q", reason, ReasonKeptInUse)
	}
}

// TestReclaimSkipsRepinForUnrelatedLease pins the per-digest watch: a lease
// taken mid-batch forces a fresh pin read only before a blob it names, so a
// stream of pulls of blobs outside the plan costs no extra roots reads.
func TestReclaimSkipsRepinForUnrelatedLease(t *testing.T) {
	cases := []struct {
		name      string
		leaseLate bool // lease the later planned blob instead of an unplanned one
		wantReads int
	}{
		{name: "lease names a digest outside the plan", leaseLate: false, wantReads: 1},
		{name: "lease names a later planned blob", leaseLate: true, wantReads: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCFixture(t)
			first := f.blob("first planned blob", 24*time.Hour)
			second := f.blob("second planned blob", 24*time.Hour)
			sum := sha256.Sum256([]byte("blob not in the plan"))
			outside := "sha256:" + hex.EncodeToString(sum[:])

			fired := false
			f.cache.beforePruneBlob = func(digest string) {
				if fired || digest != first {
					return
				}
				fired = true
				target := outside
				if tc.leaseLate {
					target = second
				}
				f.cache.AcquireLease([]string{target}, time.Minute).Release()
			}
			reads := 0
			pinned := func() (map[string]PruneReason, error) {
				reads++
				return f.cache.pinnedNow(nil)
			}
			if _, err := f.cache.executePrune(planOf(first, second), 0, f.clock, nil, pinned, f.cache.leaseHasLocked); err != nil {
				t.Fatalf("executePrune: %v", err)
			}
			if !fired {
				t.Fatal("the hook never ran, so the window was not driven")
			}
			if reads != tc.wantReads {
				t.Errorf("pin reads = %d; want %d", reads, tc.wantReads)
			}
			for _, d := range []string{first, second} {
				if f.exists(d) {
					t.Errorf("unrooted planned blob %s survived", d)
				}
			}
		})
	}
}

// TestExecutePruneOrdersALeaseAgainstTheUnlink races an AcquireLease against
// one planned blob's unlink, from the point after every re-check passed and
// just before the Remove. A pull that leases the blob and then finds it
// present must keep it: either its lease lands before the executor's lease
// check (kept as leased), or it lands after the Remove and the pull finds the
// blob absent and refetches. The failure is the third ordering — the lease
// lands, the pull sees the blob, and the unlink still happens.
//
// The hook runs while the executor may hold leaseMu, so it cannot simply call
// AcquireLease: TryLock only decides whether it may lease in line (nothing
// orders the lease against the unlink) or must lease from a goroutine that
// AcquireLease blocks until the executor lets go. The assertion is about the
// blob, not the lock.
func TestExecutePruneOrdersALeaseAgainstTheUnlink(t *testing.T) {
	f := newGCFixture(t)
	b := f.blob("planned blob a pull leases at its unlink", 24*time.Hour)

	type sighting struct {
		lease   *Lease
		present bool
	}
	seen := make(chan sighting, 1)
	pull := func() {
		l := f.cache.AcquireLease([]string{b}, time.Hour)
		seen <- sighting{lease: l, present: f.cache.Has(b)}
	}
	fired := false
	f.cache.beforePruneUnlink = func(digest string) {
		if fired || digest != b {
			return
		}
		fired = true
		if f.cache.leaseMu.TryLock() {
			f.cache.leaseMu.Unlock()
			pull()
			return
		}
		go pull()
	}
	pinned := func() (map[string]PruneReason, error) { return f.cache.pinnedNow(nil) }
	rep, err := f.cache.executePrune(planOf(b), 0, f.clock, nil, pinned, f.cache.leaseHasLocked)
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !fired {
		t.Fatal("the hook never ran, so the window was not driven")
	}
	var s sighting
	select {
	case s = <-seen:
	case <-time.After(10 * time.Second):
		t.Fatal("the pull's AcquireLease never returned after the pass")
	}
	defer s.lease.Release()
	if s.present && !f.exists(b) {
		t.Fatal("a pull leased the blob and found it present, and the executor still unlinked it")
	}
	if !s.present && !slices.Contains(rep.Removed, b) {
		t.Errorf("the pull found the blob absent but the pass did not report removing it: %v", rep.Removed)
	}
}
