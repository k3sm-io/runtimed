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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExecutePruneHooks drives executePrune directly with each pruneHooks seam
// on a fixture cache: a nil hooks pointer behaves as ExecutePrune, a guard drop
// keeps its blob with the reason in the report, a guard error unlinks nothing,
// an unlink hook that refuses a blob keeps it with the reason, a blob the
// executor's own re-verification (run by remove) refuses is kept, a hook error
// is a skip, and a removed report the root handle contradicts is a failed
// removal.
func TestExecutePruneHooks(t *testing.T) {
	t.Parallel()

	errGuard := errors.New("guard failed")
	errHook := errors.New("hook failed")

	tests := []struct {
		name string
		// hooks builds the hooks for the run; keep is the digest a hook
		// targets (empty when none does).
		hooks func(f *gcFixture, keep string) *pruneHooks
		// prep, when non-nil, runs after planning and before executing.
		prep       func(t *testing.T, f *gcFixture, keep string)
		targetKeep bool
		wantErr    error
		wantReason string
	}{
		{
			name:  "nil hooks behaves as ExecutePrune",
			hooks: func(*gcFixture, string) *pruneHooks { return nil },
		},
		{
			name:  "nil guard with a pass-through unlink removes every blob",
			hooks: func(*gcFixture, string) *pruneHooks { return &pruneHooks{} },
		},
		{
			name: "nil drop map is a no-op",
			hooks: func(*gcFixture, string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) { return nil, nil }}
			},
		},
		{
			name: "guard drop keeps that blob and unlinks the rest",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) {
					return map[string]evictReason{keep: evictInUse}, nil
				}}
			},
			targetKeep: true,
			wantReason: "dropped by guard: " + string(evictInUse),
		},
		{
			name: "guard error unlinks nothing",
			hooks: func(*gcFixture, string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) { return nil, errGuard }}
			},
			wantErr: errGuard,
		},
		{
			name: "unlink hook refusal keeps that blob with its reason",
			hooks: func(f *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					if digest == keep {
						return false, evictLeased, nil
					}
					return true, "", remove()
				}}
			},
			targetKeep: true,
			wantReason: string(evictLeased),
		},
		{
			// Re-verification runs inside remove, under the hook's lock: a
			// hook that calls remove for a young blob removes nothing, and
			// the young refusal wins over the hook's own report.
			name: "blob refused by re-verification inside remove is kept",
			hooks: func(*gcFixture, string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					return true, "", remove()
				}}
			},
			prep: func(t *testing.T, f *gcFixture, keep string) {
				p, err := f.cache.BlobPath(keep)
				if err != nil {
					t.Fatalf("BlobPath: %v", err)
				}
				if err := os.Chtimes(p, f.clock, f.clock); err != nil {
					t.Fatalf("Chtimes: %v", err)
				}
			},
			targetKeep: true,
			wantReason: "younger than grace",
		},
		{
			name: "hook error is a skip and counts nothing deleted",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					if digest == keep {
						return false, "", errHook
					}
					return true, "", remove()
				}}
			},
			targetKeep: true,
			wantReason: "remove: " + errHook.Error(),
		},
		{
			name: "removed report without calling remove is a failed removal",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					if digest == keep {
						return true, "", nil
					}
					return true, "", remove()
				}}
			},
			targetKeep: true,
			wantReason: "still present",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			a := f.blob("hooks-a", time.Hour)
			b := f.blob("hooks-b", time.Hour)
			c := f.blob("hooks-c", time.Hour)
			nodes, err := f.cache.EnumerateBlobs()
			if err != nil {
				t.Fatalf("EnumerateBlobs: %v", err)
			}
			plan, err := PlanPrune(nodes, nil, nil, nil, time.Minute, f.clock)
			if err != nil {
				t.Fatalf("PlanPrune: %v", err)
			}
			if len(plan.Delete) != 3 {
				t.Fatalf("plan.Delete = %d; want 3", len(plan.Delete))
			}

			if tc.prep != nil {
				tc.prep(t, f, b)
			}
			rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, hookedMode(tc.hooks(f, b)))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("executePrune err = %v; want %v", err, tc.wantErr)
				}
				for _, d := range []string{a, b, c} {
					if !f.exists(d) {
						t.Errorf("%s unlinked despite guard error", d)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("executePrune: %v", err)
			}

			wantDeleted := 3
			if tc.targetKeep {
				wantDeleted = 2
			}
			if rep.Deleted != wantDeleted {
				t.Errorf("Deleted = %d; want %d (skipped %v)", rep.Deleted, wantDeleted, rep.Skipped)
			}
			for _, d := range []string{a, b, c} {
				kept := tc.targetKeep && d == b
				if got := f.exists(d); got != kept {
					t.Errorf("exists(%s) = %v; want %v", d, got, kept)
				}
			}
			if !tc.targetKeep {
				if len(rep.Skipped) != 0 {
					t.Errorf("Skipped = %v; want none", rep.Skipped)
				}
				return
			}
			if len(rep.Skipped) != 1 || rep.Skipped[0].Digest != b {
				t.Fatalf("Skipped = %v; want exactly %s", rep.Skipped, b)
			}
			if !strings.Contains(rep.Skipped[0].Reason, tc.wantReason) {
				t.Errorf("Skipped reason = %q; want it to contain %q", rep.Skipped[0].Reason, tc.wantReason)
			}
		})
	}
}

// TestExecutePruneTypedRefusal pins the typed refusal beside each skip's
// string: a guard drop, an unlink-seam refusal, a blob younger than grace and
// a failed removal each fill Refusal with the blob's digest, the path's kind
// and the exported reason, while the string stays byte-for-byte what prune's
// callers read. A skip on any other path (here, a blob already gone) carries
// no Refusal.
func TestExecutePruneTypedRefusal(t *testing.T) {
	t.Parallel()

	errHook := errors.New("hook failed")
	refuse := func(why evictReason, err error) func(*gcFixture, string) *pruneHooks {
		return func(_ *gcFixture, keep string) *pruneHooks {
			return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
				if digest == keep {
					return false, why, err
				}
				return true, "", remove()
			}}
		}
	}
	tests := []struct {
		name       string
		hooks      func(f *gcFixture, keep string) *pruneHooks
		prep       func(t *testing.T, f *gcFixture, keep string)
		edit       func(plan *PrunePlan, keep string)
		wantString string
		want       *SkipRefusal // Digest is filled in by the loop
	}{
		{
			name: "guard drop",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) {
					return map[string]evictReason{keep: evictShared}, nil
				}}
			},
			wantString: "dropped by guard: shared",
			want:       &SkipRefusal{Kind: RefusedByGuard, Reason: EvictKeptShared},
		},
		{
			name: "guard drop with an unknown reason is unlink-failed",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) {
					return map[string]evictReason{keep: "bogus"}, nil
				}}
			},
			wantString: "dropped by guard: bogus",
			want:       &SkipRefusal{Kind: RefusedByGuard, Reason: EvictKeptUnlinkFailed},
		},
		{
			// A guard entry keyed by the empty digest drops nothing: the other
			// blob, planned with no digest, is still removed.
			name: "guard entry for the empty digest drops nothing",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{guard: func() (map[string]evictReason, error) {
					return map[string]evictReason{"": evictShared, keep: evictShared}, nil
				}}
			},
			edit: func(plan *PrunePlan, keep string) {
				for i := range plan.Delete {
					if plan.Delete[i].Node.Digest != keep {
						plan.Delete[i].Node.Digest = ""
					}
				}
			},
			wantString: "dropped by guard: shared",
			want:       &SkipRefusal{Kind: RefusedByGuard, Reason: EvictKeptShared},
		},
		{
			name:       "unlink seam refusal",
			hooks:      refuse(evictLeased, nil),
			wantString: "refused by unlink: leased",
			want:       &SkipRefusal{Kind: RefusedByUnlink, Reason: EvictKeptLeased},
		},
		{
			name:       "unlink seam refusal with no reason is unlink-failed",
			hooks:      refuse("", nil),
			wantString: "refused by unlink: ",
			want:       &SkipRefusal{Kind: RefusedByUnlink, Reason: EvictKeptUnlinkFailed},
		},
		{
			name:  "younger than grace",
			hooks: func(*gcFixture, string) *pruneHooks { return nil },
			prep: func(t *testing.T, f *gcFixture, keep string) {
				p, err := f.cache.BlobPath(keep)
				if err != nil {
					t.Fatalf("BlobPath: %v", err)
				}
				if err := os.Chtimes(p, f.clock, f.clock); err != nil {
					t.Fatalf("Chtimes: %v", err)
				}
			},
			wantString: "younger than grace",
			want:       &SkipRefusal{Kind: RefusedYoung, Reason: EvictKeptYoung},
		},
		{
			name:       "removal error",
			hooks:      refuse("", errHook),
			wantString: "remove: " + errHook.Error(),
			want:       &SkipRefusal{Kind: RefusedRemoveFailed, Reason: EvictKeptUnlinkFailed},
		},
		{
			name: "removed report the root contradicts",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					if digest == keep {
						return true, "", nil
					}
					return true, "", remove()
				}}
			},
			wantString: "remove: unlink reported removed but blob is still present",
			want:       &SkipRefusal{Kind: RefusedRemoveFailed, Reason: EvictKeptUnlinkFailed},
		},
		{
			name:  "already absent carries no refusal",
			hooks: func(*gcFixture, string) *pruneHooks { return nil },
			prep: func(t *testing.T, f *gcFixture, keep string) {
				p, err := f.cache.BlobPath(keep)
				if err != nil {
					t.Fatalf("BlobPath: %v", err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatalf("Remove: %v", err)
				}
			},
			wantString: "already absent",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			a := f.blob("typed-a", time.Hour)
			b := f.blob("typed-b", time.Hour)
			nodes, err := f.cache.EnumerateBlobs()
			if err != nil {
				t.Fatalf("EnumerateBlobs: %v", err)
			}
			plan, err := PlanPrune(nodes, nil, nil, nil, time.Minute, f.clock)
			if err != nil {
				t.Fatalf("PlanPrune: %v", err)
			}
			if tc.prep != nil {
				tc.prep(t, f, b)
			}
			if tc.edit != nil {
				tc.edit(plan, b)
			}
			rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, hookedMode(tc.hooks(f, b)))
			if err != nil {
				t.Fatalf("executePrune: %v", err)
			}
			if len(rep.Skipped) != 1 || rep.Skipped[0].Digest != b {
				t.Fatalf("Skipped = %+v; want exactly %s", rep.Skipped, b)
			}
			s := rep.Skipped[0]
			if s.Reason != tc.wantString {
				t.Errorf("Reason = %q; want %q byte-for-byte", s.Reason, tc.wantString)
			}
			if blobOnDisk(t, f, a) {
				t.Errorf("unrefused blob %s is still on disk", a)
			}
			if tc.want != nil && !blobOnDisk(t, f, b) {
				t.Errorf("refused blob %s was removed anyway", b)
			}
			if tc.want == nil {
				if s.Refusal != nil {
					t.Errorf("Refusal = %+v; want nil", s.Refusal)
				}
				return
			}
			want := *tc.want
			want.Digest = b
			if s.Refusal == nil || *s.Refusal != want {
				t.Errorf("Refusal = %+v; want %+v", s.Refusal, want)
			}
		})
	}
}

// blobOnDisk reports whether digest's blob file is present, by Lstat of its
// path so a symlink left in its place still counts as present.
func blobOnDisk(t *testing.T, f *gcFixture, digest string) bool {
	t.Helper()
	p, err := f.cache.BlobPath(digest)
	if err != nil {
		t.Fatalf("BlobPath: %v", err)
	}
	_, err = os.Lstat(p)
	if err == nil {
		return true
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Lstat %s: %v", p, err)
	}
	return false
}

// hookedMode is the mode a table case's hooks select: eviction when the case
// supplies hooks, ExecutePrune's plain mode when it supplies none.
func hookedMode(h *pruneHooks) pruneMode {
	if h == nil {
		return plainPrune()
	}
	if h.unlink == nil {
		// Eviction requires an unlink hook; a case that exercises only the
		// guard gets an explicit pass-through, equivalent to the old bare Remove.
		c := *h
		c.unlink = func(_ string, remove func() error) (bool, evictReason, error) {
			err := remove()
			return err == nil, "", err
		}
		h = &c
	}
	return evictPrune(h)
}

// TestUnlinkUnlessLeasedTypedRefusal pins the typed refusals on the plain and
// pressure bodies (unlinkUnlessLeased): a blob younger than grace and a failed
// Remove carry the same Refusal the eviction body reports, beside their
// unchanged reason strings.
func TestUnlinkUnlessLeasedTypedRefusal(t *testing.T) {
	t.Parallel()

	modes := map[string]func() pruneMode{
		"plain": plainPrune,
		"pressure": func() pruneMode {
			return pressurePrune(func() (map[string]PruneReason, error) { return nil, nil })
		},
	}
	cases := []struct {
		name       string
		prep       func(t *testing.T, path string, now time.Time)
		wantPrefix string
		want       SkipRefusal
	}{
		{
			name: "younger than grace",
			prep: func(t *testing.T, path string, now time.Time) {
				if err := os.Chtimes(path, now, now); err != nil {
					t.Fatalf("Chtimes: %v", err)
				}
			},
			wantPrefix: "younger than grace",
			want:       SkipRefusal{Kind: RefusedYoung, Reason: EvictKeptYoung},
		},
		{
			name: "remove fails",
			prep: func(t *testing.T, path string, _ time.Time) {
				dir := filepath.Dir(path)
				if err := os.Chmod(dir, 0o500); err != nil {
					t.Fatalf("Chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			},
			wantPrefix: "remove: ",
			want:       SkipRefusal{Kind: RefusedRemoveFailed, Reason: EvictKeptUnlinkFailed},
		},
	}
	for modeName, mode := range modes {
		for _, tc := range cases {
			t.Run(modeName+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				if tc.name == "remove fails" && os.Geteuid() == 0 {
					t.Skip("root ignores directory permissions")
				}
				f := newGCFixture(t)
				b := f.blob("pressure-typed", time.Hour)
				p, err := f.cache.BlobPath(b)
				if err != nil {
					t.Fatalf("BlobPath: %v", err)
				}
				nodes, err := f.cache.EnumerateBlobs()
				if err != nil {
					t.Fatalf("EnumerateBlobs: %v", err)
				}
				plan, err := PlanPrune(nodes, nil, nil, nil, time.Minute, f.clock)
				if err != nil {
					t.Fatalf("PlanPrune: %v", err)
				}
				if len(plan.Delete) != 1 {
					t.Fatalf("plan.Delete = %d; want 1", len(plan.Delete))
				}
				tc.prep(t, p, f.clock)
				rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, mode())
				if err != nil {
					t.Fatalf("executePrune: %v", err)
				}
				if len(rep.Skipped) != 1 || rep.Skipped[0].Digest != b {
					t.Fatalf("Skipped = %+v; want exactly %s", rep.Skipped, b)
				}
				s := rep.Skipped[0]
				if !strings.HasPrefix(s.Reason, tc.wantPrefix) {
					t.Errorf("Reason = %q; want prefix %q", s.Reason, tc.wantPrefix)
				}
				want := tc.want
				want.Digest = b
				if s.Refusal == nil || *s.Refusal != want {
					t.Errorf("Refusal = %+v; want %+v", s.Refusal, want)
				}
				if !blobOnDisk(t, f, b) {
					t.Errorf("refused blob %s was removed anyway", b)
				}
			})
		}
	}
}

// TestExecutePruneModeMismatch pins that executePrune refuses a mode whose
// kind lacks, or carries, the wrong seam, before touching the cache.
func TestExecutePruneModeMismatch(t *testing.T) {
	t.Parallel()
	pinned := func() (map[string]PruneReason, error) { return nil, nil }
	passUnlink := func(_ string, remove func() error) (bool, evictReason, error) { return remove() == nil, "", nil }
	for name, tc := range map[string]struct {
		mode pruneMode
		want string
	}{
		"pressure without pins": {pruneMode{kind: pruneModePressure}, "pressure mode takes a pin set and no hooks"},
		"evict without hooks":   {pruneMode{kind: pruneModeEvict}, "evict mode takes hooks and no pin set"},
		"plain with hooks":      {pruneMode{kind: pruneModePlain, hooks: &pruneHooks{}}, "plain mode takes no pin set and no hooks"},
		"evict with pins":       {pruneMode{kind: pruneModeEvict, hooks: &pruneHooks{unlink: passUnlink}, pinned: pinned}, "evict mode takes hooks and no pin set"},
		"evict without unlink":  {pruneMode{kind: pruneModeEvict, hooks: &pruneHooks{}}, "evict mode requires an unlink hook"},
		"unknown kind":          {pruneMode{kind: 9}, "unknown mode 9"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			_, err := f.cache.executePrune(&PrunePlan{}, 0, f.clock, nil, tc.mode)
			if err == nil {
				t.Fatal("executePrune accepted a mismatched mode")
			}
			if want := "execute prune: " + tc.want; err.Error() != want {
				t.Errorf("executePrune err = %q; want %q", err, want)
			}
		})
	}
}

// TestEvictGraceIsCheckedUnderTheLeaseLock pins that the eviction executor's
// Lstat and grace check run inside the remove closure it hands the unlink
// hook, so they run in the hook's critical section immediately before the
// Remove. The hook here commits the blob again (a lock-free rename that
// refreshes its mtime, as CommitBlob does) before calling remove: the blob
// must survive with the typed young refusal and the unchanged reason string,
// and the other blob is still removed.
func TestEvictGraceIsCheckedUnderTheLeaseLock(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	a := f.blob("grace-lock-a", time.Hour)
	b := f.blob("grace-lock-b", time.Hour)
	nodes, err := f.cache.EnumerateBlobs()
	if err != nil {
		t.Fatalf("EnumerateBlobs: %v", err)
	}
	plan, err := PlanPrune(nodes, nil, nil, nil, time.Minute, f.clock)
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	recommit := func() {
		p, err := f.cache.BlobPath(b)
		if err != nil {
			t.Fatalf("BlobPath: %v", err)
		}
		tmp := p + ".recommit"
		if err := os.WriteFile(tmp, []byte("grace-lock-b"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Chtimes(tmp, f.clock, f.clock); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
		if err := os.Rename(tmp, p); err != nil {
			t.Fatalf("Rename: %v", err)
		}
	}
	hooks := &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
		if digest == b {
			recommit()
		}
		err := remove()
		return err == nil, "", err
	}}
	rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, evictPrune(hooks))
	if err != nil {
		t.Fatalf("executePrune: %v", err)
	}
	if !blobOnDisk(t, f, b) {
		t.Fatalf("blob %s committed under the hook was removed", b)
	}
	if blobOnDisk(t, f, a) {
		t.Errorf("old blob %s is still on disk", a)
	}
	if rep.Deleted != 1 {
		t.Errorf("Deleted = %d; want 1", rep.Deleted)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Digest != b {
		t.Fatalf("Skipped = %+v; want exactly %s", rep.Skipped, b)
	}
	s := rep.Skipped[0]
	if s.Reason != "younger than grace" {
		t.Errorf("Reason = %q; want %q", s.Reason, "younger than grace")
	}
	want := SkipRefusal{Digest: b, Kind: RefusedYoung, Reason: EvictKeptYoung}
	if s.Refusal == nil || *s.Refusal != want {
		t.Errorf("Refusal = %+v; want %+v", s.Refusal, want)
	}
}
