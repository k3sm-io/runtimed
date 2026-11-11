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
	"os"
	"strings"
	"testing"
	"time"
)

// TestExecutePruneHooks drives executePrune directly with each pruneHooks seam
// on a fixture cache: a nil hooks pointer behaves as ExecutePrune, a guard drop
// keeps its blob with the reason in the report, a guard error unlinks nothing,
// an unlink hook that refuses a blob keeps it with the reason, a blob the
// executor's own re-verification refuses never reaches the hook, a hook error
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
			name:  "nil guard and nil unlink are no-ops",
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
			name: "blob refused by re-verification is never offered to the hook",
			hooks: func(_ *gcFixture, keep string) *pruneHooks {
				return &pruneHooks{unlink: func(digest string, remove func() error) (bool, evictReason, error) {
					if digest == keep {
						return false, "", errors.New("hook offered a blob younger than grace")
					}
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
			rep, err := f.cache.executePrune(plan, time.Minute, f.clock, nil, tc.hooks(f, b))
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
