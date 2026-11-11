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
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

// TestExecuteTreePruneHooks drives executeTreePrune with each guard shape on a
// fixture holding two unreferenced trees: nil hooks, an empty hooks value and
// a nil drop set remove both exactly as ExecuteTreePrune does; a guard naming
// one tree's backing blob leaves that tree on disk with a typed refusal; a
// guard error removes nothing.
func TestExecuteTreePruneHooks(t *testing.T) {
	t.Parallel()

	errGuard := errors.New("guard failed")
	keepCfg, keepLayer := treeDigest("a"), treeDigest("b")
	goneCfg, goneLayer := treeDigest("c"), treeDigest("d")

	tests := []struct {
		name       string
		hooks      *treePruneHooks
		wantErr    error
		targetKeep bool
	}{
		{name: "nil hooks behaves as ExecuteTreePrune"},
		{name: "nil guard is a no-op", hooks: &treePruneHooks{}},
		{
			name: "nil drop set is a no-op",
			hooks: &treePruneHooks{guard: func() (map[string]evictReason, error) {
				return nil, nil
			}},
		},
		{
			name: "guard drop keeps that tree and removes the rest",
			hooks: &treePruneHooks{guard: func() (map[string]evictReason, error) {
				return map[string]evictReason{keepLayer: evictShared}, nil
			}},
			targetKeep: true,
		},
		{
			name: "guard error removes nothing",
			hooks: &treePruneHooks{guard: func() (map[string]evictReason, error) {
				return nil, errGuard
			}},
			wantErr: errGuard,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newGCFixture(t)
			keep := f.nativeTree(keepCfg, []string{keepLayer}, 100, time.Hour)
			gone := f.nativeTree(goneCfg, []string{goneLayer}, 200, time.Hour)
			plan := f.planFor(time.Minute)
			if len(plan.DeleteTrees) != 2 {
				t.Fatalf("DeleteTrees = %v; want both trees", plan.DeleteTrees)
			}

			rep, err := f.cache.executeTreePrune(plan, time.Minute, f.clock, nil, tt.hooks)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v; want %v", err, tt.wantErr)
				}
				for _, tf := range []treeFixture{keep, gone} {
					if _, serr := os.Lstat(tf.dir); serr != nil {
						t.Errorf("tree %s removed despite the guard error: %v", tf.key, serr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("executeTreePrune: %v", err)
			}

			if !tt.targetKeep {
				want := []string{keep.key, gone.key}
				got := append([]string(nil), rep.Removed...)
				sort.Strings(want)
				sort.Strings(got)
				if !reflect.DeepEqual(got, want) || rep.Deleted != 2 || rep.DeletedBytes != 300 || len(rep.Skipped) != 0 {
					t.Fatalf("report = %+v; want both trees removed, 300 bytes, no skips", rep)
				}
				return
			}

			if _, err := os.Lstat(keep.dir); err != nil {
				t.Errorf("dropped tree is gone from disk: %v", err)
			}
			if _, err := os.Lstat(gone.dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("undropped tree still on disk: %v", err)
			}
			if !reflect.DeepEqual(rep.Removed, []string{gone.key}) || rep.Deleted != 1 || rep.DeletedBytes != 200 {
				t.Errorf("report = %+v; want only %s removed, 200 bytes", rep, gone.key)
			}
			want := []SkippedTree{{
				Store:   TreeStoreUnpacked,
				Path:    treeRel(t, f, keep),
				Key:     keep.key,
				Reason:  "dropped by guard: " + string(evictShared),
				Refusal: &SkipRefusal{Digest: keepLayer, Kind: RefusedByGuard, Reason: EvictKeptShared},
			}}
			if !reflect.DeepEqual(rep.Skipped, want) {
				t.Errorf("Skipped = %+v; want %+v", rep.Skipped, want)
			}
		})
	}
}

// TestExecuteTreePruneUntypedSkipsCarryNoRefusal pins that the executor's own
// skip paths stay untyped: only a guard drop sets Refusal.
func TestExecuteTreePruneUntypedSkipsCarryNoRefusal(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	tf := f.nativeTree(treeDigest("a"), []string{treeDigest("b")}, 100, time.Hour)
	plan := f.planFor(time.Minute)
	if err := os.RemoveAll(tf.dir); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	guard := &treePruneHooks{guard: func() (map[string]evictReason, error) {
		return map[string]evictReason{treeDigest("e"): evictInUse}, nil
	}}
	rep, err := f.cache.executeTreePrune(plan, time.Minute, f.clock, nil, guard)
	if err != nil {
		t.Fatalf("executeTreePrune: %v", err)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].Reason != "already absent" || rep.Skipped[0].Refusal != nil {
		t.Fatalf("Skipped = %+v; want one untyped \"already absent\"", rep.Skipped)
	}
}

// treeRel is tf's store-root-relative path as the inventory records it.
func treeRel(t *testing.T, f *gcFixture, tf treeFixture) string {
	t.Helper()
	root, _, err := f.cache.treeStoreLayout(tf.store)
	if err != nil {
		t.Fatalf("treeStoreLayout: %v", err)
	}
	r, err := filepath.Rel(root, tf.dir)
	if err != nil {
		t.Fatalf("Rel: %v", err)
	}
	return r
}
