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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chmodFor sets dir's mode for the rest of the test and restores it in
// cleanup, so t.TempDir can still remove the store. A permission-based
// failure cannot be provoked as root, so the case is skipped there.
func chmodFor(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission failures cannot be provoked as root")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, fi.Mode().Perm()) })
}

// assertUnusableAtRealName fails unless tf is still at its real name with no
// record, and the inventory lists it as a tree whose record is unusable — a
// node the planner may reclaim but nothing can serve.
func assertUnusableAtRealName(t *testing.T, f *gcFixture, tf treeFixture) {
	t.Helper()
	if fi, err := os.Lstat(tf.dir); err != nil || !fi.IsDir() {
		t.Fatalf("tree %s not at its real name: %v", tf.dir, err)
	}
	if _, err := os.Lstat(filepath.Join(tf.dir, TreeRecordName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record of %s still present: %v", tf.dir, err)
	}
	trees, err := f.cache.EnumerateTrees()
	if err != nil {
		t.Fatalf("EnumerateTrees: %v", err)
	}
	found := false
	for _, n := range trees {
		if n.Key != tf.key {
			continue
		}
		found = true
		if n.Kind != TreeKindTree || !n.RecordUnusable || n.Size != 0 || len(n.Backing) != 0 {
			t.Errorf("inventory node = %+v; want a tree with an unusable record, no size, no backing", n)
		}
	}
	if !found {
		t.Fatalf("inventory = %+v; want %s listed", trees, tf.key)
	}
}

// TestTreeTrashDetachMkdirFails pins the residue of a detach whose trash
// directory cannot be created: the record is already unlinked, the tree is
// skipped (not removed) and stays at its real name, and the next inventory
// lists it as RecordUnusable rather than as a usable tree.
func TestTreeTrashDetachMkdirFails(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	tf := f.nativeTree(f.blob("trash-mkdir-cfg", time.Hour), nil, 10, time.Hour)
	plan := f.planFor(time.Minute)
	if len(plan.DeleteTrees) != 1 {
		t.Fatalf("DeleteTrees = %v; want exactly %s", plan.DeleteTrees, tf.key)
	}
	chmodFor(t, f.cache.UnpackedRoot(), 0o500)

	rep, err := f.cache.ExecuteTreePrune(plan, time.Minute, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecuteTreePrune: %v", err)
	}
	if len(rep.Removed) != 0 || rep.Deleted != 0 || rep.DeletedBytes != 0 || rep.TrashLeft != 0 {
		t.Fatalf("report = %+v; want nothing removed", rep)
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "create tree trash") {
		t.Fatalf("Skipped = %+v; want one create-trash skip", rep.Skipped)
	}
	assertUnusableAtRealName(t, f, tf)
	assertNoTrash(t, f)
}

// TestTreeTrashDetachRenameFails pins the residue of a detach whose rename
// fails: the tree is skipped and stays at its real name without its record,
// and the empty trash directory created for it is removed, not left behind.
func TestTreeTrashDetachRenameFails(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	tf := f.nativeTree(f.blob("trash-rename-cfg", time.Hour), nil, 10, time.Hour)
	plan := f.planFor(time.Minute)
	if len(plan.DeleteTrees) != 1 {
		t.Fatalf("DeleteTrees = %v; want exactly %s", plan.DeleteTrees, tf.key)
	}
	// The rename unlinks the tree's name from its algorithm directory, so a
	// read-only algorithm directory fails it while the record (inside the
	// tree) and the trash directory (at the store root) are still writable.
	chmodFor(t, filepath.Dir(tf.dir), 0o500)

	rep, err := f.cache.ExecuteTreePrune(plan, time.Minute, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecuteTreePrune: %v", err)
	}
	if len(rep.Removed) != 0 || rep.Deleted != 0 || rep.TrashLeft != 0 {
		t.Fatalf("report = %+v; want nothing removed", rep)
	}
	if len(rep.Skipped) != 1 || !strings.Contains(rep.Skipped[0].Reason, "move tree to trash") {
		t.Fatalf("Skipped = %+v; want one move-to-trash skip", rep.Skipped)
	}
	assertNoTrash(t, f)
	assertUnusableAtRealName(t, f, tf)
}

// TestTreeTrashSweepDoesNotFollowLinks pins that the sweep removes a planted
// ".trash-*" symlink and regular file at a store root by name: the link is
// unlinked, never followed, so a sentinel it points at outside the store is
// untouched.
func TestTreeTrashSweepDoesNotFollowLinks(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	store := f.cache.UnpackedRoot()
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	link := filepath.Join(store, treeTrashPrefix+"link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	file := filepath.Join(store, treeTrashPrefix+"file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write planted file: %v", err)
	}

	swept, remaining, err := f.cache.sweepTreeTrash()
	if swept != 2 || remaining != 0 || err != nil {
		t.Fatalf("sweepTreeTrash = %d, %d, %v; want 2, 0, nil", swept, remaining, err)
	}
	for _, p := range []string{link, file} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("planted %s still present: %v", p, err)
		}
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Fatalf("sentinel outside the store = %q, %v; want it untouched", b, err)
	}
}

// TestTreeTrashSweepCap pins the per-pass bound: with more leftover trash
// entries than maxStageSweep, one run removes exactly maxStageSweep and
// reports the rest as TrashRemaining, and the next run removes the rest.
func TestTreeTrashSweepCap(t *testing.T) {
	t.Parallel()
	f := newGCFixture(t)
	store := f.cache.UnpackedRoot()
	const extra = 6
	for i := range maxStageSweep + extra {
		d := filepath.Join(store, fmt.Sprintf("%s%03d", treeTrashPrefix, i), treeTrashTreeName)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		if err := os.WriteFile(filepath.Join(d, "payload"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}

	rep, err := f.cache.ExecuteTreePrune(&PrunePlan{}, time.Minute, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecuteTreePrune: %v", err)
	}
	if rep.TrashSwept != maxStageSweep || rep.TrashRemaining != extra || rep.TrashErr != nil {
		t.Fatalf("first run swept %d, remaining %d, err %v; want %d, %d, nil",
			rep.TrashSwept, rep.TrashRemaining, rep.TrashErr, maxStageSweep, extra)
	}
	rep, err = f.cache.ExecuteTreePrune(&PrunePlan{}, time.Minute, f.clock, nil)
	if err != nil {
		t.Fatalf("ExecuteTreePrune: %v", err)
	}
	if rep.TrashSwept != extra || rep.TrashRemaining != 0 || rep.TrashErr != nil {
		t.Fatalf("second run swept %d, remaining %d, err %v; want %d, 0, nil",
			rep.TrashSwept, rep.TrashRemaining, rep.TrashErr, extra)
	}
	assertNoTrash(t, f)
}

// TestLogTreeTrash pins the reclaim pass's one trash line: a Warn carrying
// the counts and the first error when trash is left, an Info when the sweep
// only recovered leftovers, and nothing for a clean run.
func TestLogTreeTrash(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		rep  TreeExecuteReport
		want []string // substrings of the output; nil means no output
	}{
		{name: "clean", rep: TreeExecuteReport{}},
		{name: "swept only", rep: TreeExecuteReport{TrashSwept: 3},
			want: []string{"level=INFO", "trash_swept=3"}},
		{name: "left", rep: TreeExecuteReport{TrashLeft: 1, TrashRemaining: 2, TrashSwept: 64, TrashErr: errors.New("boom")},
			want: []string{"level=WARN", "trash_left=1", "trash_remaining=2", "trash_swept=64", "err=boom"}},
		{name: "error only", rep: TreeExecuteReport{TrashErr: errors.New("unreadable")},
			want: []string{"level=WARN", "err=unreadable"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logTreeTrash(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &tt.rep)
			out := buf.String()
			if tt.want == nil {
				if out != "" {
					t.Fatalf("output = %q; want none", out)
				}
				return
			}
			if strings.Count(out, "\n") != 1 {
				t.Errorf("output = %q; want exactly one line", out)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output = %q; want it to contain %q", out, w)
				}
			}
		})
	}
}
