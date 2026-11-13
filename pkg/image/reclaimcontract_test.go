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
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSpaceReclaimerHonoursDryRun pins the DryRun contract of the real Cache:
// a dry pass reports what it would reclaim and changes nothing. The store is
// byte-for-byte what it was, free space is sampled once and reported as
// unchanged, and the once-per-dir skip report is not consumed, so the real
// pass that follows logs the skipped pod dir exactly as a real pass on a fresh
// identical store does.
func TestSpaceReclaimerHonoursDryRun(t *testing.T) {
	const skippedPod = "pod-gone-dry"

	// build makes the fixture: one unreferenced blob past grace, and one pod
	// dir with no reachability record that the daemon proves untracked.
	build := func() (*gcFixture, string) {
		f := newGCFixture(t)
		dig := f.blob("evict me: nothing names this blob", 2*time.Hour)
		pid := f.pod(skippedPod)
		if err := os.Remove(filepath.Join(f.cache.PodDir(pid), PodReferencesName)); err != nil {
			t.Fatalf("remove record: %v", err)
		}
		return f, dig
	}
	config := func(logs *syncBuffer, free *fakeFree, dry bool) ReclaimConfig {
		return ReclaimConfig{
			HighFreeBytes: 1 << 40, TargetFreeBytes: 1 << 40, Grace: time.Minute,
			FreeBytes:    free.sample,
			Log:          slog.New(slog.NewTextHandler(logs, nil)),
			UntrackedPod: func(PodID) bool { return true },
			DryRun:       dry,
		}
	}
	pass := func(f *gcFixture, dry bool) (*ReclaimReport, string, int) {
		t.Helper()
		var logs syncBuffer
		free := &fakeFree{free: []uint64{0}}
		rep, err := f.cache.ReclaimUnderPressure(context.Background(), config(&logs, free, dry))
		if err != nil {
			t.Fatalf("reclaim (dry=%v): %v", dry, err)
		}
		return rep, logs.take(), free.count()
	}

	f, dig := build()
	before := storeSnapshot(t, f.cache.root)

	rep, dryLog, samples := pass(f, true)
	if !rep.DryRun || !rep.Triggered {
		t.Fatalf("dry pass report: DryRun=%v Triggered=%v, want both true", rep.DryRun, rep.Triggered)
	}
	if rep.ReclaimedBytes <= 0 {
		t.Fatalf("dry pass ReclaimedBytes = %d, want > 0", rep.ReclaimedBytes)
	}
	if !slices.Contains(rep.Removed, dig) {
		t.Fatalf("dry pass plan %v does not name the evictable blob %s", rep.Removed, dig)
	}
	if rep.FreeAfter != rep.FreeBefore {
		t.Fatalf("dry pass FreeAfter = %d, FreeBefore = %d; want them equal", rep.FreeAfter, rep.FreeBefore)
	}
	if samples != 1 {
		t.Fatalf("dry pass sampled free space %d times, want 1", samples)
	}
	if after := storeSnapshot(t, f.cache.root); !maps.Equal(before, after) {
		t.Fatalf("dry pass changed the store:\nbefore %v\nafter  %v", before, after)
	}
	if !f.exists(dig) {
		t.Fatalf("dry pass removed %s", dig)
	}
	if got := skipLines(dryLog); !strings.Contains(got, skippedPod) {
		t.Fatalf("dry pass did not name the dir a real pass would report:\n%s", dryLog)
	}

	// The real pass after the dry one must log exactly what a real pass on a
	// fresh identical store logs.
	_, afterDry, _ := pass(f, false)
	fresh, _ := build()
	_, onFresh, _ := pass(fresh, false)
	want := skipLines(onFresh)
	if !strings.Contains(want, skippedPod) {
		t.Fatalf("baseline real pass did not report the skipped dir:\n%s", onFresh)
	}
	if got := skipLines(afterDry); got != want {
		t.Fatalf("the dry pass consumed the skip report:\nreal pass after dry: %q\nreal pass on fresh: %q", got, want)
	}
	if f.exists(dig) {
		t.Fatalf("real pass after the dry one kept the evictable blob %s", dig)
	}
}

// storeSnapshot maps every node under root to its type, size and, for a
// regular file, a hash of its content.
func storeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		v := fi.Mode().Type().String()
		if fi.Mode().IsRegular() {
			buf, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(buf)
			v += " " + hex.EncodeToString(sum[:])
		}
		if !fi.IsDir() {
			v += " " + strconv.FormatInt(fi.Size(), 10)
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatalf("walk store %s: %v", root, err)
	}
	return out
}

// skipLines returns the skipped-pod-dir warnings in a captured log, each
// reduced to its pods attribute so the timestamps do not differ.
func skipLines(log string) string {
	var out []string
	for line := range strings.SplitSeq(log, "\n") {
		if !strings.Contains(line, "skipped pod dirs") {
			continue
		}
		if i := strings.Index(line, "pods="); i >= 0 {
			out = append(out, line[i:])
		}
	}
	return strings.Join(out, "\n")
}
