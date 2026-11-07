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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// writeReleasedCopy writes a decodable released copy straight into dir under
// its own name, released at at, and returns the name.
func writeReleasedCopy(t *testing.T, dir string, i int, at time.Time) string {
	t.Helper()
	buf := fmt.Appendf(nil, `{"reference":"r%d","artifactType":%q,"configDigest":"sha256:%064x","layerDigests":[]}`, i, testModelType, i)
	name := releasedName(buf)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	return name
}

// TestReleasedArtifactCopiesAreBounded pins the bound on the released record
// copies: an untriggered reclaim pass keeps the newest MaxReleasedArtifacts
// and removes every file that is not a decodable copy under its own name, and
// a stale commit temp, while keeping a fresh temp. A byte cap drops the oldest
// copies first.
func TestReleasedArtifactCopiesAreBounded(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(x.dir, ArtifactReleasedIndexSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-48 * time.Hour)
	var names []string // oldest first
	for i := range MaxReleasedArtifacts + 10 {
		names = append(names, writeReleasedCopy(t, dir, i, base.Add(time.Duration(i)*time.Second)))
	}
	junk := map[string][]byte{
		"not-a-copy.json":            []byte(`{}`),
		fmt.Sprintf("%064x.json", 7): []byte(`{"configDigest":"sha256:%064x"}`),
		releasedName([]byte("{")):    []byte("{"),
		".index-stale.json":          []byte("partial"),
	}
	for name, buf := range junk {
		if err := os.WriteFile(filepath.Join(dir, name), buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, ".index-stale.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".index-fresh.json"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Free space is above the floor: the pass is not triggered, and bounds anyway.
	rep, err := f.cache.ReclaimUnderPressure(context.Background(), ReclaimConfig{
		FreeBytes: (&fakeFree{free: []uint64{1 << 40}}).sample,
	})
	if err != nil || rep.Triggered {
		t.Fatalf("ReclaimUnderPressure = %+v, %v; want an untriggered pass", rep, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	want := append(slices.Clone(names[10:]), ".index-fresh.json")
	slices.Sort(left)
	slices.Sort(want)
	if !slices.Equal(left, want) {
		t.Fatalf("left %d entries, want the newest %d copies and the fresh temp; extra or missing: %v",
			len(left), MaxReleasedArtifacts, symmetricDiff(left, want))
	}

	sub, err := x.openReleased()
	if err != nil || sub == nil {
		t.Fatalf("openReleased: %v", err)
	}
	defer sub.Close()
	fi, err := os.Stat(filepath.Join(dir, names[len(names)-1]))
	if err != nil {
		t.Fatal(err)
	}
	if err := boundReleased(sub, MaxReleasedArtifacts, 3*fi.Size(), time.Now(), true); err != nil {
		t.Fatalf("boundReleased: %v", err)
	}
	copies, err := x.releasedArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, rc := range copies {
		kept = append(kept, rc.name)
	}
	slices.Sort(kept)
	newest := slices.Clone(names[len(names)-3:])
	slices.Sort(newest)
	if !slices.Equal(kept, newest) {
		t.Fatalf("byte cap kept %v; want the three newest %v", kept, newest)
	}
}

func symmetricDiff(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, "+"+s)
		}
	}
	for _, s := range b {
		if !slices.Contains(a, s) {
			out = append(out, "-"+s)
		}
	}
	return out
}

// TestOpenSubdirNamesTheSubdirectory pins that an ownership refusal names the
// index subdirectory and what was expected, so the operator can fix it, and
// that a symlink planted at a subdirectory's name is refused, not followed.
func TestOpenSubdirNamesTheSubdirectory(t *testing.T) {
	f := newGCFixture(t)
	x, err := NewFileIndex(f.cache)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(x.dir, ArtifactReleasedIndexSubdir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err = x.releasedArtifacts()
	if !errors.Is(err, ErrIndexNotOwned) || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "expected 0700") {
		t.Fatalf("releasedArtifacts on a 0777 subdirectory = %v; want ErrIndexNotOwned naming %s and the expected mode", err, dir)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(x.dir, ArtifactIndexSubdir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ArtifactIndexSubdir, dir); err != nil {
		t.Fatal(err)
	}
	if err := x.BoundReleasedArtifacts(); !errors.Is(err, ErrIndexNotOwned) {
		t.Fatalf("BoundReleasedArtifacts through a symlinked subdirectory = %v; want ErrIndexNotOwned", err)
	}
}

// TestReadAnchoredLimitRefusesAnOversizedFile pins the bounded read the
// released copies and a replaced record go through.
func TestReadAnchoredLimitRefusesAnOversizedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if buf, err := readAnchoredLimit(root, "f", 5); err != nil || string(buf) != "12345" {
		t.Fatalf("readAnchoredLimit at the limit = %q, %v", buf, err)
	}
	if _, err := readAnchoredLimit(root, "f", 4); !errors.Is(err, ErrArtifactRecordTooLarge) {
		t.Fatalf("readAnchoredLimit over the limit = %v; want ErrArtifactRecordTooLarge", err)
	}
}
