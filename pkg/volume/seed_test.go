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

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/image"
)

// errSeedClone is the injected clone failure.
var errSeedClone = errors.New("injected clone failure")

// failNthCloner byte-copies like image.ByteCopier but fails the nth Clone call
// (1-based), modelling a seed that dies partway through the template.
type failNthCloner struct {
	n     int
	calls int
}

func (c *failNthCloner) Clone(src, dst string) (bool, error) {
	c.calls++
	if c.calls == c.n {
		return false, errSeedClone
	}
	return image.ByteCopier{}.Clone(src, dst)
}

// TestSeedFailureLeavesNoHalfSeededVolume proves seeding is all-or-nothing: a
// seed that fails on the second file returns the error and leaves neither the
// data dir nor a staging dir behind, so the retry does not take the reuse path
// and report a half-seeded volume as bound. A retry with a working cloner then
// seeds the whole template, even over a stale staging dir left by a crash.
func TestSeedFailureLeavesNoHalfSeededVolume(t *testing.T) {
	root := t.TempDir()
	class := testClass(root)

	src := filepath.Join(root, "template")
	files := map[string]string{"a.sql": "A", "b.sql": "B", "c.sql": "C"}
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tmpl := fakeTemplate{dir: src, present: true}
	box := pvcBox("prod", "data", "seeded", "/seed", false)

	dataDir, err := class.DataDir("prod", "seeded")
	if err != nil {
		t.Fatal(err)
	}

	// First bind: the clone of the second file fails.
	failing := &failNthCloner{n: 2}
	rootfs1 := filepath.Join(root, "pods", "pod-a", "rootfs")
	if err := os.MkdirAll(rootfs1, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBinder(class, failing, tmpl, nil).Bind(context.Background(), box, rootfs1); !errors.Is(err, errSeedClone) {
		t.Fatalf("Bind with a failing cloner: err = %v, want %v", err, errSeedClone)
	}
	if failing.calls < 2 {
		t.Fatalf("cloner called %d times, want the failure on call 2", failing.calls)
	}
	if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("data dir %s exists after a failed seed (err=%v); a retry would reuse a half-seeded volume", dataDir, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(dataDir)); err == nil && len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("namespace dir holds %v after a failed seed; want no data or staging dir", names)
	}

	// A crash mid-seed (no deferred cleanup) leaves a stale staging dir; the
	// retry must discard it rather than fold its contents into the volume.
	stale := stagingDir(dataDir)
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "junk"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Retry with a working cloner: the whole template is seeded.
	rootfs2 := filepath.Join(root, "pods", "pod-b", "rootfs")
	if err := os.MkdirAll(rootfs2, 0o755); err != nil {
		t.Fatal(err)
	}
	bindings, err := NewBinder(class, image.ByteCopier{}, tmpl, nil).Bind(context.Background(), box, rootfs2)
	if err != nil {
		t.Fatalf("Bind (retry): %v", err)
	}
	if !bindings[0].Seeded {
		t.Error("retry after a failed seed must seed (and report Seeded)")
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(files) {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("seeded dir holds %v, want exactly the %d template files", names, len(files))
	}
	for name, body := range files {
		if got, err := os.ReadFile(filepath.Join(dataDir, name)); err != nil || string(got) != body {
			t.Errorf("seeded %s = %q (err %v), want %q", name, got, err, body)
		}
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging dir %s survives a successful seed (err=%v)", stale, err)
	}
}
