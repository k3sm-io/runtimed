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

package runtime

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCreatePodStartsFromAnEmptyRootfs pins that a create never inherits what
// an earlier life of the pod id left in its rootfs: the stale entries are
// cleared without following a symlink out of the pod dir, and only the rootfs
// entry is cleared, so the pod dir's other records survive.
func TestCreatePodStartsFromAnEmptyRootfs(t *testing.T) {
	const podID = "pod-stale"
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})

	podDir, err := rt.podDir(podID)
	if err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(podDir, "rootfs")
	staleFile := filepath.Join(rootfs, "stale")
	staleDir := filepath.Join(rootfs, "nested", "deeper")
	if err := os.MkdirAll(staleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleFile, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "f"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(t.TempDir(), "canary")
	if err := os.Mkdir(canary, 0o755); err != nil {
		t.Fatal(err)
	}
	canaryFile := filepath.Join(canary, "keep")
	if err := os.WriteFile(canaryFile, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canary, filepath.Join(rootfs, "escape")); err != nil {
		t.Fatal(err)
	}
	podMarker := filepath.Join(podDir, "pod-marker")
	if err := os.WriteFile(podMarker, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, podID)})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod = (%v, %v)", resp, err)
	}

	for _, p := range []string{staleFile, filepath.Join(rootfs, "nested"), filepath.Join(rootfs, "escape")} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s survived the create: %v", p, err)
		}
	}
	if b, err := os.ReadFile(canaryFile); err != nil || string(b) != "outside" {
		t.Errorf("canary outside the pod dir = (%q, %v), want it intact", b, err)
	}
	if b, err := os.ReadFile(podMarker); err != nil || string(b) != "keep" {
		t.Errorf("pod dir marker = (%q, %v), want it intact", b, err)
	}
	if fi, err := os.Stat(rootfs); err != nil || !fi.IsDir() {
		t.Errorf("rootfs after create = (%v, %v), want a directory", fi, err)
	}
}
