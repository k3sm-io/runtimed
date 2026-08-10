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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// tree lists every path under root with its type, so a test can assert the
// filesystem is byte-identical before and after a rejected operation.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, rel+"|"+d.Type().String())
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(out)
	return out
}

// TestCreatePodRejectsTraversingPodID is the artifact half of B136's contract,
// and the half that can actually fail: it exercises the call sites that TOUCH
// the filesystem (createPod's MkdirAll, DeletePod's RemoveAll, and the reap
// store's MkdirAll/RemoveAll) rather than the pure path-building function.
//
// Two harness details are load-bearing, both learned from the guard this fix
// replaces:
//
//   - ONE shared root. The default test harness gives Config.Root and the image
//     cache two DIFFERENT temp dirs, which makes removePodDir's containment check
//     unsatisfiable and its RemoveAll leg unreachable — the destructive path
//     would never execute and the test would pass against unfixed code.
//   - The root is nested inside an observable parent, so an escape ABOVE it is
//     detectable. A test that only watched the root itself could not see the very
//     traversal it exists to catch.
func TestCreatePodRejectsTraversingPodID(t *testing.T) {
	outside := t.TempDir()
	root := filepath.Join(outside, "a", "b", "k3sm")
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	// Deliberately siblings of the pods tree, so a "../<name>" id that stays
	// inside the daemon root still has something real to destroy — this is the
	// case a bare prefix check on the root admits.
	mustMkdir(t, filepath.Join(root, "server", "bin"))
	mustWrite(t, filepath.Join(root, "server", "k3sm.kubeconfig"), "sentinel")
	// A sibling of the ROOT whose name merely starts with it — the classic
	// prefix-check bypass.
	mustMkdir(t, filepath.Join(outside, "a", "b", "k3sm-evil"))
	mustWrite(t, filepath.Join(outside, "a", "b", "k3sm-evil", "keep"), "sentinel")

	rt := newTestRuntimeCfg(t, Config{Root: root}, testDeps(t, Deps{Cache: cache}))
	before := tree(t, outside)

	hostile := []string{
		"..",
		"../server",
		"../../k3sm-evil",
		"a/b",
		"/abs",
		"./pod-1",
		"POD-1",
	}
	for _, id := range hostile {
		t.Run("create/"+id, func(t *testing.T) {
			// hostBinBox passes validatePodBox, so the ONLY thing that can stop
			// this request is the pod id itself. A box that failed validation for
			// an unrelated reason would make this test pass without ever reaching
			// the filesystem — the vacuity this whole gate exists to avoid.
			box := hostBinBox(id)
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err == nil && resp.GetError() == nil {
				t.Fatalf("CreatePod(pod_id=%q) succeeded; a traversing id must be refused", id)
			}
		})
		t.Run("delete/"+id, func(t *testing.T) {
			// DeletePod reaches removePodDir's RemoveAll with the raw id, and the
			// reap store's RemoveAll with no containment guard at all — so it is
			// exercised independently of CreatePod having succeeded.
			_, _ = rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: id})
		})
	}

	if got := tree(t, outside); !slices.Equal(before, got) {
		t.Errorf("a hostile pod id mutated the filesystem\nbefore: %v\nafter:  %v", before, got)
	}

	// POSITIVE CONTROL: a legal id must still create its rootfs under the pods
	// tree. Without this the test cannot distinguish "traversal is refused" from
	// "every pod is refused", and the latter would break every pod on the node.
	okID := "5f8a1c2d-3e4b-4a6c-8d9e-0f1a2b3c4d5e"
	id, err := image.ParsePodID(okID)
	if err != nil {
		t.Fatalf("ParsePodID(%q): %v", okID, err)
	}
	mustMkdir(t, cache.PodRootfs(id))
	if err := rt.removePodDir(okID); err != nil {
		t.Fatalf("removePodDir(valid id) = %v, want nil", err)
	}
	if _, err := os.Stat(filepath.Join(root, "pods", okID)); !os.IsNotExist(err) {
		t.Errorf("removePodDir(valid id) left %s in place (err=%v); the positive control proves the RemoveAll leg is reachable", filepath.Join(root, "pods", okID), err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
