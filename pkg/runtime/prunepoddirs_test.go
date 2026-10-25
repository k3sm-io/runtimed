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
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// putUntrackedPodDir leaves the shape an upgraded node carries: a pod dir with
// only rootfs/ and no reachability record, for a uid the daemon has no sandbox
// and no record of.
func putUntrackedPodDir(t *testing.T, rt *Runtime, id string) image.PodID {
	t.Helper()
	pid, err := image.ParsePodID(id)
	if err != nil {
		t.Fatalf("ParsePodID: %v", err)
	}
	if err := os.MkdirAll(rt.cache.PodRootfs(pid), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return pid
}

// registerLivePod makes id a pod the runtime holds a live sandbox for.
func registerLivePod(rt *Runtime, id string) {
	rt.mu.Lock()
	rt.pods[id] = &pod{box: &runtimev1.PodBox{PodId: id}}
	rt.mu.Unlock()
}

// TestPruneIgnoresUntrackedPodDirWithoutRecord is the upgraded-node defect: a
// leftover pod dir with no images.json, for a uid runtimed has no sandbox,
// in-flight create, reap record or vm helper for, aborted every prune with
// ErrRootsIncomplete. Such a dir cannot be a running pod's, so it contributes
// no root and the prune proceeds; the live pod's blobs stay protected.
func TestPruneIgnoresUntrackedPodDirWithoutRecord(t *testing.T) {
	client, rt := imagesTestClient(t)
	live := putBlob(t, rt, "live layer")
	orphan := putBlob(t, rt, "orphan layer")
	putPod(t, rt, "pod-live", image.ImageRoot{Reference: "app:v1", Config: live})
	registerLivePod(rt, "pod-live")
	putUntrackedPodDir(t, rt, "47ce8437-0000-4000-8000-000000000000")

	resp, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
	if err != nil {
		t.Fatalf("PruneImages with an untracked record-less pod dir: %v", err)
	}
	if !contains(resp.GetRemovedDigests(), orphan) {
		t.Errorf("the unreferenced blob was not pruned (removed: %v)", resp.GetRemovedDigests())
	}
	if !rt.cache.Has(live) {
		t.Fatalf("a live pod's blob was unlinked")
	}
}

// TestPruneFailsClosedOnTrackedPodDirWithoutRecord is the guarantee the skip
// must not weaken: a pod dir with no images.json whose uid the runtime DOES
// track still aborts the prune and deletes nothing, because that pod's blobs
// would otherwise look unreferenced.
func TestPruneFailsClosedOnTrackedPodDirWithoutRecord(t *testing.T) {
	cases := []struct {
		name  string
		track func(t *testing.T, rt *Runtime, id string)
	}{
		{"a live sandbox", func(_ *testing.T, rt *Runtime, id string) { registerLivePod(rt, id) }},
		{"an in-flight create", func(_ *testing.T, rt *Runtime, id string) {
			rt.mu.Lock()
			rt.creating[id]++
			rt.mu.Unlock()
		}},
		{"a durable reap record", func(t *testing.T, rt *Runtime, id string) {
			dir, err := rt.podReapDir(id)
			if err != nil {
				t.Fatalf("podReapDir: %v", err)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir reap dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "4242.json"), []byte("{}"), 0o600); err != nil {
				t.Fatalf("write reap record: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, rt := imagesTestClient(t)
			orphan := putBlob(t, rt, "orphan")
			putUntrackedPodDir(t, rt, "pod-tracked")
			tc.track(t, rt, "pod-tracked")

			_, err := client.PruneImages(context.Background(), &runtimev1.PruneImagesRequest{})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("PruneImages err = %v (code %v); want FailedPrecondition", err, status.Code(err))
			}
			if !rt.cache.Has(orphan) {
				t.Errorf("a blob was deleted despite a tracked pod with no record")
			}
		})
	}
}

// TestPodUntrackedBeforeStartupReap pins that nothing is untracked until the
// startup reap has run: before it, AttachPod may still adopt any pod dir's
// pod, so absence from the registry proves nothing.
func TestPodUntrackedBeforeStartupReap(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	pid := putUntrackedPodDir(t, rt, "pod-early")
	if rt.podUntracked(pid) {
		t.Fatalf("a pod dir was judged untracked before the startup reap ran")
	}
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatalf("ReapOrphanedPods: %v", err)
	}
	if !rt.podUntracked(pid) {
		t.Fatalf("an unowned pod dir was not judged untracked after the startup reap")
	}
}
