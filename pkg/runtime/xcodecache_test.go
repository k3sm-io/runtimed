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
	"os"
	"path/filepath"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/xcodecache"
)

const testXcodeBuild = "17E5159k"

// xcodeCacheRuntime is a runtime whose developer dir reads as testXcodeBuild,
// so no test reads the real Xcode.
func xcodeCacheRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt := newTestRuntime(t, Deps{Spawner: &mcProbeSpawner{}, Waiter: newBlockingWaiter()})
	rt.xcodeCache.builds = map[string]xcodeBuild{testDevDir: {build: testXcodeBuild}}
	// The commit runs synchronously, so a delete's publish (or its absence)
	// is final by the time DeletePod returns.
	rt.xcodeCache.runCommit = func(f func()) { f() }
	return rt
}

func xcodeCacheBox(rt *Runtime, podID, key string) *runtimev1.PodBox {
	box := hostBinBox(rt, podID)
	box.Namespace = "builds"
	box.GetSandboxProfile().XcodeToolchainDir = testDevDir
	if box.Annotations == nil {
		box.Annotations = map[string]string{}
	}
	box.Annotations[xcodecache.Annotation] = key
	return box
}

var testCacheEntry = xcodecache.Entry{Namespace: "builds", Key: "app", Build: testXcodeBuild}

// seedXcodeCache publishes a snapshot whose every part holds file f = tag.
func seedXcodeCache(t *testing.T, rt *Runtime, tag string) {
	t.Helper()
	home := t.TempDir()
	writeCacheParts(t, home, tag)
	if _, err := rt.xcodeCacheStore().Publish(testCacheEntry, home, "seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func writeCacheParts(t *testing.T, home, tag string) {
	t.Helper()
	for _, part := range xcodecache.Parts {
		if err := os.MkdirAll(filepath.Join(home, part), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, part, "f"), []byte(tag), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func snapshotTag(t *testing.T, rt *Runtime) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(rt.xcodeCacheStore().Dir(testCacheEntry), xcodecache.SnapshotName, xcodecache.Parts[0], "f"))
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

func podHome(t *testing.T, rt *Runtime, box *runtimev1.PodBox) string {
	t.Helper()
	dv, err := rt.rootfsPath(box)
	if err != nil {
		t.Fatal(err)
	}
	return podHomeDir(dv)
}

func TestXcodeCacheCheckoutAtCreate(t *testing.T) {
	t.Run("a snapshot is cloned into the pod home", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		seedXcodeCache(t, rt, "warm")
		box := xcodeCacheBox(rt, "pod-xc-warm", "app")
		mustCreatePod(t, rt, box)
		for _, part := range xcodecache.Parts {
			b, err := os.ReadFile(filepath.Join(podHome(t, rt, box), part, "f"))
			if err != nil || string(b) != "warm" {
				t.Errorf("%s in the pod home = %q, %v; want warm", part, b, err)
			}
		}
	})
	t.Run("no snapshot: the pod starts cold", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		box := xcodeCacheBox(rt, "pod-xc-cold", "app")
		mustCreatePod(t, rt, box)
		if _, err := os.Lstat(filepath.Join(podHome(t, rt, box), xcodecache.Parts[0])); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("cold pod has a DerivedData: %v", err)
		}
	})
	// The cache is keyed by the granted Xcode; without the grant there is no
	// key and no checkout, however the annotation reads.
	t.Run("no toolchain grant: no checkout", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		seedXcodeCache(t, rt, "warm")
		box := xcodeCacheBox(rt, "pod-xc-nogrant", "app")
		box.GetSandboxProfile().XcodeToolchainDir = ""
		mustCreatePod(t, rt, box)
		if _, err := os.Lstat(filepath.Join(podHome(t, rt, box), xcodecache.Parts[0])); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("ungranted pod got a checkout: %v", err)
		}
	})
	// An invalid key degrades: the pod is created, cold.
	t.Run("an invalid key starts the pod cold", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		seedXcodeCache(t, rt, "warm")
		box := xcodeCacheBox(rt, "pod-xc-badkey", "../app")
		mustCreatePod(t, rt, box)
		if _, err := os.Lstat(filepath.Join(podHome(t, rt, box), xcodecache.Parts[0])); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("bad-key pod got a checkout: %v", err)
		}
	})
}

func wantSnapshot(t *testing.T, rt *Runtime, want string) {
	t.Helper()
	if got, _ := snapshotTag(t, rt); got != want {
		t.Fatalf("snapshot = %q, want %q", got, want)
	}
}

func deleteWithPhase(t *testing.T, rt *Runtime, box *runtimev1.PodBox, phase runtimev1.PodPhase) {
	t.Helper()
	rt.mu.Lock()
	p := rt.pods[box.GetPodId()]
	rt.mu.Unlock()
	if p == nil {
		t.Fatalf("pod %s not held", box.GetPodId())
	}
	p.mu.Lock()
	p.phase = phase
	p.mu.Unlock()
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: box.GetPodId()}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
}

func TestXcodeCachePublishAtDelete(t *testing.T) {
	t.Run("a pod that succeeded publishes its home", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		seedXcodeCache(t, rt, "old")
		box := xcodeCacheBox(rt, "pod-xc-pub", "app")
		mustCreatePod(t, rt, box)
		writeCacheParts(t, podHome(t, rt, box), "new")
		deleteWithPhase(t, rt, box, runtimev1.PodPhase_POD_PHASE_SUCCEEDED)
		wantSnapshot(t, rt, "new")
	})
	for name, phase := range map[string]runtimev1.PodPhase{
		"failed":  runtimev1.PodPhase_POD_PHASE_FAILED,
		"running": runtimev1.PodPhase_POD_PHASE_RUNNING,
	} {
		t.Run("a "+name+" pod never publishes", func(t *testing.T) {
			rt := xcodeCacheRuntime(t)
			seedXcodeCache(t, rt, "old")
			box := xcodeCacheBox(rt, "pod-xc-"+name, "app")
			mustCreatePod(t, rt, box)
			writeCacheParts(t, podHome(t, rt, box), "bad")
			deleteWithPhase(t, rt, box, phase)
			wantSnapshot(t, rt, "old")
		})
	}
	// A pod that swapped its home for a link gets nothing published through it.
	t.Run("a home replaced by a symlink never publishes", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		seedXcodeCache(t, rt, "old")
		box := xcodeCacheBox(rt, "pod-xc-link", "app")
		mustCreatePod(t, rt, box)
		elsewhere := t.TempDir()
		writeCacheParts(t, elsewhere, "stolen")
		home := podHome(t, rt, box)
		if err := os.RemoveAll(home); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, home); err != nil {
			t.Fatal(err)
		}
		deleteWithPhase(t, rt, box, runtimev1.PodPhase_POD_PHASE_SUCCEEDED)
		wantSnapshot(t, rt, "old")
	})
	// Deleting a pod this daemon does not hold publishes nothing.
	t.Run("an unknown pod publishes nothing", func(t *testing.T) {
		rt := xcodeCacheRuntime(t)
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-xc-unknown"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if _, ok := snapshotTag(t, rt); ok {
			t.Error("a snapshot appeared for an unknown pod")
		}
	})
}
