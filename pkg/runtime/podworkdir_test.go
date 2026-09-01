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
	"testing"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPodLaunchDefaultsWorkingDirToDataVolume is the pkg/runtime half of the
// B202 gate: the spawn seam's Dir. pkg/supervisor owns HONORING it
// (TestSpawnHonorsWorkingDir); only this package knows what a pod data volume
// is, so the DEFAULT is pinned here.
//
// The rule: the pod's working_dir wins, else the image config's
// (image.MergeRunSpec), else the POD DATA VOLUME — never "" , which the spawner
// reads as "inherit the daemon's cwd" and which the pod's own SBPL profile
// denies. Red before B202 on every row: Dir reached the spawner unset or
// unconsumed and every pod ran in the daemon's cwd.
func TestPodLaunchDefaultsWorkingDirToDataVolume(t *testing.T) {
	cases := []struct {
		name string
		// box builds the pod under test; want is derived from the runtime, so
		// it is returned alongside rather than written as a literal.
		box  func(t *testing.T, rt *Runtime, podID string) *runtimev1.PodBox
		want func(t *testing.T, rt *Runtime, podID string) string
	}{
		{
			name: "host binary, nothing set: the pod data volume",
			box:  func(t *testing.T, rt *Runtime, id string) *runtimev1.PodBox { return hostBinBox(rt, id) },
			want: func(t *testing.T, rt *Runtime, id string) string { return derivedRootfs(t, rt, id) },
		},
		{
			name: "host binary, pod working_dir set: honored verbatim",
			box: func(t *testing.T, rt *Runtime, id string) *runtimev1.PodBox {
				box := hostBinBox(rt, id)
				box.GetContainers()[0].WorkingDir = "/usr"
				return box
			},
			want: func(*testing.T, *Runtime, string) string { return "/usr" },
		},
		{
			name: "pulled image, nothing set: the pod data volume",
			box:  func(t *testing.T, rt *Runtime, id string) *runtimev1.PodBox { return pulledImageBox(t, rt, id) },
			want: func(t *testing.T, rt *Runtime, id string) string { return derivedRootfs(t, rt, id) },
		},
		{
			name: "pulled image, pod working_dir set: honored over the image's",
			box: func(t *testing.T, rt *Runtime, id string) *runtimev1.PodBox {
				box := pulledImageBox(t, rt, id)
				box.GetContainers()[0].WorkingDir = "/pod"
				return box
			},
			want: func(*testing.T, *Runtime, string) string { return "/pod" },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &fakeSpawner{}
			w := newBlockingWaiter()
			rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
			const podID = "pod-workdir"

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: tc.box(t, rt, podID)})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod returned error: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
			}
			if got, want := sp.lastSpec().Dir, tc.want(t, rt, podID); got != want {
				t.Errorf("SpawnSpec.Dir = %q, want %q", got, want)
			}
			if sp.lastSpec().Dir == "" {
				t.Error("SpawnSpec.Dir is empty: the pod would inherit the daemon's cwd, which its own profile denies")
			}
		})
	}

	// The image config's own WorkingDir reaches the seam when the pod sets none —
	// the merge (image.MergeRunSpec) already resolved that precedence, and the
	// point of this row is that the default does not overwrite it.
	t.Run("pulled image, image WorkingDir set: honored over the default", func(t *testing.T) {
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		up := &fakeUnpacker{runCfg: image.ImageRunConfig{WorkingDir: "/srv"}}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, Unpacker: up})
		const podID = "pod-imgworkdir"

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: pulledImageBox(t, rt, podID)})
		if err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("CreatePod returned error: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		if got := sp.lastSpec().Dir; got != "/srv" {
			t.Errorf("SpawnSpec.Dir = %q, want the image config's /srv", got)
		}
	})
}
