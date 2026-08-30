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
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// tmpProbeSpawner is a fakeSpawner that additionally records, AT THE MOMENT OF
// THE SPAWN, whether the directory a spec's TMPDIR names already exists and what
// its permissions are. Checking after CreatePod returns would not distinguish
// "provisioned before the pod ran" from "provisioned too late to be usable",
// which is the whole ordering B203 is about.
type tmpProbeSpawner struct {
	mu       sync.Mutex
	next     int
	specs    []supervisor.SpawnSpec
	tmpModes []os.FileMode
	tmpFound []bool
}

func (f *tmpProbeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.specs = append(f.specs, spec)
	found, mode := false, os.FileMode(0)
	if dir, ok := envValue(spec.Env, tmpDirEnv); ok {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			found, mode = true, fi.Mode().Perm()
		}
	}
	f.tmpFound = append(f.tmpFound, found)
	f.tmpModes = append(f.tmpModes, mode)
	f.next++
	return 2000 + f.next, nil
}

func (f *tmpProbeSpawner) last() (supervisor.SpawnSpec, bool, os.FileMode) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.specs)
	if n == 0 {
		return supervisor.SpawnSpec{}, false, 0
	}
	return f.specs[n-1], f.tmpFound[n-1], f.tmpModes[n-1]
}

// TestPodLaunchEnvCarriesTmpInDataVolume is the B203 gate.
//
// A confined pod has no usable temp directory: the profile write-allows neither
// /tmp nor /var/tmp and nothing set TMPDIR, so a workload that asks the platform
// for one exhausts its candidate list and dies before its own code runs (the M8
// lab failure). runtimed now provisions <podDataVolume>/tmp and names it in
// TMPDIR for every container — and, because the data volume is already the
// profile's read/write scope, with no SBPL change at all.
func TestPodLaunchEnvCarriesTmpInDataVolume(t *testing.T) {
	t.Run("injected into the launch env, and the dir exists pre-spawn", func(t *testing.T) {
		sp := &tmpProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-tmp"

		mustCreatePod(t, rt, hostBinBox(rt, podID))

		spec, found, mode := sp.last()
		want := podTmpDir(derivedRootfs(t, rt, podID))
		got := mustEnvValue(t, spec.Env, tmpDirEnv)
		if got != want {
			t.Errorf("%s = %q, want %q inside the pod data volume", tmpDirEnv, got, want)
		}
		if !found {
			t.Errorf("%s=%q did not exist at the moment of the spawn", tmpDirEnv, got)
		}
		if mode != 0o700 {
			t.Errorf("pod tmp dir mode = %#o, want 0700", mode)
		}
	})

	t.Run("a pulled image gets it too", func(t *testing.T) {
		sp := &tmpProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-tmp-img"

		mustCreatePod(t, rt, pulledImageBox(t, rt, podID))

		spec, found, _ := sp.last()
		if got, want := mustEnvValue(t, spec.Env, tmpDirEnv), podTmpDir(derivedRootfs(t, rt, podID)); got != want {
			t.Errorf("%s = %q, want %q", tmpDirEnv, got, want)
		}
		if !found {
			t.Error("pod tmp dir did not exist at the moment of the spawn")
		}
	})

	t.Run("a spec-set TMPDIR wins", func(t *testing.T) {
		sp := &tmpProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-tmp-own"

		box := hostBinBox(rt, podID)
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: tmpDirEnv, Value: "/spec/tmp"}}
		mustCreatePod(t, rt, box)

		spec, _, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, tmpDirEnv); got != "/spec/tmp" {
			t.Errorf("%s = %q, want the spec's own /spec/tmp", tmpDirEnv, got)
		}
		// Exactly one TMPDIR: an injection that appended alongside the spec's
		// would leave which one wins to whichever end of environ getenv walks.
		if n := countName(spec.Env, tmpDirEnv); n != 1 {
			t.Errorf("%s appears %d times in the launch env, want exactly 1: %v", tmpDirEnv, n, spec.Env)
		}
	})

	// The provisioned directory is the pod's own, inside the data volume the
	// profile already write-allows — so no SBPL rule had to change. Asserting
	// containment is what keeps a future "simplification" from pointing TMPDIR at
	// a shared path the profile denies.
	t.Run("the dir is inside the pod data volume", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
		const podID = "pod-tmp-scope"
		rootfs := derivedRootfs(t, rt, podID)
		if got, want := podTmpDir(rootfs), rootfs+"/"+podTmpDirName; got != want {
			t.Errorf("podTmpDir = %q, want %q", got, want)
		}
	})
}

// countName counts the "name=..." entries in env.
func countName(env []string, name string) int {
	n := 0
	for _, e := range env {
		if _, ok := envValue([]string{e}, name); ok {
			n++
		}
	}
	return n
}
