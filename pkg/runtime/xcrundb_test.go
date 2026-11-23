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
	"strings"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// xcrunProbeSpawner records each spawn's env and whether the directory the
// xcrun_db value lives in existed at that moment.
type xcrunProbeSpawner struct {
	mu    sync.Mutex
	next  int
	specs []supervisor.SpawnSpec
	found []bool
}

func (f *xcrunProbeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	spec, err := podEnvSpawn(spec)
	if err != nil {
		return 0, err
	}
	f.specs = append(f.specs, spec)
	ok := false
	if v, has := envValue(spec.Env, xcrunDBEnv); has {
		if fi, err := os.Stat(filepath.Dir(v)); err == nil && fi.IsDir() && fi.Mode().Perm() == 0o700 {
			ok = true
		}
	}
	f.found = append(f.found, ok)
	f.next++
	return 4000 + f.next, nil
}

func (f *xcrunProbeSpawner) last(t *testing.T) (supervisor.SpawnSpec, bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		t.Fatal("no spawn recorded")
	}
	return f.specs[len(f.specs)-1], f.found[len(f.found)-1]
}

// TestPodLaunchEnvCarriesXcrunDBInDataVolume pins the xcrun cache file env.
// xcrun is a platform binary: it ignores DIRHELPER_USER_DIR_SUFFIX and loses
// the path-rebase shim, so confstr hands it the daemon uid's shared
// /var/folders temp tree, which the profile denies, and it warns "couldn't
// create cache file" on every run. libxcrun reads an absolute xcrun_db for
// the cache path, and the plain environment survives into a platform binary.
func TestPodLaunchEnvCarriesXcrunDBInDataVolume(t *testing.T) {
	t.Run("injected, inside the data volume, its dir made 0700 before the spawn", func(t *testing.T) {
		sp := &xcrunProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-xcrun"
		mustCreatePod(t, rt, hostBinBox(rt, podID))

		spec, found := sp.last(t)
		dataVol := derivedRootfs(t, rt, podID)
		got := mustEnvValue(t, spec.Env, xcrunDBEnv)
		if got != podXcrunDB(dataVol) {
			t.Errorf("%s = %q, want %q", xcrunDBEnv, got, podXcrunDB(dataVol))
		}
		if !filepath.IsAbs(got) || !strings.HasPrefix(got, dataVol+"/") {
			t.Errorf("%s = %q is not an absolute path inside the data volume %q", xcrunDBEnv, got, dataVol)
		}
		if filepath.Dir(got) != podTmpDir(dataVol) {
			t.Errorf("%s = %q is not in the pod temp dir %q", xcrunDBEnv, got, podTmpDir(dataVol))
		}
		if !found {
			t.Errorf("the directory of %s=%q did not exist with mode 0700 at the spawn", xcrunDBEnv, got)
		}
		if n := countName(spec.Env, xcrunDBEnv); n != 1 {
			t.Errorf("%s appears %d times, want 1", xcrunDBEnv, n)
		}
	})

	t.Run("a spec-set value wins, exactly once", func(t *testing.T) {
		sp := &xcrunProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-xcrun-own"
		box := hostBinBox(rt, podID)
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: xcrunDBEnv, Value: "/spec/xcrun_db"}}
		mustCreatePod(t, rt, box)

		spec, _ := sp.last(t)
		if got := mustEnvValue(t, spec.Env, xcrunDBEnv); got != "/spec/xcrun_db" {
			t.Errorf("%s = %q, want the spec's own value", xcrunDBEnv, got)
		}
		if n := countName(spec.Env, xcrunDBEnv); n != 1 {
			t.Errorf("%s appears %d times, want 1: %v", xcrunDBEnv, n, spec.Env)
		}
	})
}
