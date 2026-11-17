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
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/supervisor"
)

// onNodeVolume is a runtime whose work-dir is its own volume, mounted at
// /private/var/lib/k3sm, as on a node.
func onNodeVolume(t *testing.T) *Runtime {
	t.Helper()
	rt := newTestRuntime(t, Deps{VolumeMountPoint: func(string) (string, error) { return "/private/var/lib/k3sm", nil }})
	rt.cfg.PathShimPath = testShim
	return rt
}

// TestContainerEnvRebasesSharedReplacementDir proves a container with no volume
// mount still loads the path-rebase shim when the pods live on their own
// volume, configured to rebase only that volume's shared .TemporaryItems; a
// mounting container gets the prefix after its mounts, and a shadow-only node
// now turns the rebase on as well. The restricted-child report stays tied to a
// volume mount.
func TestContainerEnvRebasesSharedReplacementDir(t *testing.T) {
	const shared = "/private/var/lib/k3sm/.TemporaryItems"

	t.Run("no mounts", func(t *testing.T) {
		rt := onNodeVolume(t)
		box, c := mountingBox(t, rt, "pod-1")
		env := mustEnv(t, rt, box, c)
		if got, want := mustEnvValue(t, env, pathShimRootfsEnv), derivedRootfs(t, rt, "pod-1"); got != want {
			t.Errorf("%s = %q, want %q", pathShimRootfsEnv, got, want)
		}
		if got := mustEnvValue(t, env, pathShimMountsEnv); got != shared {
			t.Errorf("%s = %q, want only the shared replacement dir", pathShimMountsEnv, got)
		}
		if dyld := mustEnvValue(t, env, dyldInsertEnv); !strings.Contains(dyld, testShim) {
			t.Errorf("%s = %q, want the path shim", dyldInsertEnv, dyld)
		}
		if v, ok := envValue(env, supervisor.ChildReportEnv); ok {
			t.Errorf("child report %q set for a container with no volume mount", v)
		}
	})
	t.Run("with mounts", func(t *testing.T) {
		rt := onNodeVolume(t)
		box, c := mountingBox(t, rt, "pod-2", "/etc/nats")
		env := mustEnv(t, rt, box, c)
		if got := mustEnvValue(t, env, pathShimMountsEnv); got != "/etc/nats:"+shared {
			t.Errorf("%s = %q, want the mount then the shared replacement dir", pathShimMountsEnv, got)
		}
		if _, ok := envValue(env, supervisor.ChildReportEnv); !ok {
			t.Error("child report missing for a mounting container")
		}
	})
	t.Run("shadow set, no mounts", func(t *testing.T) {
		rt := onNodeVolume(t)
		rt.cfg.ShadowBinDir = "/Library/k3sm/shadow"
		box, c := mountingBox(t, rt, "pod-3")
		env := mustEnv(t, rt, box, c)
		if got := mustEnvValue(t, env, pathShimMountsEnv); got != shared {
			t.Errorf("%s = %q, want the shared replacement dir", pathShimMountsEnv, got)
		}
		if n := strings.Count(mustEnvValue(t, env, dyldInsertEnv), testShim); n != 1 {
			t.Errorf("the shim is inserted %d times, want once", n)
		}
	})
	t.Run("work volume unknown", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{VolumeMountPoint: func(string) (string, error) { return "", errUserDirsOffInTests }})
		rt.cfg.PathShimPath = testShim
		box, c := mountingBox(t, rt, "pod-4")
		if v, ok := envValue(mustEnv(t, rt, box, c), pathShimMountsEnv); ok {
			t.Errorf("%s = %q with the work volume unknown", pathShimMountsEnv, v)
		}
	})
	t.Run("no shim configured", func(t *testing.T) {
		rt := onNodeVolume(t)
		rt.cfg.PathShimPath = ""
		box, c := mountingBox(t, rt, "pod-5")
		if v, ok := envValue(mustEnv(t, rt, box, c), pathShimMountsEnv); ok {
			t.Errorf("%s = %q with no shim configured", pathShimMountsEnv, v)
		}
	})
}
