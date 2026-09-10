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
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// testDevDir is a valid DEVELOPER_DIR for the generator: absolute, clean, based
// "Developer", outside every protected tree. Validation is lexical, so the path
// need not exist on the host running the test — which is the property that
// keeps this gate deterministic on a machine with no Xcode.
const testDevDir = "/Applications/Xcode.app/Contents/Developer"

// TestPodLaunchEnvCarriesTheGrantedDeveloperDir is the gate on the injection
// that makes the toolchain grant reachable.
//
// The grant was inert before it: sandbox.Generate emitted a stanza rooted at
// the pod's xcode_toolchain_dir, and nothing ever told the pod which directory
// that was. The toolchain shims' own fallback reads /var/db/xcode_select_link,
// which the pod profile denies, so an annotated pod on an Xcode node either
// resolved to the Command Line Tools or failed to resolve at all — and the
// profile it was running under looked perfectly correct either way.
//
// It captures what pod.go ITSELF computed, through the spawner seam, rather
// than hand-setting the variable and running a compiler. An execution test that
// sets DEVELOPER_DIR itself passes identically whether or not this injection
// exists (pkg/sandbox's TestXcodeToolchainGrantReachesTheToolchain does exactly
// that, and was green throughout the period this bug shipped), so it cannot be
// the gate on the injection.
func TestPodLaunchEnvCarriesTheGrantedDeveloperDir(t *testing.T) {
	t.Run("a granted toolchain dir reaches the launch env", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-dd"

		box := hostBinBox(rt, podID)
		box.GetSandboxProfile().XcodeToolchainDir = testDevDir
		mustCreatePod(t, rt, box)

		spec, _, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, developerDirEnv); got != testDevDir {
			t.Errorf("%s = %q, want the granted %q", developerDirEnv, got, testDevDir)
		}
		if n := countName(spec.Env, developerDirEnv); n != 1 {
			t.Errorf("%s appears %d times in the launch env, want exactly 1: %v", developerDirEnv, n, spec.Env)
		}
	})

	// The negative direction is half the gate: injecting a developer dir into
	// every pod would hand an unannotated pod a variable naming a tree its own
	// profile does not grant, and the toolchain's failure mode there is a
	// resolution error rather than the silent fallback it has with no variable
	// at all. Absence must be absence of the KEY, not an empty value.
	t.Run("a pod with no grant carries no developer dir at all", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-dd-none"

		mustCreatePod(t, rt, hostBinBox(rt, podID))

		spec, _, _ := sp.last()
		if got, has := envValue(spec.Env, developerDirEnv); has {
			t.Errorf("%s=%q is in the launch env of a pod with no xcode_toolchain_dir", developerDirEnv, got)
		}
	})

	// A pulled image takes the same path through containerEnv, over the merged
	// image-config base rather than the container's own EnvVars — the seam where
	// an injection that only handled the host-binary route would be missed.
	t.Run("a pulled image gets it too", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-dd-img"

		box := pulledImageBox(t, rt, podID)
		box.GetSandboxProfile().XcodeToolchainDir = testDevDir
		mustCreatePod(t, rt, box)

		spec, _, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, developerDirEnv); got != testDevDir {
			t.Errorf("%s = %q, want the granted %q", developerDirEnv, got, testDevDir)
		}
	})

	// Spec beats injection, the same house rule TMPDIR, the module cache and
	// DYLD_INSERT_LIBRARIES follow. A Swift build image that bakes its own
	// DEVELOPER_DIR keeps it — and keeps it exactly once, since a duplicate key
	// leaves which one wins to the child's environment implementation.
	t.Run("a spec-set developer dir wins, exactly once", func(t *testing.T) {
		sp := &mcProbeSpawner{}
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: newBlockingWaiter()})
		const podID = "pod-dd-own"

		box := hostBinBox(rt, podID)
		box.GetSandboxProfile().XcodeToolchainDir = testDevDir
		box.GetContainers()[0].Env = []*runtimev1.EnvVar{{Name: developerDirEnv, Value: "/spec/Developer"}}
		mustCreatePod(t, rt, box)

		spec, _, _ := sp.last()
		if got := mustEnvValue(t, spec.Env, developerDirEnv); got != "/spec/Developer" {
			t.Errorf("%s = %q, want the spec's own /spec/Developer", developerDirEnv, got)
		}
		if n := countName(spec.Env, developerDirEnv); n != 1 {
			t.Errorf("%s appears %d times in the launch env, want exactly 1: %v", developerDirEnv, n, spec.Env)
		}
	})
}
