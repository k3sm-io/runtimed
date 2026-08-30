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
	"slices"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const testShim = "/Library/k3sm/libk3sm_pathrebase_shim.dylib"

func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

// mustEnvValue fails the test when key is absent, so a comparison against an
// expected path cannot silently pass on "" == "" if injection stopped happening.
func mustEnvValue(t *testing.T, env []string, key string) string {
	t.Helper()
	v, ok := envValue(env, key)
	if !ok {
		t.Fatalf("env %s not set; env = %v", key, env)
	}
	return v
}

// mountingBox builds a mounting host-binary box whose rootfs_path is the
// runtime's OWN derived pod data volume. It was a hard-coded /var/lib/k3sm/...
// literal, which B140 now refuses: rootfs_path must be byte-equal to the
// derivation, and a literal cannot match a test runtime's temp-dir cache root.
func mountingBox(t *testing.T, rt *Runtime, podID string, mountPaths ...string) (*runtimev1.PodBox, *runtimev1.Container) {
	t.Helper()
	box := hostBinBox(rt, podID)
	box.RootfsPath = derivedRootfs(t, rt, podID)
	c := box.GetContainers()[0]
	for _, mp := range mountPaths {
		c.VolumeMounts = append(c.VolumeMounts, &runtimev1.VolumeMount{Name: "v", MountPath: mp})
	}
	return box, c
}

// TestContainerEnvPathShim proves the path-rebase shim + its K3SM_ROOTFS /
// K3SM_MOUNT_PATHS config are injected for a mounting container, so an absolute
// volume mount resolves under the pod data volume.
func TestContainerEnvPathShim(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim
	box, _ := mountingBox(t, rt, "pod-1", "/etc/nats", "/scratch")
	c := box.GetContainers()[0]

	env := mustEnv(t, rt, box, c)
	if got, want := mustEnvValue(t, env, pathShimRootfsEnv), derivedRootfs(t, rt, "pod-1"); got != want {
		t.Errorf("%s = %q, want the derived pod rootfs %q", pathShimRootfsEnv, got, want)
	}
	if got, _ := envValue(env, pathShimMountsEnv); got != "/etc/nats:/scratch" {
		t.Errorf("%s = %q, want /etc/nats:/scratch", pathShimMountsEnv, got)
	}
	dyld, ok := envValue(env, dyldInsertEnv)
	if !ok || !strings.Contains(dyld, testShim) {
		t.Errorf("%s = %q, want it to include the path shim %q", dyldInsertEnv, dyld, testShim)
	}
}

// TestContainerEnvPathShimWithDNS proves the path shim and the DNS shim coexist in
// DYLD_INSERT_LIBRARIES (colon-joined) when a mounting pod also carries the DNS
// annotation.
func TestContainerEnvPathShimWithDNS(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim
	box, _ := mountingBox(t, rt, "pod-2", "/etc/nats")
	box.Annotations = map[string]string{dyldInsertAnnotation: "/opt/k3sm/libdnsshim.dylib"}
	c := box.GetContainers()[0]

	dyld, _ := envValue(mustEnv(t, rt, box, c), dyldInsertEnv)
	got := strings.Split(dyld, ":")
	want := []string{testShim, "/opt/k3sm/libdnsshim.dylib"}
	if !slices.Equal(got, want) {
		t.Errorf("DYLD_INSERT_LIBRARIES = %v, want %v", got, want)
	}
}

// TestContainerEnvNoShimWhenNoMounts / disabled: no rebase env or insert when the
// container mounts nothing, or the shim is not configured.
func TestContainerEnvNoShimWhenNoMounts(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim
	box, _ := mountingBox(t, rt, "pod-3") // no mounts
	c := box.GetContainers()[0]

	env := mustEnv(t, rt, box, c)
	if _, ok := envValue(env, pathShimMountsEnv); ok {
		t.Error("no volume mounts: must not set K3SM_MOUNT_PATHS")
	}
	if _, ok := envValue(env, dyldInsertEnv); ok {
		t.Error("no volume mounts + no DNS annotation: must not set DYLD_INSERT_LIBRARIES")
	}

	rt.cfg.PathShimPath = "" // disabled
	box2, _ := mountingBox(t, rt, "pod-4", "/etc/nats")
	if _, ok := envValue(mustEnv(t, rt, box2, box2.GetContainers()[0]), pathShimMountsEnv); ok {
		t.Error("PathShimPath empty: must not inject the rebase env")
	}
}

// TestContainerEnvExplicitDyldWins proves a container that sets its own
// DYLD_INSERT_LIBRARIES opts out of shim injection (no override).
func TestContainerEnvExplicitDyldWins(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim
	box, c := mountingBox(t, rt, "pod-5", "/etc/nats")
	c.Env = []*runtimev1.EnvVar{{Name: dyldInsertEnv, Value: "/custom.dylib"}}

	dyld, _ := envValue(mustEnv(t, rt, box, c), dyldInsertEnv)
	if dyld != "/custom.dylib" {
		t.Errorf("explicit DYLD must win: got %q", dyld)
	}
	if _, ok := envValue(mustEnv(t, rt, box, c), pathShimMountsEnv); ok {
		t.Error("explicit DYLD opts out: must not inject K3SM_MOUNT_PATHS")
	}
}

// TestContainerEnvKeepsEntriesAfterDYLD is the B205 regression gate: an
// explicit DYLD_INSERT_LIBRARIES entry mid-slice must not truncate the base
// env at that point — every entry before AND after it must survive, in
// order, and the injected-annotation (non-explicit) DYLD path must still
// carry the whole base too. Asserts the full resulting slice, not membership.
func TestContainerEnvKeepsEntriesAfterDYLD(t *testing.T) {
	t.Run("explicit spec DYLD preserves entries before and after it", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		box, c := mountingBox(t, rt, "pod-6")
		c.Env = []*runtimev1.EnvVar{
			{Name: "A", Value: "1"},
			{Name: dyldInsertEnv, Value: "/custom.dylib"},
			{Name: "B", Value: "2"},
		}

		env := mustEnv(t, rt, box, c)
		want := []string{
			tmpDirEnv + "=" + podTmpDir(derivedRootfs(t, rt, "pod-6")),
			"A=1",
			dyldInsertEnv + "=/custom.dylib",
			"B=2",
		}
		if !slices.Equal(env, want) {
			t.Errorf("containerEnv = %v, want %v", env, want)
		}
	})

	t.Run("no DYLD entry: base order unchanged", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		box, c := mountingBox(t, rt, "pod-7")
		c.Env = []*runtimev1.EnvVar{
			{Name: "A", Value: "1"},
			{Name: "B", Value: "2"},
		}

		env := mustEnv(t, rt, box, c)
		want := []string{
			tmpDirEnv + "=" + podTmpDir(derivedRootfs(t, rt, "pod-7")),
			"A=1",
			"B=2",
		}
		if !slices.Equal(env, want) {
			t.Errorf("containerEnv = %v, want %v", env, want)
		}
	})

	t.Run("annotation-injected DYLD (not explicit) still carries the whole base", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		box, c := mountingBox(t, rt, "pod-8")
		box.Annotations = map[string]string{dyldInsertAnnotation: "/opt/k3sm/libdnsshim.dylib"}
		c.Env = []*runtimev1.EnvVar{
			{Name: "A", Value: "1"},
			{Name: "B", Value: "2"},
		}

		env := mustEnv(t, rt, box, c)
		want := []string{
			tmpDirEnv + "=" + podTmpDir(derivedRootfs(t, rt, "pod-8")),
			"A=1",
			"B=2",
			dyldInsertEnv + "=/opt/k3sm/libdnsshim.dylib",
		}
		if !slices.Equal(env, want) {
			t.Errorf("containerEnv = %v, want %v", env, want)
		}
	})
}

// mustEnv is a test helper: containerEnv now returns an error because the
// path-rebase shim's rootfs is derived from a validated pod id, and a test that
// silently dropped that error would hide a rejected id behind an empty env.
func mustEnv(t *testing.T, rt *Runtime, box *runtimev1.PodBox, c *runtimev1.Container) []string {
	t.Helper()
	env, err := rt.containerEnv(box, c, nil)
	if err != nil {
		t.Fatalf("containerEnv: %v", err)
	}
	return env
}
