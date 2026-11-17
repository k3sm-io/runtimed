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

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestImagePodAbsoluteImagePathResolvesUnderRootfs is the gate for reaching
// absolute image paths. A native pod has no chroot, so an absolute path naming
// the image's own tree (PYTHONPATH=/app) is the host's; the runtime now exports
// the image root as K3SM_IMAGE_ROOT to every pulled-image container, mounts or
// not: the pod rootfs the image is unpacked into, so a workload builds
// $K3SM_IMAGE_ROOT/app and reaches the image's file. The value is
// runtime-owned: a spec value for it is dropped, and a host-binary container
// (no image tree) gets none.
func TestImagePodAbsoluteImagePathResolvesUnderRootfs(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	rt.cfg.PathShimPath = testShim

	imageBox := func(podID string, mounts ...string) (*runtimev1.PodBox, *runtimev1.Container) {
		box, c := mountingBox(t, rt, podID, mounts...)
		c.Image = "registry.example/parcel-runtime:1"
		c.Command = []string{"/python/bin/python3.13"}
		return box, c
	}
	spoofed := []*runtimev1.EnvVar{
		{Name: imageRootEnv, Value: "/etc"},
		{Name: "PYTHONPATH", Value: "/app"},
	}
	count := func(env []string, key string) int {
		n := 0
		for _, e := range env {
			if k, _, _ := strings.Cut(e, "="); k == key {
				n++
			}
		}
		return n
	}

	t.Run("the exported root is the rootfs the image is unpacked into", func(t *testing.T) {
		box, c := imageBox("pod-imgroot-1")
		c.Env = append(c.Env, spoofed...)
		env := mustEnv(t, rt, box, c)
		root := mustEnvValue(t, env, imageRootEnv)
		if want := derivedRootfs(t, rt, "pod-imgroot-1"); root != want {
			t.Fatalf("%s = %q, want the derived pod rootfs %q", imageRootEnv, root, want)
		}
		if n := count(env, imageRootEnv); n != 1 {
			t.Fatalf("%s appears %d times, want once (the runtime's): %v", imageRootEnv, n, env)
		}
		// The root is not the shim's activation knob: with no mount the
		// shim stays unconfigured.
		for _, k := range []string{pathShimRootfsEnv, pathShimMountsEnv} {
			if v, ok := envValue(env, k); ok {
				t.Errorf("%s = %q with no mount", k, v)
			}
		}
		if v, _ := envValue(env, "PYTHONPATH"); v != "/app" {
			t.Errorf("PYTHONPATH = %q, want the spec's own value untouched", v)
		}
	})

	t.Run("with mounts the root is the same", func(t *testing.T) {
		box, c := imageBox("pod-imgroot-2", "/data")
		c.Env = append(c.Env, spoofed...)
		env := mustEnv(t, rt, box, c)
		want := derivedRootfs(t, rt, "pod-imgroot-2")
		if got := mustEnvValue(t, env, imageRootEnv); got != want {
			t.Errorf("%s = %q, want %q", imageRootEnv, got, want)
		}
		if got := mustEnvValue(t, env, pathShimRootfsEnv); got != want {
			t.Errorf("%s = %q, want %q", pathShimRootfsEnv, got, want)
		}
		if n := count(env, imageRootEnv); n != 1 {
			t.Errorf("%s appears %d times, want once: %v", imageRootEnv, n, env)
		}
	})

	t.Run("an explicit DYLD_INSERT_LIBRARIES still gets the image root", func(t *testing.T) {
		box, c := imageBox("pod-imgroot-3")
		c.Env = append(c.Env, &runtimev1.EnvVar{Name: dyldInsertEnv, Value: "/custom.dylib"})
		if got := mustEnvValue(t, mustEnv(t, rt, box, c), imageRootEnv); got != derivedRootfs(t, rt, "pod-imgroot-3") {
			t.Errorf("%s = %q", imageRootEnv, got)
		}
	})

	t.Run("a host-binary container has no image root", func(t *testing.T) {
		box, c := mountingBox(t, rt, "pod-imgroot-4")
		c.Env = append(c.Env, &runtimev1.EnvVar{Name: imageRootEnv, Value: "/etc"})
		if v, ok := envValue(mustEnv(t, rt, box, c), imageRootEnv); ok {
			t.Errorf("%s = %q on a host-binary container", imageRootEnv, v)
		}
	})
}
