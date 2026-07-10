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
	"slices"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestResolveBinaryNativeSentinel proves the "native" HostProcess sentinel runs
// command[0] as an absolute host binary and NEVER touches the registry — the M2
// conformance model (every nativePod uses Image: "native" + a command). Before the
// fix a native pod fell through to the pull path and failed on
// docker.io/library/native (UNAUTHORIZED), so every M2 criterion was RED.
func TestResolveBinaryNativeSentinel(t *testing.T) {
	pull := &fakePuller{}
	rt := newTestRuntime(t, Deps{Puller: pull})
	box := hostBinBox("pod-native")
	rootfs := "/var/lib/k3sm/pods/pod-native/rootfs"

	t.Run("runs command[0] as the host binary, skips the pull", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage, Command: []string{"/bin/sh", "-c", "echo ok"}}
		bin, argv, err := rt.resolveBinary(context.Background(), box, rootfs, c)
		if err != nil {
			t.Fatalf("resolveBinary native: %v", err)
		}
		if bin != "/bin/sh" {
			t.Errorf("bin = %q, want /bin/sh", bin)
		}
		if want := []string{"/bin/sh", "-c", "echo ok"}; !slices.Equal(argv, want) {
			t.Errorf("argv = %v, want %v", argv, want)
		}
		// The decisive regression assertion: a native pod must never hit the registry.
		if pull.ref() != "" {
			t.Errorf("native pod pulled %q; the sentinel must skip the registry entirely", pull.ref())
		}
	})

	t.Run("native image with no command is rejected", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage}
		if _, _, err := rt.resolveBinary(context.Background(), box, rootfs, c); err == nil {
			t.Fatal("want an error for a native image with no command")
		}
	})

	t.Run("native command that is not absolute is rejected", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage, Command: []string{"sh", "-c", "true"}}
		if _, _, err := rt.resolveBinary(context.Background(), box, rootfs, c); err == nil {
			t.Fatal("want an error for a relative native command path")
		}
	})
}
