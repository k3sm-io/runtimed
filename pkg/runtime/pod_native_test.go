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
	"k3sm.io/runtimed/pkg/image"
)

// TestResolveBinaryNativeSentinel proves the "native" HostProcess sentinel runs
// command[0] as an absolute host binary and NEVER touches the registry — the M2
// conformance model (every nativePod uses Image: "native" + a command). Before the
// fix a native pod fell through to the pull path and failed on
// docker.io/library/native (UNAUTHORIZED), so every M2 criterion was RED.
func TestResolveBinaryNativeSentinel(t *testing.T) {
	pull := &fakePuller{}
	rt := newTestRuntime(t, Deps{Puller: pull})
	p := &pod{box: hostBinBox(rt, "pod-native"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	rootfs := "/var/lib/k3sm/pods/pod-native/rootfs"

	t.Run("runs command[0] as the host binary, skips the pull, flags hostBinary", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage, Command: []string{"/bin/sh", "-c", "echo ok"}}
		rb, err := rt.resolveBinary(context.Background(), p, rootfs, c)
		if err != nil {
			t.Fatalf("resolveBinary native: %v", err)
		}
		if rb.path != "/bin/sh" {
			t.Errorf("bin = %q, want /bin/sh", rb.path)
		}
		if want := []string{"/bin/sh", "-c", "echo ok"}; !slices.Equal(rb.argv, want) {
			t.Errorf("argv = %v, want %v", rb.argv, want)
		}
		// The decisive regression assertion: a native pod must never hit the registry.
		if pull.ref() != "" {
			t.Errorf("native pod pulled %q; the sentinel must skip the registry entirely", pull.ref())
		}
		// hostBinary must be true so gateSignature never ad-hoc re-signs /bin/sh.
		if !rb.hostBinary {
			t.Error("native binary must be flagged hostBinary=true (never ad-hoc re-signed)")
		}
	})

	t.Run("native image with no command is rejected", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage}
		if _, err := rt.resolveBinary(context.Background(), p, rootfs, c); err == nil {
			t.Fatal("want an error for a native image with no command")
		}
	})

	t.Run("native command that is not absolute is rejected", func(t *testing.T) {
		c := &runtimev1.Container{Name: "app", Image: NativeImage, Command: []string{"sh", "-c", "true"}}
		if _, err := rt.resolveBinary(context.Background(), p, rootfs, c); err == nil {
			t.Fatal("want an error for a relative native command path")
		}
	})
}

// TestResolveBinaryPullPolicyCarriesResolvedBackend proves a pull runs under the
// pod's RESOLVED sandbox backend, which is what image.PlatformPolicy.Backend is
// contractually defined to carry — not a constant that merely happens to be
// behaviourally equivalent today.
//
// A hardcoded stand-in is exact only while every native rung maps to the same
// image-platform candidate list. A future native rung that did not would be
// mis-selected through a VALID enum value, so the fail-closed default in
// image.Candidates could never fire — the failure would be silent, which is the
// class of bug B99 exists to remove.
func TestResolveBinaryPullPolicyCarriesResolvedBackend(t *testing.T) {
	backends := []runtimev1.SandboxBackend{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL,
	}
	for _, backend := range backends {
		t.Run(backend.String(), func(t *testing.T) {
			pull := &fakePuller{}
			rt := newTestRuntime(t, Deps{Puller: pull})
			p := &pod{box: hostBinBox(rt, "pod-policy"), backend: backend}
			c := &runtimev1.Container{Name: "app", Image: "example.com/app:v1", Command: []string{"/app"}}
			if _, err := rt.resolveBinary(context.Background(), p, "/var/lib/k3sm/pods/pod-policy/rootfs", c); err != nil {
				t.Fatalf("resolveBinary: %v", err)
			}
			pol := pull.policy()
			if pol.Backend != backend {
				t.Errorf("pull policy backend = %v, want the pod's resolved backend %v", pol.Backend, backend)
			}
			// Every native rung must still resolve to darwin/arm64 only: the
			// host-process spine runs Mach-O, and HostRosetta stays false even
			// though the capability probe now EXISTS (B103) — the pull path
			// deliberately does not consume it until the Seatbelt x Rosetta spawn
			// is proven (B105). This assertion is what keeps that decision honest.
			cands, err := image.Candidates(pol)
			if err != nil {
				t.Fatalf("pull policy has no candidates: %v", err)
			}
			if len(cands) != 1 || cands[0].OS != "darwin" || cands[0].Architecture != "arm64" {
				t.Errorf("candidates = %v, want [darwin/arm64/v8]", cands)
			}
		})
	}
}
