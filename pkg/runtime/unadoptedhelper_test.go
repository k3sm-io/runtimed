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
)

// unadoptedFakeVMBackend is fakeVMBackend with the unadoptedHelperProber
// capability: it reports a live, unowned helper for the pod ids in live.
type unadoptedFakeVMBackend struct {
	*fakeVMBackend
	live map[string]int
}

func (b *unadoptedFakeVMBackend) UnadoptedHelper(podID string) (int, bool) {
	pid, ok := b.live[podID]
	return pid, ok
}

// TestCreatePodRefusesAnyBackendBesideAnUnadoptedHelper pins that the refusal
// beside a live unadopted helper is keyed by the pod id alone: a create for
// that id naming a non-vm backend would otherwise write into, and on failure
// remove, the directory the live guest's rootfs lives in.
func TestCreatePodRefusesAnyBackendBesideAnUnadoptedHelper(t *testing.T) {
	const podID = "pod-unadopted"
	for _, backend := range []runtimev1.SandboxBackend{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC,
	} {
		t.Run(backend.String(), func(t *testing.T) {
			vmb := &unadoptedFakeVMBackend{
				fakeVMBackend: &fakeVMBackend{available: true},
				live:          map[string]int{podID: 4242},
			}
			rt := newTestRuntime(t, Deps{VMBackend: vmb})

			podDir, err := rt.podDir(podID)
			if err != nil {
				t.Fatal(err)
			}
			rootfs := filepath.Join(podDir, "rootfs")
			if err := os.MkdirAll(rootfs, 0o755); err != nil {
				t.Fatal(err)
			}
			guestMarker := filepath.Join(rootfs, "guest-marker")
			podMarker := filepath.Join(podDir, "pod-marker")
			for _, p := range []string{guestMarker, podMarker} {
				if err := os.WriteFile(p, []byte("live"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			box := hostBinBox(rt, podID)
			box.SandboxProfile.Backend = backend
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if !errors.Is(err, ErrVMHelperUnadoptable) {
				t.Fatalf("CreatePod = (%v, %v), want ErrVMHelperUnadoptable", resp, err)
			}
			if _, ok := rt.lookupPod(podID); ok {
				t.Error("the refused pod was registered")
			}
			for _, p := range []string{guestMarker, podMarker} {
				if b, err := os.ReadFile(p); err != nil || string(b) != "live" {
					t.Errorf("%s = (%q, %v), want it untouched", p, b, err)
				}
			}
			vmb.mu.Lock()
			n := vmb.createCalls
			vmb.mu.Unlock()
			if n != 0 {
				t.Errorf("CreateVM called %d times beside the live helper", n)
			}
		})
	}
}
