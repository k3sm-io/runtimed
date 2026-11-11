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
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// policyRecorder wraps an Unpacker and records the dialect of every
// MaterializeTree call.
type policyRecorder struct {
	Unpacker
	mu       sync.Mutex
	policies []image.UnpackPolicy
}

func (r *policyRecorder) MaterializeTree(ctx context.Context, mfst *runtimev1.ImageManifest, policy image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	r.mu.Lock()
	r.policies = append(r.policies, policy)
	r.mu.Unlock()
	return r.Unpacker.MaterializeTree(ctx, mfst, policy, dst)
}

func (r *policyRecorder) seen() []image.UnpackPolicy {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]image.UnpackPolicy(nil), r.policies...)
}

// TestNativeSpineNeverReceivesALinuxTree pins, at the seam where createPod picks
// the spine, that a linux-dialect tree (whose absolute symlinks only a guest
// chroot may resolve) never reaches the native spine's rootfs writers: volume
// materialization, image-volume links and the persistent-volume binder all run
// in createPod after the vm route has returned, over a rootfs whose only image
// tree comes from resolveBinary under unpackPolicy(p.backend).
//
// So the guard is behavioural in two halves: a vm-routed pod is handed to
// createVMPod (CreateVM runs) and materializes only under the linux dialect,
// and a pod that stays on the host-process route resolves to a native backend
// whose materialization is native.
func TestNativeSpineNeverReceivesALinuxTree(t *testing.T) {
	t.Run("vm_route_leaves_the_native_spine", func(t *testing.T) {
		const ref = "docker.io/library/alpine:3"
		w := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/bin/sleep"}}})
		rec := &policyRecorder{Unpacker: w}
		vmb := &fakeVMBackend{available: true, bootOK: true}
		cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Puller: w, Unpacker: rec})
		rt := newTestRuntimeCfg(t, cfg, d)

		p, _, err := rt.createPod(context.Background(), vmPodBox(rt, "pod-dialect-vm", 0))
		if err != nil {
			t.Fatalf("createPod: %v", err)
		}
		if p.backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
			t.Fatalf("pod backend = %v, want the vm backend", p.backend)
		}
		if n, _ := vmb.created(); n != 1 {
			t.Fatalf("CreateVM called %d times, want 1: the vm pod did not leave the host-process spine", n)
		}
		got := rec.seen()
		if len(got) == 0 {
			t.Fatal("the vm pod materialized no image; the guard would pass vacuously")
		}
		for _, pol := range got {
			if pol != image.LinuxUnpackPolicy() {
				t.Errorf("vm pod materialized under %+v, want the linux dialect", pol)
			}
		}
	})

	t.Run("host_route_materializes_natively", func(t *testing.T) {
		unpack := &fakeUnpacker{}
		pull := &fakePuller{manifest: &runtimev1.ImageManifest{
			Reference: "example.com/app:v1",
			Config:    &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')},
		}}
		rt := newTestRuntime(t, Deps{Puller: pull, Unpacker: unpack})
		box := hostBinBox(rt, "pod-dialect-host")

		p, _, err := rt.createPod(context.Background(), box)
		if err != nil {
			t.Fatalf("createPod: %v", err)
		}
		if p.backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
			t.Fatalf("host-process pod resolved to the vm backend")
		}
		// createPod's own containers name host binaries; drive the image route
		// over the pod createPod built, so the backend under test is the one
		// selection recorded rather than one the test chose.
		before, _, _ := unpack.observed()
		rootfs := derivedRootfs(t, rt, "pod-dialect-host")
		c := &runtimev1.Container{Name: "img", Image: "example.com/app:v1", Command: []string{"bin/app"}}
		if _, err := rt.resolveBinary(context.Background(), p, rootfs, c); err != nil {
			t.Fatalf("resolveBinary: %v", err)
		}
		calls, policy, dst := unpack.observed()
		if calls != before+1 {
			t.Fatalf("MaterializeTree called %d times, want 1", calls-before)
		}
		if policy != image.NativeUnpackPolicy() {
			t.Errorf("host-process pod materialized under %+v into %s, want the native dialect", policy, dst)
		}
	})
}
