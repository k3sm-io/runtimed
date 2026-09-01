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
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// vmPVCBox is a vm-routed pod with one local-path PVC, the shape that failed on
// the rig: postgres with its data directory on a claim.
func vmPVCBox(rt *Runtime, podID, claim string) *runtimev1.PodBox {
	box := vmPodBox(rt, podID, 0)
	box.Volumes = []*runtimev1.Volume{{
		Name:                  "data",
		PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: claim},
	}}
	box.Containers[0].VolumeMounts = []*runtimev1.VolumeMount{
		{Name: "data", MountPath: "/var/lib/postgresql/data"},
	}
	return box
}

// TestCreateVMPodProvisionsPersistentVolumes is the gate on a vm pod that could
// not boot at all with a PVC attached. Verbatim from the pod event:
//
//	vm host failed: start the virtual machine: virtiofs share "k3sm.pvc0"
//	(/var/lib/k3sm/storage/default/pgdata): stat …: no such file or directory
//
// volume.Binder.Bind is called from the host-process spine only, so nothing ever
// created the claim's stable dir; the share plan rooted a k3sm.pvc0 device at a
// path that did not exist and VZ refused the machine before it started.
func TestCreateVMPodProvisionsPersistentVolumes(t *testing.T) {
	t.Run("the-claim-dir-exists-before-the-machine-is-built", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		box := vmPVCBox(rt, "pod-pvc", "pgdata")
		spec := mustPlanVM(t, rt, vmb, box)

		// Derived from Config.Root + the documented layout, not from the same
		// binder the production path used.
		want := filepath.Join(rt.cfg.Root, "storage", "default", "pgdata")
		share := findVMShare(t, spec, mount.ShareTagPVCPrefix+"0")
		if share.Root != want {
			t.Fatalf("pvc share root = %q, want %q", share.Root, want)
		}
		// The assertion the VZ stat makes: the planned share root must be a real
		// directory by the time the backend is handed the spec.
		fi, err := os.Stat(share.Root)
		if err != nil {
			t.Fatalf("the planned pvc share root does not exist; VZ refuses the machine over exactly this: %v", err)
		}
		if !fi.IsDir() {
			t.Errorf("%s is not a directory", share.Root)
		}
		if !share.Writable {
			t.Errorf("pvc share %q is read-only; a read-write claim must be writable", share.Tag)
		}
	})

	t.Run("an-existing-claims-contents-are-preserved", func(t *testing.T) {
		// M3.1 durability: a PVC is lifecycle-decoupled (ReclaimPolicy Retain), so
		// the second pod to mount a claim must find the first pod's data. A
		// provisioning step that re-created or re-seeded the dir would silently
		// destroy a database.
		rt, vmb := newVMPlanRuntime(t)
		dataDir := filepath.Join(rt.cfg.Root, "storage", "default", "pgdata")
		if err := os.MkdirAll(filepath.Join(dataDir, "base"), 0o755); err != nil {
			t.Fatal(err)
		}
		const payload = "PG_VERSION 16\n"
		existing := filepath.Join(dataDir, "PG_VERSION")
		if err := os.WriteFile(existing, []byte(payload), 0o644); err != nil {
			t.Fatal(err)
		}

		mustPlanVM(t, rt, vmb, vmPVCBox(rt, "pod-pvc-reuse", "pgdata"))

		got, err := os.ReadFile(existing)
		if err != nil {
			t.Fatalf("the existing claim's file is gone: %v", err)
		}
		if string(got) != payload {
			t.Errorf("claim file = %q, want %q — an existing PVC must never be re-seeded", got, payload)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "base")); err != nil {
			t.Errorf("the existing claim's subdirectory is gone: %v", err)
		}
	})

	t.Run("no-symlink-is-planted-in-the-read-only-rootfs-share", func(t *testing.T) {
		// The asymmetry Provision exists for. The host-process spine reaches a
		// claim through a symlink in the pod rootfs; a guest reaches it through the
		// share device. That rootfs is exported READ-ONLY as the image's lower
		// layer, so a symlink there would surface in the container pointing at a
		// host path with no meaning in the guest's namespace.
		rt, vmb := newVMPlanRuntime(t)
		mustPlanVM(t, rt, vmb, vmPVCBox(rt, "pod-pvc-nolink", "pgdata"))

		link := filepath.Join(rt.cfg.Root, "pods", "pod-pvc-nolink", "rootfs", "var", "lib", "postgresql", "data")
		if fi, err := os.Lstat(link); err == nil {
			t.Errorf("a %v was planted at %s; a vm pod reaches its claim through the share device, not the rootfs",
				fi.Mode().Type(), link)
		}
	})
}
