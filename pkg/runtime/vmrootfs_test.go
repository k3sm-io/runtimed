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

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCreateVMPodMaterializesTheRootfsShare is the gate on the vm spine's
// missing unpack: a vm pod pulled its image, recorded it in images.json, and
// then booted a guest over an EMPTY <podDir>/rootfs — no /bin/sh, the container
// exited instantly, and guest init powered the VM off with containers=0.
//
// It asserts all three halves of the wiring, because any one of them alone can
// be satisfied vacuously: the unpacker seam is CALLED, under the LINUX layer
// dialect (a Mach-O dialect would commit a Linux tree under a key claiming
// otherwise), into the DIRECTORY the k3sm.rootfs share exports — and the files
// actually land there.
func TestCreateVMPodMaterializesTheRootfsShare(t *testing.T) {
	imageTree := map[string]string{
		"bin/sh":         "#!/bin/sh\n",
		"etc/os-release": "NAME=\"Alpine Linux\"\n",
	}
	tu := &treeUnpacker{files: imageTree, runCfg: image.ImageRunConfig{Entrypoint: []string{"/bin/sh"}}}
	vmb := &fakeVMBackend{available: true, bootOK: true}
	cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Unpacker: tu})
	rt := newTestRuntimeCfg(t, cfg, d)

	spec := createVMSpec(t, rt, vmb, vmPodBox(rt, "pod-rootfs", 0))

	// Derived from Config.Root + the documented layout literals, never from the
	// same helper the production path used to derive it.
	rootfs := filepath.Join(rt.cfg.Root, "pods", "pod-rootfs", "rootfs")
	if spec.RootfsPath != rootfs {
		t.Fatalf("VMSpec.RootfsPath = %q, want %q", spec.RootfsPath, rootfs)
	}
	if got := findVMShare(t, spec, mount.ShareTagRootfs).Root; got != rootfs {
		t.Fatalf("%s share root = %q, want %q", mount.ShareTagRootfs, got, rootfs)
	}

	t.Run("the unpacker seam is called once, into the rootfs share, under the Linux dialect", func(t *testing.T) {
		calls := tu.observed()
		if len(calls) != 1 {
			t.Fatalf("MaterializeTree called %d times, want 1", len(calls))
		}
		if calls[0].dst != rootfs {
			t.Errorf("materialized into %q, want the rootfs share root %q", calls[0].dst, rootfs)
		}
		if want := image.LinuxUnpackPolicy(); calls[0].policy != want {
			t.Errorf("unpack policy = %+v, want %+v (a vm pod's layers are Linux layers)", calls[0].policy, want)
		}
	})

	t.Run("the image's files are on disk in the share the guest overlays", func(t *testing.T) {
		for rel, want := range imageTree {
			got, err := os.ReadFile(filepath.Join(rootfs, rel))
			if err != nil {
				t.Errorf("read %s from the pod rootfs: %v", rel, err)
				continue
			}
			if string(got) != want {
				t.Errorf("%s = %q, want %q", rel, got, want)
			}
		}
	})
}

// TestCreateVMPodMaterializesOneImagePerPod pins the recorded ceiling rather
// than hiding it: the share plan carries ONE pod-wide rootfs share
// (vmRootfsShareTag), so a pod naming a second image materializes only the
// first — never image N cloned over image 1's tree, which would leave a tree no
// manifest describes.
func TestCreateVMPodMaterializesOneImagePerPod(t *testing.T) {
	tu := &treeUnpacker{files: map[string]string{"bin/sh": "sh"}, runCfg: image.ImageRunConfig{Entrypoint: []string{"/bin/sh"}}}
	vmb := &fakeVMBackend{available: true, bootOK: true}
	cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Unpacker: tu})
	rt := newTestRuntimeCfg(t, cfg, d)

	box := vmPodBox(rt, "pod-two-images", 0)
	box.Containers = append(box.Containers, &runtimev1.Container{
		Name:    "aux",
		Image:   "docker.io/library/busybox:1",
		Command: []string{"/bin/sleep", "3600"},
	})
	createVMSpec(t, rt, vmb, box)

	calls := tu.observed()
	if len(calls) != 1 {
		t.Fatalf("MaterializeTree called %d times, want exactly 1 (one pod-wide rootfs share)", len(calls))
	}
}
