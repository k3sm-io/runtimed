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

package guestinit

import (
	"path"
	"strings"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// TestContainerKernelFSMountsProcAndCgroup2 pins the two kernel filesystems a
// vm container needs beyond its rootfs and /dev: a FRESH procfs at /proc and a
// WRITABLE cgroup2 hierarchy at /sys/fs/cgroup. Both are what a runc-based build
// worker (buildkitd's default) fails without.
func TestContainerKernelFSMountsProcAndCgroup2(t *testing.T) {
	t.Parallel()
	root := ContainerRootDir("app")
	steps := ContainerKernelFS("app", nil)

	t.Run("exactly proc and cgroup2, in that order", func(t *testing.T) {
		if len(steps) != 2 {
			t.Fatalf("%d steps, want exactly proc and cgroup2: %+v", len(steps), steps)
		}
		if steps[0].Target != path.Join(root, "proc") {
			t.Errorf("step 0 target = %q, want the container /proc", steps[0].Target)
		}
		if steps[1].Target != path.Join(root, "sys", "fs", "cgroup") {
			t.Errorf("step 1 target = %q, want the container /sys/fs/cgroup", steps[1].Target)
		}
	})

	t.Run("/proc is a FRESH procfs, not a bind of the guest's", func(t *testing.T) {
		p, ok := findMount(steps, path.Join(root, "proc"))
		if !ok {
			t.Fatal("no /proc mount")
		}
		if p.FSType != "proc" || p.Source != "proc" {
			t.Errorf("/proc = source %q type %q, want a fresh procfs (source proc, type proc)", p.Source, p.FSType)
		}
		if hasOption(p.Options, OptionBind) {
			t.Error("/proc is a bind; it must be a fresh procfs instance, never the guest's /proc")
		}
		if !p.MkdirTarget {
			t.Error("/proc does not create its mountpoint")
		}
		if p.ResolveRoot != root {
			t.Errorf("/proc ResolveRoot = %q, want %q: the image decides what is a symlink", p.ResolveRoot, root)
		}
		for _, o := range []MountOption{OptionNoSuid, OptionNoDev, OptionNoExec} {
			if !hasOption(p.Options, o) {
				t.Errorf("/proc is missing hardening option %q", o)
			}
		}
	})

	t.Run("cgroup2 is WRITABLE so runc can create sub-cgroups", func(t *testing.T) {
		cg, ok := findMount(steps, path.Join(root, "sys", "fs", "cgroup"))
		if !ok {
			t.Fatal("no cgroup2 mount")
		}
		if cg.FSType != "cgroup2" || cg.Source != "cgroup2" {
			t.Errorf("cgroup = source %q type %q, want cgroup2", cg.Source, cg.FSType)
		}
		if hasOption(cg.Options, OptionReadOnly) {
			t.Error("cgroup2 is read-only; buildkitd's runc worker must be able to create per-build sub-cgroups in it")
		}
		// This is the SECOND mount of the single unified cgroup2 hierarchy
		// (PseudoMounts mounts the first, guest-root one — that is the mount
		// that carries "nsdelegate"). A second mount that passes a cgroup-root
		// flag like "nsdelegate" comes up EMPTY (no cgroup.controllers,
		// cgroup.procs), and runc then fails "no cgroup mount found in
		// mountinfo". The per-container mount must carry NO fs data so it roots
		// at the cgroup-namespace root and shows the populated hierarchy — the
		// plain `mount -t cgroup2 none` form the mudkitty prototype uses.
		//
		// That the mounted hierarchy actually exposes cgroup.controllers is a
		// LAB-tier assertion (it needs a booted guest): hack/acceptance/
		// vm-builder-prereqs.sh rung lab.3 probes /sys/fs/cgroup/cgroup.controllers
		// on the live pod. That rung is owed and takes effect only after the
		// initramfs is re-pinned.
		if strings.Contains(cg.Data, "nsdelegate") {
			t.Errorf("cgroup2 data = %q, must NOT carry nsdelegate: a second cgroup2 mount with a cgroup-root flag comes up empty", cg.Data)
		}
		if cg.Data != "" {
			t.Errorf("cgroup2 data = %q, want empty (a plain second mount with no fs data)", cg.Data)
		}
		if !cg.MkdirTarget {
			t.Error("cgroup2 does not create its mountpoint (os.MkdirAll makes <root>/sys and <root>/sys/fs on the way)")
		}
		if cg.ResolveRoot != root {
			t.Errorf("cgroup2 ResolveRoot = %q, want %q", cg.ResolveRoot, root)
		}
	})

	t.Run("no sysfs is mounted by default: cgroup2 attaches without one", func(t *testing.T) {
		for _, s := range steps {
			if s.FSType == "sysfs" {
				t.Errorf("a sysfs was planned (%+v); cgroup2 is an independent filesystem and needs no sysfs parent", s)
			}
		}
	})
}

// TestContainerKernelFSYieldsToPodMounts pins that a pod-declared mount covering
// /proc or /sys/fs/cgroup wins — the covered default is omitted so the pod's own
// mount is the only one at that path.
func TestContainerKernelFSYieldsToPodMounts(t *testing.T) {
	t.Parallel()
	root := ContainerRootDir("app")

	cases := []struct {
		name       string
		podTargets []string
		absent     []string
		present    []string
	}{
		{
			name:       "a pod mount over /proc omits the default procfs",
			podTargets: []string{"/proc"},
			absent:     []string{path.Join(root, "proc")},
			present:    []string{path.Join(root, "sys", "fs", "cgroup")},
		},
		{
			name:       "a pod mount over /sys takes the cgroup hierarchy with it",
			podTargets: []string{"/sys"},
			absent:     []string{path.Join(root, "sys", "fs", "cgroup")},
			present:    []string{path.Join(root, "proc")},
		},
		{
			name:       "a pod mount over /sys/fs/cgroup omits just the cgroup2 default",
			podTargets: []string{"/sys/fs/cgroup"},
			absent:     []string{path.Join(root, "sys", "fs", "cgroup")},
			present:    []string{path.Join(root, "proc")},
		},
		{
			name:       "an unrelated pod mount changes nothing",
			podTargets: []string{"/pgdata"},
			present:    []string{path.Join(root, "proc"), path.Join(root, "sys", "fs", "cgroup")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pod []MountStep
			for _, target := range tc.podTargets {
				pod = append(pod, MountStep{Target: target, Source: "tmpfs", FSType: "tmpfs"})
			}
			steps := ContainerKernelFS("app", pod)
			for _, target := range tc.absent {
				if _, ok := findMount(steps, target); ok {
					t.Errorf("%s is still planned; the pod's own mount would be stacked over by it", target)
				}
			}
			for _, target := range tc.present {
				if _, ok := findMount(steps, target); !ok {
					t.Errorf("%s was dropped; only the covered path yields", target)
				}
			}
		})
	}
}

// TestNoLoopDevicesInDefaultSet pins the loop-device SECURITY POSTURE: loop
// devices are never in the default set. A build-class pod that needs
// `mount -o loop` mounts its own devtmpfs (the guest root can); widening every
// container's device set would hand loop nodes to workloads that must not have
// them, exactly the leak the additive allowlist exists to prevent.
func TestNoLoopDevicesInDefaultSet(t *testing.T) {
	t.Parallel()
	loopNodes := []string{
		"loop-control", "loop0", "loop1", "loop2", "loop3",
		"loop4", "loop5", "loop6", "loop7",
	}

	t.Run("DefaultDevices names no loop device", func(t *testing.T) {
		for _, d := range DefaultDevices {
			if d == "loop-control" || strings.HasPrefix(d, "loop") {
				t.Errorf("DefaultDevices contains a loop device %q; a build pod mounts its own devtmpfs instead", d)
			}
		}
	})

	t.Run("no container mount binds a loop node", func(t *testing.T) {
		root := ContainerRootDir("app")
		dev := ContainerDev("app", nil)
		for _, n := range loopNodes {
			if _, ok := findMount(dev.Mounts, path.Join(root, "dev", n)); ok {
				t.Errorf("a container mount exposes /dev/%s", n)
			}
			for _, m := range dev.Mounts {
				if m.Source == "/dev/"+n {
					t.Errorf("a container mount sources the guest's /dev/%s", n)
				}
			}
		}
	})
}

// TestPlanWiresContainerKernelFS is the whole-plan integration: /proc and the
// cgroup2 hierarchy are in every container's mount list, applied AFTER the
// rootfs and the /dev steps and BEFORE the pod mounts (so a pod mount at one of
// their paths wins) and the /etc binds stay last.
func TestPlanWiresContainerKernelFS(t *testing.T) {
	t.Parallel()
	plan, err := Plan(goldenSpec(), Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, c := range plan.Containers {
		root := ContainerRootDir(c.Name)

		t.Run(c.Name+": /proc and cgroup2 are present and correctly typed", func(t *testing.T) {
			p, ok := findMount(c.Mounts, path.Join(root, "proc"))
			if !ok || p.FSType != "proc" {
				t.Errorf("container %q has no fresh /proc (got %+v, ok=%v)", c.Name, p, ok)
			}
			cg, ok := findMount(c.Mounts, path.Join(root, "sys", "fs", "cgroup"))
			if !ok || cg.FSType != "cgroup2" {
				t.Errorf("container %q has no cgroup2 (got %+v, ok=%v)", c.Name, cg, ok)
			}
			if hasOption(cg.Options, OptionReadOnly) {
				t.Errorf("container %q cgroup2 is read-only", c.Name)
			}
		})

		t.Run(c.Name+": the kernel FS is planned after rootfs+dev and before the pod mounts", func(t *testing.T) {
			rootfs := indexOfMount(c.Mounts, root)
			devNull := indexOfMount(c.Mounts, path.Join(root, "dev", "null"))
			proc := indexOfMount(c.Mounts, path.Join(root, "proc"))
			cgroup := indexOfMount(c.Mounts, path.Join(root, "sys", "fs", "cgroup"))
			// The golden spec declares a Memory emptyDir at /dev/shm, so the
			// pod's own /dev/shm re-exposure is the first pod mount to order
			// against.
			podShm := indexOfMount(c.Mounts, path.Join(root, "dev", "shm"))
			etc := indexOfMount(c.Mounts, path.Join(root, "etc", "resolv.conf"))
			if rootfs < 0 || devNull < 0 || proc < 0 || cgroup < 0 || podShm < 0 || etc < 0 {
				t.Fatalf("missing a step: rootfs=%d dev=%d proc=%d cgroup=%d shm=%d etc=%d",
					rootfs, devNull, proc, cgroup, podShm, etc)
			}
			if !(devNull < proc && proc < podShm && cgroup < podShm && podShm < etc) {
				t.Errorf("order dev=%d proc=%d cgroup=%d podShm=%d etc=%d, want dev < kernelfs < pod mounts < etc",
					devNull, proc, cgroup, podShm, etc)
			}
		})
	}

	t.Run("a pod mount over /proc leaves exactly the pod's own", func(t *testing.T) {
		spec := goldenSpec()
		spec.Mounts = append(spec.Mounts, &guestv1.GuestMount{
			Target: "/proc", Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS,
		})
		p, err := Plan(spec, Options{MemTotalBytes: 2 << 30})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		root := ContainerRootDir(p.Containers[0].Name)
		n := 0
		for _, m := range p.Containers[0].Mounts {
			if m.Target == path.Join(root, "proc") {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%d mounts at /proc, want exactly the pod's own re-exposed mount", n)
		}
		proc, _ := findMount(p.Containers[0].Mounts, path.Join(root, "proc"))
		if proc.FSType == "proc" {
			t.Error("the default fresh procfs is still planned; the pod's mount must win")
		}
	})
}
