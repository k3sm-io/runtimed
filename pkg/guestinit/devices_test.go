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

// TestContainerDevIsTheOCIDefaultSet pins the device allowlist exactly. The list
// is a security boundary (see ContainerDev), so both halves are asserted: every
// device that must be there, and the absence of everything else.
func TestContainerDevIsTheOCIDefaultSet(t *testing.T) {
	t.Parallel()
	root := ContainerRootDir("app")
	dev := ContainerDev("app", nil)

	t.Run("exactly the six OCI default devices are bound", func(t *testing.T) {
		want := []string{"null", "zero", "full", "random", "urandom", "tty"}
		var got []string
		for _, m := range dev.Mounts {
			if m.FSType != "" {
				continue // devpts and the shm tmpfs are not device binds
			}
			got = append(got, path.Base(m.Target))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("bound devices = %v, want %v", got, want)
		}
		if strings.Join(DefaultDevices, ",") != strings.Join(want, ",") {
			t.Errorf("DefaultDevices = %v, want %v", DefaultDevices, want)
		}
	})

	t.Run("each device is a bind of the guest's own node onto a created file", func(t *testing.T) {
		for _, d := range DefaultDevices {
			m, ok := findMount(dev.Mounts, path.Join(root, "dev", d))
			if !ok {
				t.Fatalf("no mount for /dev/%s", d)
			}
			if m.Source != "/dev/"+d {
				t.Errorf("/dev/%s source = %q, want the guest node", d, m.Source)
			}
			if !hasOption(m.Options, OptionBind) {
				t.Errorf("/dev/%s options = %v, want a bind (mknod is not available in the overlay upper)", d, m.Options)
			}
			if !m.TouchTarget {
				t.Errorf("/dev/%s does not create its target file; binding a node needs a non-directory target", d)
			}
			if m.ResolveRoot != root {
				t.Errorf("/dev/%s ResolveRoot = %q, want %q: the image decides what is a symlink", d, m.ResolveRoot, root)
			}
			if hasOption(m.Options, OptionNoDev) {
				t.Errorf("/dev/%s is mounted nodev, which makes the device node it just bound unusable", d)
			}
		}
	})

	t.Run("no guest device outside the allowlist is exposed, /dev/vsock above all", func(t *testing.T) {
		// The pod's guest agent is served over AF_VSOCK with vsock loopback in
		// the kernel, so a container holding /dev/vsock could exec into every
		// container of its own pod, read their logs and stop the pod. Nothing
		// else stands between it and the agent.
		forbidden := []string{
			"/dev/vsock", "/dev/vhost-vsock", "/dev/mem", "/dev/kmem", "/dev/kmsg",
			"/dev/console", "/dev/hvc0", "/dev/vda", "/dev/loop0", "/dev/mapper",
		}
		for _, m := range dev.Mounts {
			for _, bad := range forbidden {
				if m.Source == bad || m.Target == path.Join(root, strings.TrimPrefix(bad, "/")) {
					t.Errorf("the plan exposes %s to the container (step %+v)", bad, m)
				}
			}
		}
		// Nothing binds the guest's /dev wholesale either, which would carry
		// every one of the above in one step.
		for _, m := range dev.Mounts {
			if m.Source == "/dev" || m.Source == "/dev/" {
				t.Errorf("the plan binds the guest's whole /dev: %+v", m)
			}
		}
	})

	t.Run("the container gets a private devpts and its own ptmx link", func(t *testing.T) {
		pts, ok := findMount(dev.Mounts, path.Join(root, "dev", "pts"))
		if !ok {
			t.Fatal("no devpts mount")
		}
		if pts.FSType != "devpts" {
			t.Errorf("devpts FSType = %q", pts.FSType)
		}
		for _, want := range []string{"newinstance", "ptmxmode=0666", "mode=0620", "gid=5"} {
			if !strings.Contains(pts.Data, want) {
				t.Errorf("devpts data %q lacks %q", pts.Data, want)
			}
		}
		if dev.PtsDir != path.Join(root, "dev", "pts") {
			t.Errorf("PtsDir = %q, want %q", dev.PtsDir, path.Join(root, "dev", "pts"))
		}
		if len(dev.Links) != 1 {
			t.Fatalf("%d links, want 1 (/dev/ptmx)", len(dev.Links))
		}
		l := dev.Links[0]
		if l.Target != path.Join(root, "dev", "ptmx") || l.LinkTo != "pts/ptmx" {
			t.Errorf("link = %+v, want %s -> pts/ptmx", l, path.Join(root, "dev", "ptmx"))
		}
		if l.ResolveRoot != root {
			t.Errorf("link ResolveRoot = %q, want %q", l.ResolveRoot, root)
		}
		if path.IsAbs(l.LinkTo) {
			t.Error("the ptmx link is absolute; it must resolve to this container's own instance however it is reached")
		}
	})

	t.Run("/dev/shm is a bounded tmpfs", func(t *testing.T) {
		shm, ok := findMount(dev.Mounts, path.Join(root, "dev", "shm"))
		if !ok {
			t.Fatal("no /dev/shm")
		}
		if shm.FSType != "tmpfs" {
			t.Errorf("/dev/shm FSType = %q, want tmpfs", shm.FSType)
		}
		if !strings.Contains(shm.Data, "size=") {
			t.Errorf("/dev/shm data = %q, want a size bound (guest tmpfs is charged to guest RAM)", shm.Data)
		}
		if !strings.Contains(shm.Data, "mode=1777") {
			t.Errorf("/dev/shm data = %q, want mode=1777", shm.Data)
		}
	})
}

// TestContainerDevYieldsToPodMounts pins the rule that a pod-declared mount at
// one of these paths wins — the Memory-emptyDir-at-/dev/shm case, and the
// coverage cases around it.
func TestContainerDevYieldsToPodMounts(t *testing.T) {
	t.Parallel()
	root := ContainerRootDir("app")

	cases := []struct {
		name       string
		podTargets []string
		absent     []string
		wantPtsDir string
	}{
		{
			name:       "a pod Memory emptyDir at /dev/shm replaces the default one",
			podTargets: []string{"/dev/shm"},
			absent:     []string{path.Join(root, "dev", "shm")},
			wantPtsDir: path.Join(root, "dev", "pts"),
		},
		{
			name:       "a pod mount over /dev takes the whole tree, devpts included",
			podTargets: []string{"/dev"},
			absent: []string{
				path.Join(root, "dev", "shm"), path.Join(root, "dev", "pts"),
				path.Join(root, "dev", "null"), path.Join(root, "dev", "tty"),
			},
			wantPtsDir: "",
		},
		{
			name:       "a pod mount at an unrelated path changes nothing",
			podTargets: []string{"/pgdata", "/var/run/secrets"},
			wantPtsDir: path.Join(root, "dev", "pts"),
		},
		{
			name:       "a pod mount over /dev/pts leaves the container without an instance",
			podTargets: []string{"/dev/pts"},
			absent:     []string{path.Join(root, "dev", "pts")},
			wantPtsDir: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pod []MountStep
			for _, target := range tc.podTargets {
				pod = append(pod, MountStep{Target: target, Source: "tmpfs", FSType: "tmpfs"})
			}
			dev := ContainerDev("app", pod)
			for _, target := range tc.absent {
				if _, ok := findMount(dev.Mounts, target); ok {
					t.Errorf("%s is still planned; the pod's own mount would be stacked over by it", target)
				}
			}
			if dev.PtsDir != tc.wantPtsDir {
				t.Errorf("PtsDir = %q, want %q", dev.PtsDir, tc.wantPtsDir)
			}
			if tc.wantPtsDir == "" && len(dev.Links) != 0 {
				t.Errorf("links = %+v, want none without a private devpts", dev.Links)
			}
		})
	}
}

// TestPlanWiresTheContainerDev checks the whole-plan integration: the /dev steps
// are in every container's mount list, they are applied after the rootfs and
// BEFORE the pod mounts (so a pod mount at one of their paths wins), and the
// /etc binds stay last.
func TestPlanWiresTheContainerDev(t *testing.T) {
	t.Parallel()
	plan, err := Plan(goldenSpec(), Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, c := range plan.Containers {
		root := ContainerRootDir(c.Name)

		t.Run(c.Name+": every OCI default device is present", func(t *testing.T) {
			for _, d := range DefaultDevices {
				if _, ok := findMount(c.Mounts, path.Join(root, "dev", d)); !ok {
					t.Errorf("container %q has no /dev/%s", c.Name, d)
				}
			}
			if c.DevPtsDir != path.Join(root, "dev", "pts") {
				t.Errorf("container %q DevPtsDir = %q", c.Name, c.DevPtsDir)
			}
			if len(c.Links) != 1 {
				t.Errorf("container %q links = %+v, want the ptmx symlink", c.Name, c.Links)
			}
		})

		t.Run(c.Name+": /dev is planned after the rootfs and before the pod mounts", func(t *testing.T) {
			rootfs := indexOfMount(c.Mounts, root)
			devNull := indexOfMount(c.Mounts, path.Join(root, "dev", "null"))
			// The golden spec declares a Memory emptyDir at /dev/shm, so the
			// pod's own /dev/shm is the mount to order against.
			podShm := indexOfMount(c.Mounts, path.Join(root, "dev", "shm"))
			etc := indexOfMount(c.Mounts, path.Join(root, "etc", "resolv.conf"))
			if rootfs < 0 || devNull < 0 || podShm < 0 || etc < 0 {
				t.Fatalf("missing a step: rootfs=%d dev=%d shm=%d etc=%d", rootfs, devNull, podShm, etc)
			}
			if !(rootfs < devNull && devNull < podShm && podShm < etc) {
				t.Errorf("order rootfs=%d dev=%d podShm=%d etc=%d, want rootfs < dev < pod mounts < etc",
					rootfs, devNull, podShm, etc)
			}
		})

		t.Run(c.Name+": the pod's /dev/shm is the only one", func(t *testing.T) {
			// The golden spec's 64Mi Memory emptyDir at /dev/shm must be what
			// the container sees — not a default tmpfs with the pod's mount
			// stacked over it, and not the default's size.
			n := 0
			for _, m := range c.Mounts {
				if m.Target == path.Join(root, "dev", "shm") {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%d mounts at /dev/shm, want exactly the pod's own", n)
			}
			shm, _ := findMount(c.Mounts, path.Join(root, "dev", "shm"))
			if !hasOption(shm.Options, OptionRBind) {
				t.Errorf("/dev/shm = %+v, want the pod mount re-exposed as an rbind", shm)
			}
		})
	}

	t.Run("a pod with no /dev/shm mount gets the bounded default", func(t *testing.T) {
		spec := goldenSpec()
		var kept []*guestv1.GuestMount
		for _, m := range spec.GetMounts() {
			if m.GetTarget() != "/dev/shm" {
				kept = append(kept, m)
			}
		}
		spec.Mounts = kept
		p, err := Plan(spec, Options{MemTotalBytes: 2 << 30})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		root := ContainerRootDir(p.Containers[0].Name)
		shm, ok := findMount(p.Containers[0].Mounts, path.Join(root, "dev", "shm"))
		if !ok {
			t.Fatal("no /dev/shm at all")
		}
		if shm.FSType != "tmpfs" || !strings.Contains(shm.Data, "size=") {
			t.Errorf("/dev/shm = %+v, want the bounded default tmpfs", shm)
		}
	})
}

// indexOfMount returns the index of the first step with the given target, or -1.
func indexOfMount(steps []MountStep, target string) int {
	for i, s := range steps {
		if s.Target == target {
			return i
		}
	}
	return -1
}
