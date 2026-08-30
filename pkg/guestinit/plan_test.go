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
	"errors"
	"strings"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// goldenSpec mirrors apis/guest/v1/testdata/guest-spec.json — the schema's own
// executable statement of a realistic pod: one init container, one main
// container, a read-only projected share, a bounded tmpfs, and an idmapped
// claim.
func goldenSpec() *guestv1.GuestSpec {
	return &guestv1.GuestSpec{
		Hostname: "web-0",
		ResolvConf: &guestv1.ResolvConf{
			Nameservers: []string{"10.43.0.10"},
			Searches:    []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"},
			Options:     []string{"ndots:5"},
		},
		Containers: []*guestv1.GuestContainer{
			{
				Name: "init-db", RootfsTag: "k3sm.rootfs.init-db",
				Command: []string{"/bin/sh", "-c"}, Args: []string{"initdb /pgdata"},
				Env: []string{"PGDATA=/pgdata"}, WorkingDir: "/",
				Uid: 999, Gid: 999, Init: true,
			},
			{
				Name: "postgres", RootfsTag: "k3sm.rootfs.postgres",
				Command: []string{"/usr/local/bin/postgres"}, Args: []string{"-D", "/pgdata"},
				Env:        []string{"PGDATA=/pgdata", "POSTGRES_DB=stockkitty"},
				WorkingDir: "/var/lib/postgresql",
				Uid:        999, Gid: 999, SupplementalGids: []int64{999, 2000},
			},
		},
		Mounts: []*guestv1.GuestMount{
			{
				TagOrSource: "k3sm.proj", Target: "/var/run/secrets/kubernetes.io/serviceaccount",
				Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, ReadOnly: true,
			},
			{
				Target: "/dev/shm", Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS,
				SizeLimitBytes: 67108864,
			},
			{
				TagOrSource: "k3sm.pvc.default.pgdata", Target: "/pgdata",
				Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, Idmap: true,
			},
		},
		Rosetta: true, FsGroup: 2000, AgentPort: 1024,
	}
}

// findMount returns the first step whose target matches, and whether one did.
func findMount(steps []MountStep, target string) (MountStep, bool) {
	for _, s := range steps {
		if s.Target == target {
			return s, true
		}
	}
	return MountStep{}, false
}

// TestPlanRealizesTheGoldenSpec walks the whole plan produced for the guest/v1
// golden fixture. Each subtest pins one property the boot depends on.
func TestPlanRealizesTheGoldenSpec(t *testing.T) {
	t.Parallel()
	plan, err := Plan(goldenSpec(), Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	t.Run("the pseudo filesystems come first and include binfmt_misc", func(t *testing.T) {
		want := []string{"/proc", "/sys", "/dev", "/dev/pts", "/dev/shm", "/sys/fs/cgroup", BinfmtMiscMountPoint}
		if len(plan.Pseudo) != len(want) {
			t.Fatalf("pseudo mounts = %d, want %d", len(plan.Pseudo), len(want))
		}
		for i, target := range want {
			if plan.Pseudo[i].Target != target {
				t.Errorf("pseudo[%d].Target = %q, want %q", i, plan.Pseudo[i].Target, target)
			}
		}
		if proc := plan.Pseudo[0]; !hasOption(proc.Options, OptionNoSuid) ||
			!hasOption(proc.Options, OptionNoExec) || !hasOption(proc.Options, OptionNoDev) {
			t.Errorf("/proc options = %v, want nosuid+noexec+nodev", proc.Options)
		}
	})

	t.Run("containers start init-first regardless of spec order", func(t *testing.T) {
		if len(plan.Containers) != 2 {
			t.Fatalf("containers = %d, want 2", len(plan.Containers))
		}
		if plan.Containers[0].Name != "init-db" || plan.Containers[0].Phase != PhaseInit ||
			!plan.Containers[0].WaitForExit {
			t.Errorf("first container = %+v, want the init container, waited for", plan.Containers[0])
		}
		if plan.Containers[1].Name != "postgres" || plan.Containers[1].Phase != PhaseMain ||
			plan.Containers[1].WaitForExit {
			t.Errorf("second container = %+v, want the main container, not waited for", plan.Containers[1])
		}

		// The ordering is applied, not inherited: a spec listing the main
		// container first still starts the init container first.
		spec := goldenSpec()
		spec.Containers[0], spec.Containers[1] = spec.Containers[1], spec.Containers[0]
		reordered, err := Plan(spec, Options{})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if reordered.Containers[0].Name != "init-db" {
			t.Errorf("reordered spec started %q first, want init-db", reordered.Containers[0].Name)
		}
	})

	t.Run("argv is command followed by args", func(t *testing.T) {
		got := strings.Join(plan.Containers[1].Argv, " ")
		if want := "/usr/local/bin/postgres -D /pgdata"; got != want {
			t.Errorf("argv = %q, want %q", got, want)
		}
	})

	t.Run("fsGroup joins the supplementary groups", func(t *testing.T) {
		id := plan.Containers[1].Ident
		if id.UID != 999 || id.GID != 999 {
			t.Errorf("ident = %+v, want 999:999", id)
		}
		if len(id.Groups) != 2 || id.Groups[0] != 999 || id.Groups[1] != 2000 {
			t.Errorf("groups = %v, want [999 2000] (deduplicated, sorted, fsGroup included)", id.Groups)
		}
	})

	t.Run("each container gets a bounded overlay over a read-only lower", func(t *testing.T) {
		c := plan.Containers[1]
		lower, ok := findMount(c.Mounts, ContainerLowerDir("postgres"))
		if !ok {
			t.Fatal("no rootfs lower mount")
		}
		if lower.FSType != "virtiofs" || lower.Source != "k3sm.rootfs.postgres" ||
			!hasOption(lower.Options, OptionReadOnly) {
			t.Errorf("lower = %+v, want a read-only virtiofs of the rootfs tag", lower)
		}
		upper, ok := findMount(c.Mounts, ContainerUpperTmpfs("postgres"))
		if !ok {
			t.Fatal("no overlay upper tmpfs")
		}
		if !strings.Contains(upper.Data, "size=") {
			t.Errorf("upper tmpfs data = %q, want a size bound (an unbounded upper becomes a guest OOM)", upper.Data)
		}
		root, ok := findMount(c.Mounts, ContainerRootDir("postgres"))
		if !ok {
			t.Fatal("no overlay root mount")
		}
		if root.FSType != "overlay" || !strings.Contains(root.Data, "metacopy=on") {
			t.Errorf("root = %+v, want an overlay with metacopy=on", root)
		}
		for _, want := range []string{ContainerUpperDir("postgres"), ContainerWorkDir("postgres")} {
			if !strings.Contains(root.Data, want) {
				t.Errorf("overlay data %q does not name %q", root.Data, want)
			}
		}
	})

	t.Run("the rootfs lower is mounted before the overlay that stacks on it", func(t *testing.T) {
		c := plan.Containers[1]
		lower, upper, root := -1, -1, -1
		for i, m := range c.Mounts {
			switch m.Target {
			case ContainerLowerDir("postgres"):
				lower = i
			case ContainerUpperTmpfs("postgres"):
				upper = i
			case ContainerRootDir("postgres"):
				root = i
			}
		}
		if !(lower < upper && upper < root) {
			t.Errorf("mount order lower=%d upper=%d root=%d, want lower < upper < root", lower, upper, root)
		}
	})

	t.Run("every container gets the read-only /etc bind set, last", func(t *testing.T) {
		for _, c := range plan.Containers {
			root := ContainerRootDir(c.Name)
			for _, f := range EtcBindFiles {
				target := root + "/etc/" + f
				bind, ok := findMount(c.Mounts, target)
				if !ok {
					t.Fatalf("container %q: no bind at %s", c.Name, target)
				}
				if !bind.TouchTarget {
					t.Errorf("container %q: bind of %s does not create the target file", c.Name, f)
				}
			}
			// The remount is what actually makes a bind read-only on Linux.
			ro := 0
			for _, m := range c.Mounts {
				if hasOption(m.Options, OptionRemount) && hasOption(m.Options, OptionReadOnly) &&
					strings.HasPrefix(m.Target, root+"/etc/") {
					ro++
				}
			}
			if ro != len(EtcBindFiles) {
				t.Errorf("container %q: %d read-only remounts over /etc, want %d", c.Name, ro, len(EtcBindFiles))
			}
			// Nothing may be stacked after the /etc binds.
			last := c.Mounts[len(c.Mounts)-1]
			if !strings.HasPrefix(last.Target, root+"/etc/") {
				t.Errorf("container %q: last mount is %q, want an /etc bind", c.Name, last.Target)
			}
		}
	})

	t.Run("pod mounts are re-exposed inside every container rootfs", func(t *testing.T) {
		for _, c := range plan.Containers {
			for _, target := range []string{"/pgdata", "/dev/shm", "/var/run/secrets/kubernetes.io/serviceaccount"} {
				if _, ok := findMount(c.Mounts, ContainerRootDir(c.Name)+target); !ok {
					t.Errorf("container %q: pod mount %s is not visible after the chroot", c.Name, target)
				}
			}
		}
	})

	t.Run("the projected share stays read-only inside the container", func(t *testing.T) {
		c := plan.Containers[1]
		target := ContainerRootDir("postgres") + "/var/run/secrets/kubernetes.io/serviceaccount"
		var remounts int
		for _, m := range c.Mounts {
			if m.Target == target && hasOption(m.Options, OptionRemount) && hasOption(m.Options, OptionReadOnly) {
				remounts++
			}
		}
		if remounts != 1 {
			t.Errorf("%d read-only remounts of the projected share, want 1 (MS_BIND|MS_RDONLY alone does not apply RDONLY)", remounts)
		}
	})

	t.Run("the idmapped claim carries the pod fsGroup", func(t *testing.T) {
		m, ok := findMount(plan.PodMounts, "/pgdata")
		if !ok {
			t.Fatal("no /pgdata pod mount")
		}
		if m.IDMap == nil {
			t.Fatal("/pgdata carries no idmap request")
		}
		if m.IDMap.ContainerGID != 2000 {
			t.Errorf("idmap container gid = %d, want the pod fsGroup 2000", m.IDMap.ContainerGID)
		}
	})

	t.Run("Rosetta is planned as mount-then-register", func(t *testing.T) {
		if plan.Binfmt == nil {
			t.Fatal("spec.rosetta is true but the plan carries no registration")
		}
		if plan.Binfmt.ShareMount.Source != RosettaShareTag {
			t.Errorf("share source = %q, want %q", plan.Binfmt.ShareMount.Source, RosettaShareTag)
		}
		spec := goldenSpec()
		spec.Rosetta = false
		noRosetta, err := Plan(spec, Options{})
		if err != nil {
			t.Fatalf("Plan: %v", err)
		}
		if noRosetta.Binfmt != nil {
			t.Error("a non-Rosetta pod still planned a binfmt registration")
		}
	})
}

// TestPlanRejectsUnrealizableSpecs pins the fail-closed refusals. PID 1 has
// nowhere to degrade to, so each of these must be a typed error rather than a
// partially booted pod.
func TestPlanRejectsUnrealizableSpecs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*guestv1.GuestSpec)
		want   error
	}{
		{"nil spec", nil, ErrInvalidSpec},
		{"no agent port", func(s *guestv1.GuestSpec) { s.AgentPort = 0 }, ErrInvalidSpec},
		{"agent port out of range", func(s *guestv1.GuestSpec) { s.AgentPort = 70000 }, ErrInvalidSpec},
		{"no containers", func(s *guestv1.GuestSpec) { s.Containers = nil }, ErrInvalidSpec},
		{"only init containers", func(s *guestv1.GuestSpec) { s.Containers = s.Containers[:1] }, ErrInvalidSpec},
		{"duplicate container names", func(s *guestv1.GuestSpec) { s.Containers[1].Name = "init-db" }, ErrInvalidSpec},
		{"container name is a path traversal", func(s *guestv1.GuestSpec) { s.Containers[1].Name = "../../etc" }, ErrInvalidSpec},
		{"container name is a dot segment", func(s *guestv1.GuestSpec) { s.Containers[1].Name = ".." }, ErrInvalidSpec},
		{"empty container name", func(s *guestv1.GuestSpec) { s.Containers[1].Name = "" }, ErrInvalidSpec},
		{"empty argv", func(s *guestv1.GuestSpec) {
			s.Containers[1].Command, s.Containers[1].Args = nil, nil
		}, ErrInvalidSpec},
		{"env entry is not KEY=VALUE", func(s *guestv1.GuestSpec) {
			s.Containers[1].Env = []string{"PGDATA"}
		}, ErrInvalidSpec},
		{"relative working dir", func(s *guestv1.GuestSpec) { s.Containers[1].WorkingDir = "pgdata" }, ErrInvalidSpec},
		{"empty rootfs tag", func(s *guestv1.GuestSpec) { s.Containers[1].RootfsTag = "" }, ErrInvalidSpec},
		{"negative uid", func(s *guestv1.GuestSpec) { s.Containers[1].Uid = -1 }, ErrInvalidSpec},
		{"uid past uid_t", func(s *guestv1.GuestSpec) { s.Containers[1].Uid = 1 << 33 }, ErrInvalidSpec},
		{"fsGroup out of range", func(s *guestv1.GuestSpec) { s.FsGroup = -5 }, ErrInvalidSpec},
		{"relative mount target", func(s *guestv1.GuestSpec) { s.Mounts[0].Target = "pgdata" }, ErrInvalidSpec},
		{"mount target escapes", func(s *guestv1.GuestSpec) { s.Mounts[0].Target = "/pods/../../etc" }, ErrInvalidSpec},
		{"virtiofs mount with no tag", func(s *guestv1.GuestSpec) { s.Mounts[0].TagOrSource = "" }, ErrInvalidSpec},
		{"tmpfs mount with a source", func(s *guestv1.GuestSpec) { s.Mounts[1].TagOrSource = "somewhere" }, ErrInvalidSpec},
		{"unspecified mount kind", func(s *guestv1.GuestSpec) {
			s.Mounts[0].Kind = guestv1.GuestMountKind_GUEST_MOUNT_KIND_UNSPECIFIED
		}, ErrInvalidSpec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var spec *guestv1.GuestSpec
			if tc.mutate != nil {
				spec = goldenSpec()
				tc.mutate(spec)
			}
			_, err := Plan(spec, Options{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Plan error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestUpperSizeBytes pins the overlay-upper bound: it is derived from the
// guest's RAM, shared across the containers, clamped, and NEVER unbounded.
func TestUpperSizeBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		mem        int64
		containers int
		want       int64
	}{
		{"half the RAM split across two containers", 2 << 30, 2, 512 << 20},
		{"one container takes the whole half, capped", 8 << 30, 1, upperSizeCap},
		{"a tiny guest is floored", 32 << 20, 4, upperSizeFloor},
		{"unknown RAM falls back to the default, not to unbounded", 0, 2, DefaultUpperSizeBytes},
		{"no containers falls back to the default", 2 << 30, 0, DefaultUpperSizeBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := UpperSizeBytes(tc.mem, tc.containers); got != tc.want {
				t.Fatalf("UpperSizeBytes(%d, %d) = %d, want %d", tc.mem, tc.containers, got, tc.want)
			}
		})
	}
}

// TestLinuxMountFlags pins the symbolic-option to MS_* translation, which is
// the one piece of the plan the kernel actually consumes.
func TestLinuxMountFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts []MountOption
		want uintptr
	}{
		{"none", nil, 0},
		{"read-only", []MountOption{OptionReadOnly}, 0x1},
		{"hardened pseudo fs", []MountOption{OptionNoSuid, OptionNoDev, OptionNoExec}, 0x2 | 0x4 | 0x8},
		{"read-only bind remount", []MountOption{OptionBind, OptionRemount, OptionReadOnly}, 0x1000 | 0x20 | 0x1},
		{"recursive bind", []MountOption{OptionRBind}, 0x1000 | 0x4000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := LinuxMountFlags(tc.opts)
			if err != nil {
				t.Fatalf("LinuxMountFlags: %v", err)
			}
			if got != tc.want {
				t.Fatalf("flags = %#x, want %#x", got, tc.want)
			}
		})
	}

	t.Run("an unknown option is an error, never a dropped flag", func(t *testing.T) {
		t.Parallel()
		if _, err := LinuxMountFlags([]MountOption{"suid"}); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("error = %v, want ErrInvalidSpec (a dropped flag would mount a credential share writable)", err)
		}
	})
}
