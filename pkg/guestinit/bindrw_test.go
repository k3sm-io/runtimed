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
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// stageMount is the pooled-share staging mount the host emits: one read-only
// virtiofs mount that per-volume binds are taken out of.
func stageMount(tag, target string) *guestv1.GuestMount {
	return &guestv1.GuestMount{
		TagOrSource: tag, Target: target,
		Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS, ReadOnly: true,
	}
}

// bindMount is one volume bound out of a stage.
func bindMount(source, target string, readOnly bool) *guestv1.GuestMount {
	return &guestv1.GuestMount{
		TagOrSource: source, Target: target,
		Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND, ReadOnly: readOnly,
	}
}

// stepShape is the part of a MountStep these cases assert: where it goes, and
// with which options.
type stepShape struct {
	target  string
	options []MountOption
}

func shapesOf(steps []MountStep) []stepShape {
	out := make([]stepShape, 0, len(steps))
	for _, s := range steps {
		out = append(out, stepShape{target: s.Target, options: s.Options})
	}
	return out
}

func sameOptions(a, b []MountOption) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertShapes(t *testing.T, got []MountStep, want []stepShape) {
	t.Helper()
	g := shapesOf(got)
	if len(g) != len(want) {
		t.Fatalf("got %d steps %+v, want %d %+v", len(g), g, len(want), want)
	}
	for i := range want {
		if g[i].target != want[i].target || !sameOptions(g[i].options, want[i].options) {
			t.Errorf("step %d = {%s %v}, want {%s %v}", i, g[i].target, g[i].options, want[i].target, want[i].options)
		}
	}
}

// TestPodMountsBindWritability is the gate on every emptyDir being read-only
// inside a vm guest. Two containers sharing a default-medium emptyDir at
// /shared reported, from the init container:
//
//	sh: can't create /shared/from-init.txt: Read-only file system
//
// while the VZ device, the share plan and the guest spec all said writable. The
// staging mount is read-only ON PURPOSE — it exists only so a subdirectory can
// be bound out of it, and a writable stage would hand every container the whole
// pooled share — but a bind INHERITS its source mount's writability, and only
// the opposite direction (a read-only bind out of a writable source) had ever
// been handled.
func TestPodMountsBindWritability(t *testing.T) {
	t.Parallel()
	const (
		stage   = "/run/k3sm/shares/k3sm.vols"
		projSt  = "/run/k3sm/shares/k3sm.proj"
		volsSrc = stage + "/sh"
		projSrc = projSt + "/token"
	)

	t.Run("a-writable-bind-out-of-a-read-only-stage-gets-a-clearing-remount", func(t *testing.T) {
		t.Parallel()
		got, err := PodMounts([]*guestv1.GuestMount{
			stageMount("k3sm.vols", stage),
			bindMount(volsSrc, "/shared", false),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		assertShapes(t, got, []stepShape{
			// The stage is mounted WRITABLE at the superblock and made read-only
			// at the mount, so a bind out of it can carry its own writability.
			{stage, []MountOption{OptionNoSuid, OptionNoDev}},
			{stage, []MountOption{OptionBind, OptionRemount, OptionReadOnly}},
			// The bind, then the remount that CLEARS the inherited read-only.
			{"/shared", []MountOption{OptionBind}},
			{"/shared", []MountOption{OptionBind, OptionRemount}},
		})
	})

	t.Run("a-read-only-bind-out-of-the-same-stage-still-sets-read-only", func(t *testing.T) {
		t.Parallel()
		// The direction that already worked must keep working: a projected
		// credential bind stays read-only. mounts.go's own warning is that "a bind
		// that skipped the remount would expose a credential file writable", and
		// the new clearing remount must never be the one that reaches it.
		got, err := PodMounts([]*guestv1.GuestMount{
			stageMount("k3sm.proj", projSt),
			bindMount(projSrc, "/var/run/secrets/kubernetes.io/serviceaccount", true),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		assertShapes(t, got, []stepShape{
			// No writable bind sources from this stage, so it keeps the stronger
			// superblock read-only.
			{projSt, []MountOption{OptionNoSuid, OptionNoDev, OptionReadOnly}},
			{"/var/run/secrets/kubernetes.io/serviceaccount", []MountOption{OptionBind}},
			{"/var/run/secrets/kubernetes.io/serviceaccount", []MountOption{OptionBind, OptionRemount, OptionReadOnly}},
		})
	})

	t.Run("both-directions-out-of-one-stage-keep-their-own-writability", func(t *testing.T) {
		t.Parallel()
		// The case that catches a fix applied by tag or applied to the whole
		// stage: one read-only and one writable bind out of the SAME stage.
		got, err := PodMounts([]*guestv1.GuestMount{
			stageMount("k3sm.proj", projSt),
			bindMount(projSrc, "/secrets", true),
			bindMount(projSt+"/scratch", "/scratch", false),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		assertShapes(t, got, []stepShape{
			{projSt, []MountOption{OptionNoSuid, OptionNoDev}},
			{projSt, []MountOption{OptionBind, OptionRemount, OptionReadOnly}},
			{"/secrets", []MountOption{OptionBind}},
			{"/secrets", []MountOption{OptionBind, OptionRemount, OptionReadOnly}},
			{"/scratch", []MountOption{OptionBind}},
			{"/scratch", []MountOption{OptionBind, OptionRemount}},
		})
	})

	t.Run("a-remount-always-immediately-follows-its-own-bind", func(t *testing.T) {
		t.Parallel()
		// Ordering is the property an interleave would break: a remount names its
		// target, so a remount that landed after the NEXT bind would still apply
		// to the right mount — but only until two binds share a target prefix, and
		// the invariant is cheap to hold and cheap to assert.
		got, err := PodMounts([]*guestv1.GuestMount{
			stageMount("k3sm.vols", stage),
			bindMount(stage+"/a", "/a", false),
			bindMount(stage+"/b", "/b", true),
			bindMount(stage+"/c", "/c", false),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		for i, s := range got {
			if !hasOption(s.Options, OptionRemount) {
				continue
			}
			if i == 0 {
				t.Fatalf("step 0 is a remount with no bind before it: %+v", s)
			}
			prev := got[i-1]
			if hasOption(prev.Options, OptionRemount) {
				t.Errorf("step %d is a remount following another remount (%s); each remount must follow its own bind", i, prev.Target)
			}
			if prev.Target != s.Target {
				t.Errorf("step %d remounts %s but follows a mount of %s; a remount must immediately follow its own bind",
					i, s.Target, prev.Target)
			}
		}
	})

	t.Run("a-writable-bind-out-of-a-writable-source-gets-no-remount", func(t *testing.T) {
		t.Parallel()
		// The remount is emitted for a reason, not by reflex: with nothing
		// read-only above it there is nothing to clear.
		got, err := PodMounts([]*guestv1.GuestMount{
			{TagOrSource: "k3sm.vols", Target: stage, Kind: guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS},
			bindMount(volsSrc, "/shared", false),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		assertShapes(t, got, []stepShape{
			{stage, []MountOption{OptionNoSuid, OptionNoDev}},
			{"/shared", []MountOption{OptionBind}},
		})
	})

	t.Run("a-read-only-mount-nothing-binds-out-of-keeps-superblock-read-only", func(t *testing.T) {
		t.Parallel()
		// The rootfs lower layer and the spec share must keep SB_RDONLY: it is the
		// stronger posture, and the per-mount form is taken only where a writable
		// bind forces it.
		got, err := PodMounts([]*guestv1.GuestMount{
			stageMount("k3sm.rootfs", "/run/k3sm/lower/app"),
		}, 0)
		if err != nil {
			t.Fatalf("PodMounts: %v", err)
		}
		assertShapes(t, got, []stepShape{
			{"/run/k3sm/lower/app", []MountOption{OptionNoSuid, OptionNoDev, OptionReadOnly}},
		})
	})
}

// TestLinuxMountFlagsClearingRemount pins the flag word the clearing remount
// translates to: MS_BIND|MS_REMOUNT and, load-bearing, NO MS_RDONLY.
func TestLinuxMountFlagsClearingRemount(t *testing.T) {
	t.Parallel()
	got, err := LinuxMountFlags([]MountOption{OptionBind, OptionRemount})
	if err != nil {
		t.Fatalf("LinuxMountFlags: %v", err)
	}
	const wantBindRemount = 0x1000 | 0x20
	if got != wantBindRemount {
		t.Fatalf("flags = %#x, want %#x", got, wantBindRemount)
	}
	if got&0x1 != 0 {
		t.Fatal("the clearing remount carries MS_RDONLY; it exists to remove it")
	}
}
