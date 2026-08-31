//go:build darwin

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"k3sm.io/runtimed/pkg/guestinit"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// WHERE THE TWO DELIVERABLES MEET: the container mapper (M11.2-d11, this
// package) and the guest-spec writer (M11.2-d10, pkg/sandbox) are joined by the
// guest's own reader (pkg/guestinit), and the join is asserted end to end.
//
// It lives HERE, not in pkg/sandbox's round-trip, because the import direction
// forbids the alternative: pkg/runtime imports pkg/sandbox, so sandbox's tests
// cannot reach the mapper and their fixture has to hand-write the containers it
// feeds the composer. Driving the REAL CreateVM from this side is also strictly
// stronger than calling the composer would be — what is planned below is the
// FILE the guest will actually read off its k3sm.spec share, not an in-memory
// message that resembles it.
//
// It is darwin-gated for the one reason CreateVM is: off darwin the boot is a
// typed refusal (ErrVMBootNotImplemented), because the helper it spawns is a
// macOS binary. Every seam that would need a hypervisor is faked; nothing here
// needs an entitlement, a VZ machine or a guest.

// vmLabBackend wires a REAL *sandbox.VMBackend over fake spawn/reap/health
// seams: it writes the machine description and the boot contract exactly as
// production does, and then "spawns" and "reaches" a helper that does not exist.
func vmLabBackend(t *testing.T, root string) (*sandbox.VMBackend, *blockingWaiter, int) {
	t.Helper()
	helper := filepath.Join(root, "bin", sandbox.VMHostName)
	kernel := filepath.Join(root, "guest", "Image")
	initramfs := filepath.Join(root, "guest", "initramfs.cpio")
	for _, p := range []string{helper, kernel, initramfs} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("lab dir for %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("lab file %s: %v", p, err)
		}
	}
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	b := sandbox.NewVMBackend(
		sandbox.WithStateRoot(root),
		sandbox.WithGuestArtifacts(func() (sandbox.GuestArtifacts, error) {
			return sandbox.GuestArtifacts{KernelPath: kernel, InitramfsPath: initramfs, Cmdline: "console=hvc0 panic=1"}, nil
		}),
		sandbox.WithVMHostLocator(func() (string, error) { return helper, nil }),
		sandbox.WithVMProcessSeams(sp, w,
			// Ready on the first probe: the readiness state machine is d9's
			// gate, not this one's.
			func(context.Context, string) error { return nil },
			func(int, os.Signal) error { return nil },
			func(pid int) (int64, bool) { return int64(pid) * 1000, true },
			func(pgid int) ([]supervisor.ProcMember, bool) {
				return []supervisor.ProcMember{{Pid: pgid, StartUnixNano: int64(pgid) * 1000}}, true
			}),
	)
	// fakeSpawner hands out 1001 for the first spawn; the waiter is released
	// with it at teardown so the helper's reaper goroutine returns.
	return b, w, 1001
}

// TestVMPodBootContractSatisfiesGuestInit composes a REAL multi-container vm pod
// — mapped from a PodBox against real image configs, written by the real
// producer — and feeds the file it wrote to the REAL guest reader.
//
// NON-VACUITY IS THE POINT. Every value asserted below is one the fixture never
// handed the composer: the argv comes out of the four-quadrant merge of image
// Entrypoint/Cmd against pod args, the env out of the image's own entries
// overridden by the pod's, and the rootfs tag out of the share plan. A test that
// asserted values typed into the spec would prove only that a struct survives a
// marshal.
func TestVMPodBootContractSatisfiesGuestInit(t *testing.T) {
	const (
		initRef = "docker.io/library/initdb:1"
		mainRef = "docker.io/library/postgres:16"
	)
	w := newImageWorld(map[string]image.ImageRunConfig{
		initRef: {
			Entrypoint: []string{"/usr/bin/initdb"},
			Cmd:        []string{"--pgdata=$(PGDATA)"},
			Env:        []string{"PATH=/usr/bin", "PGDATA=/pgdata"},
			WorkingDir: "/",
		},
		mainRef: {
			Entrypoint: []string{"/usr/local/bin/postgres"},
			Cmd:        []string{"-D", "/pgdata"},
			Env:        []string{"PATH=/usr/local/bin", "PGDATA=/pgdata", "LANG=C"},
			WorkingDir: "/var/lib/postgresql",
		},
	})

	cfg, deps := vmPodConfig(t, Deps{Puller: w, Unpacker: w})
	vmb, waiter, helperPID := vmLabBackend(t, cfg.Root)
	deps.VMBackend = vmb
	rt := newTestRuntimeCfg(t, cfg, deps)

	const podID = "pod-guestcontract"
	box := vmBoxWith(rt, podID,
		[]*runtimev1.Container{{Name: "init-db", Image: initRef}},
		[]*runtimev1.Container{{
			Name:  "postgres",
			Image: mainRef,
			// Args alone: the image's Entrypoint is kept and its Cmd replaced —
			// the quadrant whose result no part of this fixture states.
			Args: []string{"-D", "/pgdata", "-c", "lc_messages=$(LANG)"},
			Env:  []*runtimev1.EnvVar{{Name: "LANG", Value: "en_US.UTF-8"}},
			VolumeMounts: []*runtimev1.VolumeMount{
				{Name: "pgdata", MountPath: "/pgdata"},
				{Name: "shm", MountPath: "/dev/shm"},
			},
		}})
	box.Volumes = []*runtimev1.Volume{
		{Name: "pgdata", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
		{Name: "shm", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory", SizeLimit: "64Mi"}},
	}
	box.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsUser: 999, RunAsGroup: 999, FsGroup: 2000}

	// createVMPod is entered DIRECTLY rather than through CreatePod, because
	// SelectBackend gates on VMBackend.Available(), which requires a validly
	// signed helper carrying com.apple.security.virtualization — a rig property
	// this test deliberately does not have. The routing decision itself is
	// proven by TestCreatePodVMRoutingBypassesHostProcessSteps; what is under
	// test here is everything after it.
	p, reason, err := rt.createVMPod(context.Background(), box, box.GetSandboxProfile())
	if err != nil {
		t.Fatalf("createVMPod: %v (reason %v)", err, reason)
	}
	t.Cleanup(func() {
		p.cancel()
		waiter.release(helperPID)
		_ = vmb.StopVM(context.Background(), podID, time.Second)
	})

	specPath := filepath.Join(mustPodDir(t, rt, podID), guestinit.SpecShareTag, sandbox.VMGuestSpecFileName)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("the boot contract is missing from the k3sm.spec share root: %v", err)
	}
	var gs guestv1.GuestSpec
	// Unknown fields REJECTED — the same strictness the guest init reads with,
	// so a spec the guest would refuse fails here instead of on a rig.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &gs); err != nil {
		t.Fatalf("the written guest spec does not decode as a guestv1.GuestSpec: %v\n%s", err, raw)
	}

	plan, err := guestinit.Plan(&gs, guestinit.Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("the guest refused the contract this host composed for a real pod: %v", err)
	}

	t.Run("the guest plans the pod's containers in start order", func(t *testing.T) {
		if len(plan.Containers) != 2 {
			t.Fatalf("plan has %d containers, want 2 — an empty list is the pre-d11 state", len(plan.Containers))
		}
		if plan.Containers[0].Name != "init-db" || !plan.Containers[0].WaitForExit {
			t.Errorf("first container = %q (wait=%v), want init-db waited to completion",
				plan.Containers[0].Name, plan.Containers[0].WaitForExit)
		}
		if plan.Containers[1].Name != "postgres" || plan.Containers[1].WaitForExit {
			t.Errorf("second container = %q (wait=%v), want postgres not waited for",
				plan.Containers[1].Name, plan.Containers[1].WaitForExit)
		}
	})

	t.Run("the merged argv crossed intact", func(t *testing.T) {
		// Quadrant 1: image Entrypoint + image Cmd, with $(PGDATA) expanded
		// against the image's own environment.
		wantInit := "/usr/bin/initdb --pgdata=/pgdata"
		if got := strings.Join(plan.Containers[0].Argv, " "); got != wantInit {
			t.Errorf("init-db argv = %q, want %q", got, wantInit)
		}
		// Quadrant 2: image Entrypoint + POD args, with $(LANG) expanded against
		// the pod's override of the image's LANG.
		wantMain := "/usr/local/bin/postgres -D /pgdata -c lc_messages=en_US.UTF-8"
		if got := strings.Join(plan.Containers[1].Argv, " "); got != wantMain {
			t.Errorf("postgres argv = %q, want %q", got, wantMain)
		}
	})

	t.Run("the merged environment crossed intact", func(t *testing.T) {
		env := strings.Join(plan.Containers[1].Env, "\n")
		for _, want := range []string{"PATH=/usr/local/bin", "PGDATA=/pgdata", "LANG=en_US.UTF-8"} {
			if !strings.Contains(env, want) {
				t.Errorf("postgres env is missing %q:\n%s", want, env)
			}
		}
		if strings.Contains(env, "LANG=C") {
			t.Errorf("postgres env still carries the image's LANG=C; the pod's entry must override it in place:\n%s", env)
		}
	})

	t.Run("each container's rootfs lower is a share the machine actually carries", func(t *testing.T) {
		declared := map[string]bool{}
		for _, s := range mustVMHostShares(t, mustPodDir(t, rt, podID)) {
			declared[s] = true
		}
		for _, c := range plan.Containers {
			lower, ok := findMountStep(c.Mounts, guestinit.ContainerLowerDir(c.Name))
			if !ok {
				t.Errorf("container %q has no rootfs lower mount", c.Name)
				continue
			}
			if !declared[lower.Source] {
				t.Errorf("container %q would mount virtiofs tag %q, which the machine description does not attach (declared: %v)",
					c.Name, lower.Source, declared)
			}
		}
	})

	t.Run("the identity the guest will drop to is the pod's", func(t *testing.T) {
		for _, c := range plan.Containers {
			if c.Ident.UID != 999 || c.Ident.GID != 999 {
				t.Errorf("%s ident = %d/%d, want the pod's 999/999", c.Name, c.Ident.UID, c.Ident.GID)
			}
			if !containsInt64(c.Ident.Groups, 2000) {
				t.Errorf("%s supplemental groups = %v, want the pod fsGroup 2000 among them", c.Name, c.Ident.Groups)
			}
		}
	})
}

// mustVMHostShares returns the virtiofs tags the written machine description
// attaches — the OTHER file the same boot wrote, so the guest-side tags are
// checked against what the hypervisor is actually told to attach rather than
// against the plan the daemon computed.
func mustVMHostShares(t *testing.T, podDir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(podDir, sandbox.VMSpecFileName))
	if err != nil {
		t.Fatalf("read the machine description: %v", err)
	}
	var hs guestv1.VMHostSpec
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &hs); err != nil {
		t.Fatalf("the machine description does not decode: %v\n%s", err, raw)
	}
	tags := make([]string, 0, len(hs.GetShares()))
	for _, s := range hs.GetShares() {
		tags = append(tags, s.GetTag())
	}
	return tags
}

// findMountStep returns the first mount step at target.
func findMountStep(steps []guestinit.MountStep, target string) (guestinit.MountStep, bool) {
	for _, s := range steps {
		if s.Target == target {
			return s, true
		}
	}
	return guestinit.MountStep{}, false
}
