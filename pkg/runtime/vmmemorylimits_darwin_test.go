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
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// composedVMBoot is what a real create left behind for the guest: the
// guest-spec.json bytes, their decode with the guest init's own strictness, and
// the plan the guest's own reader makes of them.
type composedVMBoot struct {
	pod  *pod
	raw  string
	spec *guestv1.GuestSpec
	plan *guestinit.BootPlan
}

// composeVMBoot drives createVMPod over a real *sandbox.VMBackend (see
// vmLabBackend) and reads back the file the guest would read.
func composeVMBoot(t *testing.T, podID string, inits, mains []*runtimev1.Container) composedVMBoot {
	t.Helper()
	w := newImageWorld(map[string]image.ImageRunConfig{vmPlainRef: {Entrypoint: []string{"/app"}}})
	cfg, deps := vmPodConfig(t, Deps{Puller: w, Unpacker: w})
	vmb, waiter, helperPID := vmLabBackend(t, cfg.Root)
	deps.VMBackend = vmb
	rt := newTestRuntimeCfg(t, cfg, deps)

	box := vmBoxWith(rt, podID, inits, mains)
	p, reason, err := rt.createVMPod(context.Background(), box, box.GetSandboxProfile())
	if err != nil {
		t.Fatalf("createVMPod: %v (reason %v)", err, reason)
	}
	t.Cleanup(func() {
		p.cancel()
		waiter.release(helperPID)
		_ = vmb.StopVM(context.Background(), podID, time.Second)
	})

	raw, err := os.ReadFile(filepath.Join(mustPodDir(t, rt, podID), guestinit.SpecShareTag, sandbox.VMGuestSpecFileName))
	if err != nil {
		t.Fatalf("read the written guest spec: %v", err)
	}
	gs := &guestv1.GuestSpec{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, gs); err != nil {
		t.Fatalf("decode the written guest spec: %v\n%s", err, raw)
	}
	plan, err := guestinit.Plan(gs, guestinit.Options{MemTotalBytes: 2 << 30})
	if err != nil {
		t.Fatalf("the guest refused the spec this host composed: %v\n%s", err, raw)
	}
	return composedVMBoot{pod: p, raw: string(raw), spec: gs, plan: plan}
}

// TestVMContainerMemoryLimitsReachGuestSpec is the gate for the per-container
// memory limit: runtime/v1 Container.memory_limit_bytes has to arrive in the
// file the guest init reads, with a memory.high this host derived.
//
// The negative half carries as much weight as the positive one. The pinned
// initramfs predates the fields and refuses a spec that sets them, so a pod with
// no limit must compose a spec that does not mention them and must require no
// token, or every vm pod on that pin would fail.
func TestVMContainerMemoryLimitsReachGuestSpec(t *testing.T) {
	limited := func(name string, limit int64) *runtimev1.Container {
		return &runtimev1.Container{Name: name, Image: vmPlainRef, MemoryLimitBytes: limit}
	}

	t.Run("a limit reaches the spec and the guest plan", func(t *testing.T) {
		const limit, high = int64(512 << 20), int64(483183820)
		boot := composeVMBoot(t, "pod-mem-set", nil, []*runtimev1.Container{limited("app", limit)})

		got := boot.spec.GetContainers()[0]
		if got.GetMemoryLimitBytes() != limit || got.GetMemoryHighBytes() != high {
			t.Errorf("guest container limit/high = %d/%d, want %d/%d", got.GetMemoryLimitBytes(), got.GetMemoryHighBytes(), limit, high)
		}
		planned := boot.plan.Containers[0]
		if planned.MemoryMaxBytes != limit || planned.MemoryHighBytes != high {
			t.Errorf("guest plan memory.max/memory.high = %d/%d, want %d/%d", planned.MemoryMaxBytes, planned.MemoryHighBytes, limit, high)
		}
		if got := boot.pod.guestRequiredCaps; len(got) != 1 || got[0] != guestagent.CapabilityMemoryLimits {
			t.Errorf("required tokens = %v, want exactly [%s]", got, guestagent.CapabilityMemoryLimits)
		}
	})

	t.Run("no limit leaves the spec without the fields and requires no token", func(t *testing.T) {
		boot := composeVMBoot(t, "pod-mem-none", nil, []*runtimev1.Container{{Name: "app", Image: vmPlainRef}})

		for _, field := range []string{"memoryLimitBytes", "memoryHighBytes"} {
			if strings.Contains(boot.raw, field) {
				t.Errorf("guest-spec.json mentions %s for a pod with no limit, and the pinned initramfs refuses that:\n%s", field, boot.raw)
			}
		}
		if planned := boot.plan.Containers[0]; planned.MemoryMaxBytes != 0 || planned.MemoryHighBytes != 0 {
			t.Errorf("guest plan memory.max/memory.high = %d/%d, want 0/0", planned.MemoryMaxBytes, planned.MemoryHighBytes)
		}
		if got := boot.pod.guestRequiredCaps; len(got) != 0 {
			t.Errorf("required tokens = %v, want none", got)
		}
	})

	t.Run("a limit stays on the container that set it", func(t *testing.T) {
		boot := composeVMBoot(t, "pod-mem-mixed",
			[]*runtimev1.Container{{Name: "setup", Image: vmPlainRef}},
			[]*runtimev1.Container{limited("app", 1000), {Name: "side", Image: vmPlainRef}})

		want := map[string][2]int64{"setup": {0, 0}, "app": {1000, 900}, "side": {0, 0}}
		for _, c := range boot.spec.GetContainers() {
			if got := [2]int64{c.GetMemoryLimitBytes(), c.GetMemoryHighBytes()}; got != want[c.GetName()] {
				t.Errorf("container %s limit/high = %v, want %v", c.GetName(), got, want[c.GetName()])
			}
		}
		if got := boot.pod.guestRequiredCaps; len(got) != 1 || got[0] != guestagent.CapabilityMemoryLimits {
			t.Errorf("required tokens = %v, want exactly [%s]", got, guestagent.CapabilityMemoryLimits)
		}
	})

	// The expected values are literals, not the formula again. The rounding is
	// down: memory.high may never exceed memory.max, and the guest refuses a spec
	// where it does.
	derivations := []struct {
		name        string
		limit, high int64
	}{
		{"an exact tenth", 1000, 900},
		{"a fraction above one half rounds down", 1001, 900},
		{"a fraction below one half rounds down", 1009, 908},
		{"a limit below ten", 9, 8},
		{"a limit whose derivation rounds to zero leaves memory.high unset", 1, 0},
		{"the largest limit does not overflow", math.MaxInt64, 8301034833169298226},
	}
	for _, tc := range derivations {
		t.Run("derivation: "+tc.name, func(t *testing.T) {
			boot := composeVMBoot(t, "pod-mem-derive", nil, []*runtimev1.Container{limited("app", tc.limit)})
			got := boot.spec.GetContainers()[0]
			if got.GetMemoryLimitBytes() != tc.limit || got.GetMemoryHighBytes() != tc.high {
				t.Errorf("limit/high = %d/%d, want %d/%d", got.GetMemoryLimitBytes(), got.GetMemoryHighBytes(), tc.limit, tc.high)
			}
		})
	}

	t.Run("a negative limit is refused before any pull", func(t *testing.T) {
		w := newImageWorld(map[string]image.ImageRunConfig{vmPlainRef: {Entrypoint: []string{"/app"}}})
		rt, vmb := newVMImageRuntime(t, w)
		box := vmBoxWith(rt, "pod-mem-negative", nil, []*runtimev1.Container{limited("app", -1)})
		_, reason, err := rt.createVMPod(context.Background(), box, box.GetSandboxProfile())
		if !errors.Is(err, errInvalidPodBox) || reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Fatalf("createVMPod = %v (reason %v), want errInvalidPodBox with INVALID_POD_BOX", err, reason)
		}
		if pulled, _, _ := w.observed(); len(pulled) != 0 {
			t.Errorf("pulled %v for a pod refused on its spec, want nothing", pulled)
		}
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("CreateVM called %d times, want 0", n)
		}
	})

	// The agent below answers Health with the token set of today's pin, so these
	// two rows are the mixed-version statement. A real guest of that pin refuses
	// a limit at boot and never answers; the row with a limit is what the host
	// does if a guest's decoder ever stops refusing.
	onPinnedGuest := func(t *testing.T, podID string, c *runtimev1.Container) (*Runtime, *fakeVMBackend, *capsAgent) {
		t.Helper()
		agent := &capsAgent{caps: pinnedGuestCapabilities}
		w := newImageWorld(map[string]image.ImageRunConfig{vmPlainRef: {Entrypoint: []string{"/app"}}})
		rt, vmb := newVMCapsRuntime(t, w, agent)
		createRunningVMPod(t, rt, vmBoxWith(rt, podID, nil, []*runtimev1.Container{c}))
		return rt, vmb, agent
	}

	t.Run("today's pinned guest keeps a pod with no limit running", func(t *testing.T) {
		const podID = "pod-mem-pin-none"
		rt, vmb, agent := onPinnedGuest(t, podID, &runtimev1.Container{Name: "app", Image: vmPlainRef})
		// The third call proves the first two answers were recorded and enforced.
		waitFor(t, 5*time.Second, "the guest to answer Health three times", func() bool { return agent.healthCalls() >= 3 })
		if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want RUNNING: the pin's missing token must not refuse a pod that sets no limit", got)
		}
		if got := vmb.stops(); len(got) != 0 {
			t.Errorf("StopVM calls = %v, want none", got)
		}
	})

	t.Run("today's pinned guest fails a pod with a limit by name", func(t *testing.T) {
		const podID = "pod-mem-pin-set"
		rt, vmb, _ := onPinnedGuest(t, podID, limited("app", 1000))
		waitFor(t, 5*time.Second, "the pod to fail on the missing token", func() bool {
			return podPhase(t, rt, podID) == runtimev1.PodPhase_POD_PHASE_FAILED
		})
		gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		if got := gs.GetStatus().GetReason(); got != vmReasonGuestCapabilityMissing {
			t.Errorf("reason = %q, want %q", got, vmReasonGuestCapabilityMissing)
		}
		if got := gs.GetStatus().GetMessage(); !strings.Contains(got, guestagent.CapabilityMemoryLimits) {
			t.Errorf("message = %q, want it to name %s", got, guestagent.CapabilityMemoryLimits)
		}
		waitFor(t, 5*time.Second, "the VM to be torn down", func() bool { return len(vmb.stops()) > 0 })
	})
}
