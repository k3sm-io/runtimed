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
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// capsAgent is a guest/v1 agent answering only Health, with a scriptable
// capability set. An agent whose err is set does not answer at all, which is
// the "unobserved" state: no Health response has been read for the pod.
type capsAgent struct {
	guestv1.UnimplementedGuestAgentServer

	mu    sync.Mutex
	caps  []string
	err   error
	calls int
}

func (a *capsAgent) Health(context.Context, *guestv1.HealthRequest) (*guestv1.HealthResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	return &guestv1.HealthResponse{Ready: true, Capabilities: append([]string(nil), a.caps...)}, nil
}

func (a *capsAgent) set(caps []string, err error) {
	a.mu.Lock()
	a.caps, a.err = caps, err
	a.mu.Unlock()
}

func (a *capsAgent) healthCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// capsWithout returns this build's advertised token set minus drop: what an
// initramfs that predates exactly that token would advertise.
func capsWithout(drop string) []string {
	var out []string
	for _, tok := range guestagent.Capabilities() {
		if tok != drop {
			out = append(out, tok)
		}
	}
	return out
}

// newVMCapsRuntime is a vm-routed runtime over w whose guest dialer reaches
// agent, polling Health fast enough that a verdict lands in milliseconds.
func newVMCapsRuntime(t *testing.T, w *imageWorld, agent guestv1.GuestAgentServer) (*Runtime, *fakeVMBackend) {
	t.Helper()
	dial, _ := startFakeGuestAgent(t, agent)
	rt, vmb := newVMImageRuntimeWith(t, w, Deps{GuestDialer: dial})
	rt.guestLeasePoll = time.Millisecond
	return rt, vmb
}

// withScratchVolume gives the box's first main container an emptyDir. An
// emptyDir lives in a subdirectory of the pooled k3sm.vols share, so the guest
// spec stages that share — the guest-private mount the token check is about.
func withScratchVolume(box *runtimev1.PodBox) *runtimev1.PodBox {
	box.Containers[0].VolumeMounts = []*runtimev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}
	box.Volumes = []*runtimev1.Volume{{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}}
	return box
}

// createRunningVMPod drives CreatePod and fails unless it answered Running.
func createRunningVMPod(t *testing.T, rt *Runtime, box *runtimev1.PodBox) {
	t.Helper()
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	if got := resp.GetStatus().GetPhase(); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Fatalf("phase = %v, want RUNNING", got)
	}
}

// assertGuestCapFailure waits for the pod to fail on the missing token and
// checks the whole verdict: phase, reason, a message that names the pod and the
// fix, and exactly one StopVM carrying the pod's own grace.
func assertGuestCapFailure(t *testing.T, rt *Runtime, vmb *fakeVMBackend, podID, token string, grace time.Duration) {
	t.Helper()
	waitFor(t, 5*time.Second, "the pod to fail on the missing "+token+" token", func() bool {
		return podPhase(t, rt, podID) == runtimev1.PodPhase_POD_PHASE_FAILED
	})
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	st := gs.GetStatus()
	if st.GetReason() != vmReasonGuestCapabilityMissing {
		t.Errorf("reason = %q, want %q", st.GetReason(), vmReasonGuestCapabilityMissing)
	}
	wantMsg := "guest initramfs predates " + token + "; the daemon's pinned initramfs is required"
	if !strings.Contains(st.GetMessage(), wantMsg) || !strings.Contains(st.GetMessage(), podID) {
		t.Errorf("message = %q, want one naming pod %s and carrying %q", st.GetMessage(), podID, wantMsg)
	}
	waitFor(t, 5*time.Second, "the VM to be torn down", func() bool { return len(vmb.stops()) > 0 })
	// Keep polling past the verdict: every later Health answer is still
	// missing the token, and the teardown must not be requested again.
	time.Sleep(50 * time.Millisecond)
	stops := vmb.stops()
	if len(stops) != 1 || stops[0].podID != podID {
		t.Fatalf("StopVM calls = %v, want exactly one for %s", stops, podID)
	}
	if stops[0].grace != grace {
		t.Errorf("StopVM grace = %s, want the pod's own %s", stops[0].grace, grace)
	}
}

// TestGuestPrivateTokenAbsentFailsPod is the host half of the guest-private
// mount contract: a pod whose guest spec stages a pooled share relies on the
// guest detaching that staging root before any container starts, and a guest
// that has not said it does so is failed and torn down with a reason that
// names the fix.
//
// What keeps an older guest from running the containers at all is its own
// refusal of a spec field it does not know; this check is the legible half,
// and it must hold on the three states a Health poll can leave behind.
func TestGuestPrivateTokenAbsentFailsPod(t *testing.T) {
	world := func() *imageWorld {
		return newImageWorld(map[string]image.ImageRunConfig{vmPlainRef: {Entrypoint: []string{"/app"}}})
	}
	box := func(rt *Runtime, podID string) *runtimev1.PodBox {
		b := withScratchVolume(vmBoxWith(rt, podID, nil, []*runtimev1.Container{{Name: "c", Image: vmPlainRef}}))
		b.TerminationGracePeriodSeconds = 7
		return b
	}

	t.Run("the spec relies on the token", func(t *testing.T) {
		agent := &capsAgent{err: status.Error(codes.Unavailable, "not yet")}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := box(rt, "pod-gp-spec")
		createRunningVMPod(t, rt, b)
		_, spec := vmb.created()
		if !spec.Volumes.HasGuestPrivateMounts() {
			t.Fatal("the fixture's spec carries no guest-private mount; the gate would be vacuous")
		}
		p, ok := rt.lookupPod(b.GetPodId())
		if !ok {
			t.Fatal("the pod is not registered")
		}
		if got := p.guestRequiredCaps; len(got) != 1 || got[0] != guestagent.CapabilityGuestPrivateMounts {
			t.Errorf("required tokens = %v, want exactly [%s]", got, guestagent.CapabilityGuestPrivateMounts)
		}
	})

	t.Run("token absent fails the pod and tears the VM down", func(t *testing.T) {
		agent := &capsAgent{caps: capsWithout(guestagent.CapabilityGuestPrivateMounts)}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := box(rt, "pod-gp-absent")
		createRunningVMPod(t, rt, b)
		assertGuestCapFailure(t, rt, vmb, b.GetPodId(), guestagent.CapabilityGuestPrivateMounts, 7*time.Second)
	})

	t.Run("an old guest advertising nothing is failed the same way", func(t *testing.T) {
		agent := &capsAgent{caps: nil}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := box(rt, "pod-gp-old")
		createRunningVMPod(t, rt, b)
		assertGuestCapFailure(t, rt, vmb, b.GetPodId(), guestagent.CapabilityGuestPrivateMounts, 7*time.Second)
	})

	t.Run("token present keeps the pod running", func(t *testing.T) {
		agent := &capsAgent{caps: guestagent.Capabilities()}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := box(rt, "pod-gp-present")
		createRunningVMPod(t, rt, b)
		waitFor(t, 5*time.Second, "several Health answers", func() bool { return agent.healthCalls() >= 5 })
		if got := podPhase(t, rt, b.GetPodId()); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want RUNNING for a guest that advertises the token", got)
		}
		if stops := vmb.stops(); len(stops) != 0 {
			t.Errorf("StopVM calls = %v, want none", stops)
		}
	})

	t.Run("unobserved is no verdict, until the first answer is one", func(t *testing.T) {
		agent := &capsAgent{err: status.Error(codes.Unavailable, "booting")}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := box(rt, "pod-gp-unobserved")
		createRunningVMPod(t, rt, b)
		waitFor(t, 5*time.Second, "several unanswered polls", func() bool { return agent.healthCalls() >= 5 })
		if got := podPhase(t, rt, b.GetPodId()); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want RUNNING while no Health answer has been read", got)
		}
		if stops := vmb.stops(); len(stops) != 0 {
			t.Errorf("StopVM calls = %v before any answer, want none", stops)
		}
		agent.set(nil, nil)
		assertGuestCapFailure(t, rt, vmb, b.GetPodId(), guestagent.CapabilityGuestPrivateMounts, 7*time.Second)
	})

	t.Run("a guest whose Health never answers fails at the boot deadline", func(t *testing.T) {
		// No new timer: CreateVM's readiness IS a Health round trip, so a guest
		// that never answers one never becomes a pod at all. The boot deadline
		// decides it, and the create fails SANDBOX_SETUP with nothing to tear
		// down afterwards.
		agent := &capsAgent{err: status.Error(codes.Unavailable, "never")}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		vmb.err = &sandbox.VMBootError{PodID: "pod-gp-never", Cause: sandbox.VMBootAgentNeverReady,
			Err: errors.New("no Health response within the boot deadline")}
		b := box(rt, "pod-gp-never")
		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: b})
		if err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if resp.GetError() == nil {
			t.Fatal("CreatePod accepted a guest that never answered Health")
		}
		if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP {
			t.Errorf("reason = %v, want SANDBOX_SETUP", got)
		}
		if !strings.Contains(resp.GetError().GetMessage(), string(sandbox.VMBootAgentNeverReady)) {
			t.Errorf("message %q does not name the boot cause", resp.GetError().GetMessage())
		}
		if _, ok := rt.lookupPod(b.GetPodId()); ok {
			t.Error("a pod whose guest never answered was registered")
		}
	})

	t.Run("a spec with no guest-private mount needs no token", func(t *testing.T) {
		agent := &capsAgent{caps: nil}
		rt, vmb := newVMCapsRuntime(t, world(), agent)
		b := vmBoxWith(rt, "pod-gp-none", nil, []*runtimev1.Container{{Name: "c", Image: vmPlainRef}})
		createRunningVMPod(t, rt, b)
		waitFor(t, 5*time.Second, "several Health answers", func() bool { return agent.healthCalls() >= 5 })
		if got := podPhase(t, rt, b.GetPodId()); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want RUNNING: an old guest serves a spec that relies on no new field", got)
		}
		if stops := vmb.stops(); len(stops) != 0 {
			t.Errorf("StopVM calls = %v, want none", stops)
		}
	})
}
