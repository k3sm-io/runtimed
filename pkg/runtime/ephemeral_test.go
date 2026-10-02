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
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	ephMainRef  = "example.com/main:v1"
	ephDebugRef = "example.com/debug:v1"
	ephRootRef  = "example.com/rootdebug:v1"
)

// profileBackend records the compiled profile and launch spec of every wrap,
// so a test can compare an ephemeral container's confinement with the one its
// pod was created under.
type profileBackend struct {
	mu       sync.Mutex
	profiles []string
	specs    []supervisor.LaunchSpec
}

func (b *profileBackend) Available() bool { return true }
func (b *profileBackend) Name() string    { return "profile-recording" }
func (b *profileBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.profiles = append(b.profiles, profile)
	b.specs = append(b.specs, spec)
	b.mu.Unlock()
	return fakeBackend{available: true}.WrapCommand(ctx, profile, argv, spec)
}

func (b *profileBackend) wraps() ([]string, []supervisor.LaunchSpec) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.profiles...), append([]supervisor.LaunchSpec(nil), b.specs...)
}

// policySigner records the policy every signature check was asked under and
// can be told to reject.
type policySigner struct {
	mu       sync.Mutex
	policies []runtimev1.SignaturePolicy
	deny     bool
}

func (s *policySigner) Sign(context.Context, string) error { return nil }

func (s *policySigner) Check(_ context.Context, policy runtimev1.SignaturePolicy, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = append(s.policies, policy)
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		return image.ErrPolicyUnspecified
	}
	if s.deny {
		return fmt.Errorf("test signer rejects %s: %w", path, image.ErrSignatureRejected)
	}
	return nil
}

func (s *policySigner) set(deny bool) {
	s.mu.Lock()
	s.deny = deny
	s.mu.Unlock()
}

func (s *policySigner) seen() []runtimev1.SignaturePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]runtimev1.SignaturePolicy(nil), s.policies...)
}

// ephHarness is a running native pod with one main container.
type ephHarness struct {
	rt     *Runtime
	sp     *fakeSpawner
	be     *profileBackend
	signer *policySigner
	kills  *killLog
	slow   *slowPuller
	box    *runtimev1.PodBox
	podID  string
}

func newEphHarness(t *testing.T, podID string, mutate func(*runtimev1.PodBox)) *ephHarness {
	t.Helper()
	world := newImageWorld(map[string]image.ImageRunConfig{
		ephMainRef:  {Cmd: []string{"/app"}},
		ephDebugRef: {Cmd: []string{"/app"}},
		ephRootRef:  {Cmd: []string{"/app"}, User: "0"},
	})
	h := &ephHarness{
		sp: &fakeSpawner{}, be: &profileBackend{}, signer: &policySigner{}, kills: newKillLog(),
		podID: podID,
	}
	h.slow = &slowPuller{delay: 25 * time.Millisecond}
	h.rt = newTestRuntime(t, Deps{
		Puller:      &worldPuller{world: world, slow: h.slow},
		Unpacker:    world,
		Spawner:     h.sp,
		Waiter:      newBlockingWaiter(),
		Backend:     h.be,
		Signer:      h.signer,
		SignalGroup: h.kills.signal,
	})
	h.box = pullBox(h.rt, podID, raceContainer("main", ephMainRef))
	if mutate != nil {
		mutate(h.box)
	}
	resp, err := h.rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: h.box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	return h
}

// worldPuller routes an imageWorld through a slowPuller's arm/notify, so a
// race subtest can hold one pull open.
type worldPuller struct {
	world *imageWorld
	slow  *slowPuller
}

func (w *worldPuller) Pull(ctx context.Context, ref string, cred *image.RegistryCredential, policy image.PlatformPolicy, pull runtimev1.ImagePullPolicy) (*image.PullResult, error) {
	w.slow.mu.Lock()
	armed := w.slow.notified != nil && ref == w.slow.notifyRef
	if armed {
		close(w.slow.notified)
		w.slow.notified = nil
	}
	w.slow.mu.Unlock()
	if armed {
		select {
		case <-time.After(w.slow.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return w.world.Pull(ctx, ref, cred, policy, pull)
}

// appendRequest is the stored box with extra ephemeral containers appended.
func (h *ephHarness) appendRequest(cs ...*runtimev1.Container) *runtimev1.PodBox {
	req, _ := proto.Clone(h.storedBox()).(*runtimev1.PodBox)
	req.EphemeralContainers = append(req.EphemeralContainers, cs...)
	return req
}

func (h *ephHarness) pod() *pod {
	h.rt.mu.Lock()
	defer h.rt.mu.Unlock()
	return h.rt.pods[h.podID]
}

func (h *ephHarness) storedBox() *runtimev1.PodBox {
	p := h.pod()
	p.mu.Lock()
	defer p.mu.Unlock()
	box, _ := proto.Clone(p.box).(*runtimev1.PodBox)
	return box
}

func (h *ephHarness) update(t *testing.T, box *runtimev1.PodBox) *runtimev1.UpdatePodResponse {
	t.Helper()
	resp, err := h.rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("UpdatePod: %v", err)
	}
	return resp
}

func ephemeralStatus(st *runtimev1.PodStatus, name string) *runtimev1.ContainerStatus {
	for _, cs := range st.GetEphemeralContainerStatuses() {
		if cs.GetName() == name {
			return cs
		}
	}
	return nil
}

func (h *ephHarness) spawnCount(t *testing.T, name string) int {
	t.Helper()
	n := 0
	for _, got := range spawnedNames(t, h.sp, []string{"main", "debug", "rootdebug", "twin"}) {
		if got == name {
			n++
		}
	}
	return n
}

// TestUpdatePodAppendsEphemeralContainer is the ephemeral-container gate on the
// runtime: an append through UpdatePod starts the new container through the
// same resolve path as any container, under the pod's create-time profile and
// signature policy whatever the request says, and reports it in
// ephemeral_container_statuses; the list is append-only; a stopping,
// terminated or vm pod refuses; a re-created pod records its ephemeral
// containers without starting them; and no interleaving with DeletePod or with
// a second append leaves a process the pod does not track.
func TestUpdatePodAppendsEphemeralContainer(t *testing.T) {
	t.Run("a native append runs under the create-time profile and policy", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-native", nil)
		createProfiles, createSpecs := h.be.wraps()
		if len(createProfiles) != 1 {
			t.Fatalf("create wrapped %d containers, want 1", len(createProfiles))
		}

		req := h.appendRequest(raceContainer("debug", ephDebugRef))
		// Everything the request could use to widen the container is changed:
		// none of it may be adopted.
		req.SignaturePolicy = runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED
		req.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsUser: 4242}
		req.Annotations = map[string]string{"k3sm.io/signature-policy": "unrestricted"}
		req.Volumes = append(req.Volumes, &runtimev1.Volume{Name: "extra", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})

		resp := h.update(t, req)
		if resp.GetError() != nil {
			t.Fatalf("UpdatePod: %v (%v)", resp.GetError(), resp.GetFailureReason())
		}
		cs := ephemeralStatus(resp.GetStatus(), "debug")
		if cs == nil || cs.GetState().GetRunning() == nil {
			t.Fatalf("debug status = %v, want running under ephemeral_container_statuses", cs)
		}
		for _, other := range resp.GetStatus().GetContainerStatuses() {
			if other.GetName() == "debug" {
				t.Error("debug also reports as a regular container")
			}
		}
		if got := h.spawnCount(t, "debug"); got != 1 {
			t.Fatalf("debug spawned %d times, want 1", got)
		}

		profiles, specs := h.be.wraps()
		if len(profiles) != 2 {
			t.Fatalf("wraps = %d, want 2", len(profiles))
		}
		if profileDigest(profiles[1]) != profileDigest(createProfiles[0]) || profiles[1] != createProfiles[0] {
			t.Error("the ephemeral container was confined by a profile other than the one the pod was created under")
		}
		if specs[1].Cred.UID != createSpecs[0].Cred.UID || specs[1].Cred.UID == 4242 {
			t.Errorf("ephemeral uid = %d, create uid = %d; the request's run_as_user was adopted",
				specs[1].Cred.UID, createSpecs[0].Cred.UID)
		}
		for _, pol := range h.signer.seen() {
			if pol != runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK {
				t.Errorf("a signature check ran under %v; only the create-time ADHOC_OK may apply", pol)
			}
		}
		stored := h.storedBox()
		if stored.GetSignaturePolicy() != runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK ||
			stored.GetPodSecurityContext().GetRunAsUser() != 0 || len(stored.GetVolumes()) != 0 {
			t.Errorf("the stored box adopted request fields: %v", stored)
		}
		if len(stored.GetEphemeralContainers()) != 1 || stored.GetEphemeralContainers()[0].GetName() != "debug" {
			t.Errorf("stored ephemeral list = %v, want [debug]", stored.GetEphemeralContainers())
		}
		if phase := resp.GetStatus().GetPhase(); phase != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want Running", phase)
		}

		rresp, err := h.rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: h.podID, Container: "debug"})
		if err != nil || rresp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("RestartContainer(debug) = %v / %v, want NOT_UPDATABLE", rresp.GetError(), err)
		}
	})

	t.Run("a stored pod-level runAsNonRoot cannot be disarmed by the request", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-nonroot", func(b *runtimev1.PodBox) {
			b.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsNonRoot: true}
		})
		req := h.appendRequest(raceContainer("rootdebug", ephRootRef))
		req.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsNonRoot: false}
		resp := h.update(t, req)
		cs := ephemeralStatus(resp.GetStatus(), "rootdebug")
		w := cs.GetState().GetWaiting()
		if w == nil || w.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG {
			t.Fatalf("rootdebug = %v, want Waiting CONTAINER_CONFIG", cs)
		}
		if !strings.Contains(w.GetMessage(), "container has runAsNonRoot and image will run as root") {
			t.Errorf("message %q lacks the kubelet text", w.GetMessage())
		}
		if got := h.spawnCount(t, "rootdebug"); got != 0 {
			t.Errorf("rootdebug spawned %d times", got)
		}
	})

	t.Run("a policy-denied image is refused", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-denied", nil)
		h.signer.set(true)
		resp := h.update(t, h.appendRequest(raceContainer("debug", ephDebugRef)))
		cs := ephemeralStatus(resp.GetStatus(), "debug")
		if w := cs.GetState().GetWaiting(); w == nil || w.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED {
			t.Fatalf("debug = %v, want Waiting SIGNATURE_REJECTED", cs)
		}
		if got := h.spawnCount(t, "debug"); got != 0 {
			t.Errorf("a rejected image was spawned %d times", got)
		}
		if resp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v; a debug container that cannot start must not hold the pod at Pending", resp.GetStatus().GetPhase())
		}
	})

	t.Run("mutating or removing an ephemeral container is NOT_UPDATABLE", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-mutate", nil)
		if resp := h.update(t, h.appendRequest(raceContainer("debug", ephDebugRef))); resp.GetError() != nil {
			t.Fatalf("append: %v", resp.GetError())
		}
		mutated := h.storedBox()
		mutated.EphemeralContainers[0].Image = ephRootRef
		removed := h.storedBox()
		removed.EphemeralContainers = nil
		for name, box := range map[string]*runtimev1.PodBox{"mutated": mutated, "removed": removed} {
			resp := h.update(t, box)
			if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
				t.Errorf("%s: reason = %v, want NOT_UPDATABLE", name, resp.GetFailureReason())
			}
		}
		if got := h.spawnCount(t, "debug"); got != 1 {
			t.Errorf("debug spawned %d times, want 1", got)
		}
	})

	t.Run("a name collision with a regular container is refused", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-collide", nil)
		for _, name := range []string{"main", "Bad_Name", "../x"} {
			resp := h.update(t, h.appendRequest(&runtimev1.Container{Name: name, Image: ephDebugRef, Command: []string{"/app-debug"}}))
			if resp.GetError() == nil || resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("%q: %v / %v, want INVALID_POD_BOX", name, resp.GetError(), resp.GetFailureReason())
			}
		}
		if n := len(h.storedBox().GetEphemeralContainers()); n != 0 {
			t.Errorf("refused appends were stored: %d", n)
		}
		if got := h.spawnCount(t, "main"); got != 1 {
			t.Errorf("main spawned %d times", got)
		}
	})

	t.Run("an append to a stopping, terminated or deleted pod is refused", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-stopping", nil)
		p := h.pod()
		req := h.appendRequest(raceContainer("debug", ephDebugRef))

		p.mu.Lock()
		p.phase = runtimev1.PodPhase_POD_PHASE_FAILED
		p.mu.Unlock()
		if resp := h.update(t, req); resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("terminated: %v, want NOT_UPDATABLE", resp.GetFailureReason())
		}
		p.mu.Lock()
		p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
		p.stopping = true
		p.mu.Unlock()
		if resp := h.update(t, req); resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND ||
			codes.Code(resp.GetError().GetCode()) != codes.FailedPrecondition {
			t.Errorf("stopping: %v, want FailedPrecondition NOT_FOUND", resp.GetError())
		}
		p.mu.Lock()
		p.stopping = false
		p.mu.Unlock()
		if _, err := h.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: h.podID}); err != nil {
			t.Fatal(err)
		}
		if resp := h.update(t, req); resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
			t.Errorf("deleted: %v, want NOT_FOUND", resp.GetFailureReason())
		}
		if got := h.spawnCount(t, "debug"); got != 0 {
			t.Errorf("debug spawned %d times into a pod that refused it", got)
		}
	})

	t.Run("CreatePod records listed ephemeral containers as not started", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-recreate", func(b *runtimev1.PodBox) {
			b.EphemeralContainers = []*runtimev1.Container{raceContainer("debug", ephDebugRef)}
		})
		st, err := h.rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: h.podID})
		if err != nil {
			t.Fatal(err)
		}
		cs := ephemeralStatus(st.GetStatus(), "debug")
		term := cs.GetState().GetTerminated()
		if term == nil || term.GetReason() != "ContainerStatusUnknown" {
			t.Fatalf("debug = %v, want terminated ContainerStatusUnknown", cs)
		}
		if got := h.spawnCount(t, "debug"); got != 0 {
			t.Errorf("a re-created pod started its ephemeral container (%d spawns)", got)
		}
		if st.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v; the recorded entry must not decide the phase", st.GetStatus().GetPhase())
		}
		sresp, _ := h.rt.StartContainer(context.Background(), &runtimev1.StartContainerRequest{PodId: h.podID, Container: "debug"})
		if sresp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("StartContainer(debug) reason = %v, want NOT_UPDATABLE (never restarted)", sresp.GetFailureReason())
		}
		if got := h.spawnCount(t, "debug"); got != 0 {
			t.Errorf("debug spawned %d times after StartContainer", got)
		}
	})

	t.Run("the vm backend answers UNSUPPORTED", func(t *testing.T) {
		rt, _, box := bootedVMRuntime(t, "pod-eph-vm", 0)
		req, _ := proto.Clone(box).(*runtimev1.PodBox)
		req.EphemeralContainers = []*runtimev1.Container{{Name: "debug", Image: "docker.io/library/busybox:1"}}
		resp, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: req})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED {
			t.Fatalf("reason = %v, want UNSUPPORTED", resp.GetFailureReason())
		}
		if !strings.Contains(resp.GetError().GetMessage(), "ephemeral containers are not supported on the vm RuntimeClass") {
			t.Errorf("message %q does not state the refusal", resp.GetError().GetMessage())
		}
	})

	t.Run("DeletePod during an append leaves no orphan spawn", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-race", nil)
		h.rt.exitObsGrace = 400 * time.Millisecond
		notified := h.slow.arm(ephDebugRef)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.rt.UpdatePod(context.Background(),
				&runtimev1.UpdatePodRequest{Pod: h.appendRequest(raceContainer("debug", ephDebugRef))})
		}()
		<-notified
		if _, err := h.rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: h.podID}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		wg.Wait()
		// Non-vacuity: the append's spawn must have landed INSIDE the teardown
		// (after DeletePod's snapshot); a race that never spawned proves nothing.
		if got := h.spawnCount(t, "debug"); got != 1 {
			t.Fatalf("debug spawned %d times; the late spawn did not land inside the teardown", got)
		}
		for pid, n := range spawnedNames(t, h.sp, []string{"main", "debug"}) {
			if !h.kills.signalled(pid) {
				t.Errorf("pid %d (%s) was spawned and never signalled", pid, n)
			}
		}
		if got := trackedPIDs(h.rt, h.podID); len(got) != 0 {
			t.Errorf("the deleted pod still tracks %v", got)
		}
		dir, err := h.rt.podReapDir(h.podID)
		if err != nil {
			t.Fatal(err)
		}
		if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
			t.Errorf("%d reap record(s) survive the delete", len(entries))
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	})

	t.Run("two concurrent appends of one name spawn once", func(t *testing.T) {
		h := newEphHarness(t, "pod-eph-twin", nil)
		notified := h.slow.arm(ephDebugRef)
		req := h.appendRequest(raceContainer("twin", ephDebugRef))
		var wg sync.WaitGroup
		resps := make([]*runtimev1.UpdatePodResponse, 2)
		for i := range resps {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if i == 1 {
					<-notified // the first append is inside its pull
				}
				resp, err := h.rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: proto.Clone(req).(*runtimev1.PodBox)})
				if err != nil {
					t.Errorf("UpdatePod: %v", err)
				}
				resps[i] = resp
			}(i)
		}
		wg.Wait()
		if got := h.spawnCount(t, "twin"); got != 1 {
			t.Fatalf("twin spawned %d times, want exactly 1", got)
		}
		tracked := trackedPIDs(h.rt, h.podID)
		for pid, n := range spawnedNames(t, h.sp, []string{"main", "twin"}) {
			if !tracked[pid] {
				t.Errorf("pid %d (%s) is spawned but untracked", pid, n)
			}
		}
		if n := len(h.storedBox().GetEphemeralContainers()); n != 1 {
			t.Errorf("stored ephemeral list has %d entries, want 1", n)
		}
	})
}
