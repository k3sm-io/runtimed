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
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pullRef is the OCI reference every pull-route fixture in this file uses.
const pullRef = "example.com/app:v1"

// pullBox builds a PodBox whose containers take the PULL route (an OCI
// reference plus a command), against rt's own derived pod layout.
func pullBox(rt *Runtime, podID string, cs ...*runtimev1.Container) *runtimev1.PodBox {
	box := hostBinBox(rt, podID)
	box.Containers = cs
	return box
}

// pulledContainer is one container on the pull route.
func pulledContainer(name, ref string) *runtimev1.Container {
	return &runtimev1.Container{Name: name, Image: ref, Command: []string{"/app"}}
}

// statusNamed reads one container's status back through GetPodStatus, looking in
// BOTH declaration lists — a waiting init container reports under
// init_container_statuses, a waiting main under container_statuses.
func statusNamed(t *testing.T, rt *Runtime, podID, name string) *runtimev1.ContainerStatus {
	t.Helper()
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus(%s): %v", podID, err)
	}
	all := append(append([]*runtimev1.ContainerStatus(nil),
		gs.GetStatus().GetInitContainerStatuses()...),
		gs.GetStatus().GetContainerStatuses()...)
	for _, cs := range all {
		if cs.GetName() == name {
			return cs
		}
	}
	t.Fatalf("pod %s has no container status named %q (has %d)", podID, name, len(all))
	return nil
}

// assertWaiting fails unless the named container is Waiting with the expected
// typed failure_reason, and pins the two invariants a never-started container
// must always satisfy: restart_count is 0 and there is no last-termination
// state (StartContainer is not RestartContainer).
func assertWaiting(t *testing.T, rt *Runtime, podID, name string, want runtimev1.FailureReason) *runtimev1.ContainerStateWaiting {
	t.Helper()
	cs := statusNamed(t, rt, podID, name)
	w := cs.GetState().GetWaiting()
	if w == nil {
		t.Fatalf("%s/%s state = %v, want Waiting", podID, name, cs.GetState())
	}
	if w.GetFailureReason() != want {
		t.Errorf("%s/%s waiting failure_reason = %v, want %v", podID, name, w.GetFailureReason(), want)
	}
	if cs.GetRestartCount() != 0 {
		t.Errorf("%s/%s restart_count = %d; a container that never started has not restarted",
			podID, name, cs.GetRestartCount())
	}
	if cs.GetLastTerminationState() != nil {
		t.Errorf("%s/%s carries a last_termination_state %v; nothing ever terminated",
			podID, name, cs.GetLastTerminationState())
	}
	return w
}

// TestContainerStartFailureIsTypedByCause is the B119 classification gate: every
// way a container can fail BEFORE its process is spawned carries its own
// FailureReason out of startContainer, so the provider can render the kubelet's
// waiting reason (ErrImagePull / ErrImageNeverPull / InvalidImageName /
// CreateContainerConfigError) without matching on message text.
//
// # Why this is not vacuous
//
// Before this deliverable startContainer returned a blanket
// FAILURE_REASON_IMAGE_PULL for EVERY resolveBinary failure, so ten of these
// rows were indistinguishable at the RPC boundary — including the three that are
// terminal (a reference that cannot parse, an image absent under policy Never, a
// run spec that cannot be built), which a retry loop must never re-attempt on a
// pull schedule. Each row also asserts the underlying cause is still reachable
// with errors.Is, which is what keeps the typed wrapper from swallowing the
// chain every existing caller tests against.
func TestContainerStartFailureIsTypedByCause(t *testing.T) {
	cases := []struct {
		name string
		// deps are the seams the row fails at; the harness fills the rest.
		deps Deps
		// container is the container under test.
		container *runtimev1.Container
		// pullSecret makes the box carry an imagePullSecret, so the credential
		// resolver is consulted at all.
		pullSecret bool
		want       runtimev1.FailureReason
		// wantIs, when set, must still be reachable with errors.Is through the
		// typed wrapper (GO-STANDARDS §Errors).
		wantIs error
	}{
		{
			name:      "native_sentinel_without_a_command",
			container: &runtimev1.Container{Name: "c", Image: NativeImage},
			want:      runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
		},
		{
			name:      "native_command_is_not_an_absolute_host_path",
			container: &runtimev1.Container{Name: "c", Image: NativeImage, Command: []string{"sleep"}},
			want:      runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
		},
		{
			name:      "no_image_at_all",
			container: &runtimev1.Container{Name: "c"},
			want:      runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
		},
		{
			name: "the_image_pull_secret_cannot_be_resolved",
			deps: Deps{Credentials: &fakeCredentialResolver{
				err: errors.New(`secret "regcred" not found`),
			}},
			container:  pulledContainer("c", pullRef),
			pullSecret: true,
			want:       runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL,
		},
		{
			name: "the_reference_does_not_parse",
			deps: Deps{Puller: &fakePuller{errByRef: map[string]error{
				pullRef: fmt.Errorf("parse reference: %w", image.ErrInvalidReference),
			}}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME,
			wantIs:    image.ErrInvalidReference,
		},
		{
			name: "absent_under_pull_policy_never",
			deps: Deps{Puller: &fakePuller{errByRef: map[string]error{
				pullRef: fmt.Errorf("image %q: %w", pullRef, image.ErrImageNotPresent),
			}}},
			container: &runtimev1.Container{
				Name: "c", Image: pullRef, Command: []string{"/app"},
				ImagePullPolicy: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
			},
			want:   runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL,
			wantIs: image.ErrImageNotPresent,
		},
		{
			// The DISCRIMINATOR for the row above: the same sentinel under any
			// other policy is an ordinary pull failure, because only Never makes
			// "not present" the whole and final answer.
			name: "absent_without_pull_policy_never",
			deps: Deps{Puller: &fakePuller{errByRef: map[string]error{
				pullRef: fmt.Errorf("image %q: %w", pullRef, image.ErrImageNotPresent),
			}}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			wantIs:    image.ErrImageNotPresent,
		},
		{
			name: "no_manifest_matches_a_runnable_platform",
			deps: Deps{Puller: &fakePuller{errByRef: map[string]error{
				pullRef: fmt.Errorf("pull %q: %w", pullRef, image.ErrNoPlatformMatch),
			}}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH,
			wantIs:    image.ErrNoPlatformMatch,
		},
		{
			name: "the_registry_pull_failed",
			deps: Deps{Puller: &fakePuller{errByRef: map[string]error{
				pullRef: errors.New("manifest unknown: no such image"),
			}}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		},
		{
			name:      "the_image_tree_cannot_be_materialized",
			deps:      Deps{Unpacker: &fakeUnpacker{err: errors.New("layer apply failed")}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		},
		{
			name:      "the_image_config_cannot_be_read",
			deps:      Deps{Unpacker: &fakeUnpacker{cfgErr: errors.New("config blob is truncated")}},
			container: pulledContainer("c", pullRef),
			want:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
		},
		{
			name: "the_run_spec_cannot_be_built",
			deps: Deps{Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{
				Cmd: []string{"/app"}, User: "nobody",
			}}},
			container: &runtimev1.Container{
				Name: "c", Image: pullRef, Command: []string{"/app"},
				SecurityContext: &runtimev1.SecurityContext{RunAsNonRoot: true},
			},
			want:   runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG,
			wantIs: image.ErrRunSpecInvalid,
		},
		{
			name: "the_image_program_escapes_the_pod_rootfs",
			deps: Deps{Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{
				Entrypoint: []string{"../escape"},
			}}},
			container: &runtimev1.Container{Name: "c", Image: pullRef},
			want:      runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG,
			wantIs:    ErrImageArgvEscapes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const podID = "pod-classify"
			d := tc.deps
			if d.Puller == nil {
				d.Puller = &fakePuller{}
			}
			rt := newTestRuntime(t, d)
			box := pullBox(rt, podID, tc.container)
			if tc.pullSecret {
				box.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}
			}
			p := &pod{box: box, backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}

			_, reason, err := rt.startContainer(context.Background(), p,
				derivedRootfs(t, rt, podID), tc.container, false)
			if err == nil {
				t.Fatalf("startContainer succeeded; want a failure classified %v", tc.want)
			}
			if reason != tc.want {
				t.Errorf("reason = %v, want %v (err: %v)", reason, tc.want, err)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error %v no longer wraps %v; the typed wrapper must preserve the chain", err, tc.wantIs)
			}
		})
	}
}

// TestHostBinaryRoutesNeverReachTheReferenceParser pins the exemption the
// InvalidImageName reason must not swallow: the M0 native sentinel and the
// absolute-host-path convention name a HOST binary, so no reference is parsed
// and no registry is consulted for either. The puller here fails everything, so
// a row that reached it could not be green.
func TestHostBinaryRoutesNeverReachTheReferenceParser(t *testing.T) {
	for _, c := range []*runtimev1.Container{
		{Name: "c", Image: NativeImage, Command: []string{"/bin/sleep"}},
		{Name: "c", Image: "/bin/sleep"},
	} {
		t.Run(c.GetImage(), func(t *testing.T) {
			const podID = "pod-hostroute"
			rt := newTestRuntime(t, Deps{Puller: &fakePuller{
				err: fmt.Errorf("parse reference: %w", image.ErrInvalidReference),
			}})
			p := &pod{box: pullBox(rt, podID, c), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
			rb, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, podID), c)
			if err != nil {
				t.Fatalf("resolveBinary on a host-binary route: %v", err)
			}
			if !rb.hostBinary {
				t.Errorf("route resolved to %q with hostBinary=false", rb.path)
			}
		})
	}
}

// TestCreatePodStartsWhatItCanAndWaitsTheRest is the B119 partial-start gate: a
// container whose image cannot be resolved leaves the POD created, that one
// container Waiting with a typed reason, and every other container running —
// the kubelet's per-container pull semantics.
//
// # Why this is not vacuous
//
// Before this deliverable ONE bad image reference failed the whole CreatePod
// call, so the pod did not exist at all: the provider saw a pod-level failure,
// no container status was reported for the containers that were perfectly fine,
// and there was nothing to retry against. The per-reference puller seam is what
// makes the two halves observable in one call — a global failure could never
// distinguish "the pod is partly up" from "the pod is down".
func TestCreatePodStartsWhatItCanAndWaitsTheRest(t *testing.T) {
	const (
		podID   = "pod-partial"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{
		Puller:   pull,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   w,
	})
	box := pullBox(rt, podID, pulledContainer("good", goodRef), pulledContainer("bad", badRef))

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed %v (reason %v); one unresolvable image must not fail the pod",
			resp.GetError(), resp.GetFailureReason())
	}

	if got := statusNamed(t, rt, podID, "good").GetState().GetRunning(); got == nil {
		t.Errorf("the resolvable container is not running: %v", statusNamed(t, rt, podID, "good").GetState())
	}
	waiting := assertWaiting(t, rt, podID, "bad", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL)
	if !strings.Contains(waiting.GetMessage(), "manifest unknown") {
		t.Errorf("waiting message = %q, want the bounded pull error", waiting.GetMessage())
	}
	if waiting.GetReason() != "" {
		t.Errorf("waiting reason = %q; the kubelet reason string is the provider's to choose",
			waiting.GetReason())
	}
	if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_PENDING {
		t.Errorf("phase = %v, want PENDING while a container waits (kubelet getPhase order)", got)
	}
}

// TestInitFailureBlocksTheRestWithPodInitializing pins the init sequence's own
// half of the contract: a failed init container stops the sequence, so every
// later init container and every main container waits with no typed failure of
// its own and the kubelet's PodInitializing reason — they did not fail, they
// were never reached.
func TestInitFailureBlocksTheRestWithPodInitializing(t *testing.T) {
	const (
		podID   = "pod-initfail"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: fmt.Errorf("pull %q: %w", badRef, image.ErrNoPlatformMatch),
	}}
	sp := &fakeSpawner{}
	rt := newTestRuntime(t, Deps{
		Puller:   pull,
		Spawner:  sp,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   newBlockingWaiter(),
	})
	box := pullBox(rt, podID, pulledContainer("main", goodRef))
	box.InitContainers = []*runtimev1.Container{
		pulledContainer("init-a", badRef),
		pulledContainer("init-b", goodRef),
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed %v; an unresolvable init image must not fail the pod", resp.GetError())
	}

	assertWaiting(t, rt, podID, "init-a", runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH)
	for _, name := range []string{"init-b", "main"} {
		w := assertWaiting(t, rt, podID, name, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED)
		if w.GetReason() != "PodInitializing" {
			t.Errorf("%s waiting reason = %q, want %q", name, w.GetReason(), "PodInitializing")
		}
	}
	sp.mu.Lock()
	spawned := len(sp.specs)
	sp.mu.Unlock()
	if spawned != 0 {
		t.Errorf("spawned %d processes past a failed init container; the sequence must stop", spawned)
	}
	if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_PENDING {
		t.Errorf("phase = %v, want PENDING", got)
	}
}

// TestStartContainerStartsANeverStartedContainer is the StartContainer gate: the
// verb the provider's retry worker calls for a container that is Waiting because
// its start failed before the spawn. It re-runs image resolution and spawn for
// that one container, and — unlike RestartContainer, which exists for a
// container that DID run — it never bumps restart_count and never records a
// last-termination state.
func TestStartContainerStartsANeverStartedContainer(t *testing.T) {
	const (
		podID   = "pod-start"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{
		Puller:   pull,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   w,
	})
	box := pullBox(rt, podID, pulledContainer("good", goodRef), pulledContainer("bad", badRef))
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}

	t.Run("a_failed_attempt_re_types_the_wait_and_starts_nothing", func(t *testing.T) {
		// The registry is still refusing, differently: the new attempt must
		// publish the NEW cause, not the stale one.
		pull.failRef(badRef, fmt.Errorf("pull %q: %w", badRef, image.ErrNoPlatformMatch))
		got, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "bad"})
		if err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		if got.GetError() == nil {
			t.Fatal("StartContainer reported success while the pull still fails")
		}
		if got.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH {
			t.Errorf("response failure_reason = %v, want IMAGE_NO_PLATFORM_MATCH", got.GetFailureReason())
		}
		assertWaiting(t, rt, podID, "bad", runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH)
		if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_PENDING {
			t.Errorf("phase = %v, want PENDING", got)
		}
	})

	t.Run("a_healed_reference_runs_the_container", func(t *testing.T) {
		pull.healRef(badRef)
		got, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "bad"})
		if err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		if got.GetError() != nil {
			t.Fatalf("StartContainer failed: %v (reason %v)", got.GetError(), got.GetFailureReason())
		}
		if got.GetStatus().GetState().GetRunning() == nil {
			t.Errorf("response status = %v, want Running", got.GetStatus().GetState())
		}
		cs := statusNamed(t, rt, podID, "bad")
		if cs.GetState().GetRunning() == nil {
			t.Fatalf("container state = %v, want Running", cs.GetState())
		}
		if cs.GetRestartCount() != 0 || cs.GetLastTerminationState() != nil {
			t.Errorf("StartContainer recorded a restart (count %d, last %v); that is RestartContainer's job",
				cs.GetRestartCount(), cs.GetLastTerminationState())
		}
		if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
			t.Errorf("phase = %v, want RUNNING once nothing waits", got)
		}
	})

	t.Run("a_container_that_has_a_process_is_refused", func(t *testing.T) {
		got, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "good"})
		if err != nil {
			t.Fatalf("StartContainer: %v", err)
		}
		if got.GetError().GetCode() != int32(codes.FailedPrecondition) {
			t.Errorf("code = %d, want FailedPrecondition (%d)", got.GetError().GetCode(), int32(codes.FailedPrecondition))
		}
		if got.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("failure_reason = %v, want NOT_UPDATABLE", got.GetFailureReason())
		}
	})
}

// TestStartContainerResumesTheInitSequence is R12's proof: a waiting INIT
// container that starts successfully does not just start itself — the runtime
// runs the rest of the init list and then the mains, and those states arrive on
// GetPodStatus rather than in the RPC response (which carries only the named
// container).
func TestStartContainerResumesTheInitSequence(t *testing.T) {
	const (
		podID   = "pod-resume"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	w := newBlockingWaiter()
	// The two init containers exit 0 the moment they are waited; the main (the
	// third spawn) stays blocked, so the pod settles on Running.
	w.release(1001)
	w.release(1002)
	sp := &fakeSpawner{}
	rt := newTestRuntime(t, Deps{
		Puller:   pull,
		Spawner:  sp,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   w,
	})
	box := pullBox(rt, podID, pulledContainer("main", goodRef))
	box.InitContainers = []*runtimev1.Container{
		pulledContainer("init-a", badRef),
		pulledContainer("init-b", goodRef),
	}
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	assertWaiting(t, rt, podID, "main", runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED)

	pull.healRef(badRef)
	got, err := rt.StartContainer(context.Background(),
		&runtimev1.StartContainerRequest{PodId: podID, Container: "init-a"})
	if err != nil {
		t.Fatalf("StartContainer: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("StartContainer failed: %v (reason %v)", got.GetError(), got.GetFailureReason())
	}
	if n := len(got.GetStatus().GetName()); n == 0 || got.GetStatus().GetName() != "init-a" {
		t.Errorf("response carried %q; it must carry the named container only", got.GetStatus().GetName())
	}

	// The resumed sequence is observed through the status surface, per R12.
	waitFor(t, 3*time.Second, "the main container to run after the resumed init sequence", func() bool {
		return statusNamed(t, rt, podID, "main").GetState().GetRunning() != nil
	})
	if got := podPhase(t, rt, podID); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase = %v, want RUNNING", got)
	}
	// Three spawns: the healed init-a, then init-b, then the main. Two would mean
	// the sequence restarted at the mains and skipped the init container that was
	// blocked behind the failure — the mutation this assertion exists for. (Both
	// plain init containers leave the tracked set as they complete, which is
	// where a completed init container has always lived, so the spawn seam is
	// what witnesses them.)
	sp.mu.Lock()
	spawned := len(sp.specs)
	sp.mu.Unlock()
	if spawned != 3 {
		t.Errorf("spawned %d processes, want 3 (init-a, init-b, main)", spawned)
	}
}

// TestRestartContainerRefusesANeverStartedContainer is R11's guard: a Waiting
// container has no process, and RestartContainer's contract is to terminate one
// and record its last termination. Called on a never-started container it must
// refuse — never dereference the absent process (supervisor.Process.PID has no
// nil guard, and runtimed runs in-process, so the panic would take the node's
// runtime down).
func TestRestartContainerRefusesANeverStartedContainer(t *testing.T) {
	const (
		podID  = "pod-restartguard"
		badRef = "example.com/bad:v1"
	)
	rt := newTestRuntime(t, Deps{
		Puller: &fakePuller{errByRef: map[string]error{
			badRef: errors.New("manifest unknown: no such image"),
		}},
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   newBlockingWaiter(),
	})
	box := pullBox(rt, podID, pulledContainer("bad", badRef))
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}

	got, err := rt.RestartContainer(context.Background(),
		&runtimev1.RestartContainerRequest{PodId: podID, Container: "bad", Reason: "liveness probe failed"})
	if err != nil {
		t.Fatalf("RestartContainer: %v", err)
	}
	if got.GetError().GetCode() != int32(codes.FailedPrecondition) {
		t.Fatalf("code = %d, want FailedPrecondition (%d)", got.GetError().GetCode(), int32(codes.FailedPrecondition))
	}
	if got.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
		t.Errorf("failure_reason = %v, want NOT_UPDATABLE", got.GetFailureReason())
	}
	if !strings.Contains(got.GetError().GetMessage(), "StartContainer") {
		t.Errorf("message = %q, want it to name the verb that DOES apply", got.GetError().GetMessage())
	}
	assertWaiting(t, rt, podID, "bad", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL)
}

// TestStartContainerRefusalsComeFromTheSharedClaim pins the three refusals the
// single-flight start predicate can produce, as StartContainer renders them.
//
// # Why this is not vacuous
//
// StartContainer used to re-derive the predicate inline — its own p.stopping /
// has-a-process / start-in-flight switch, next to claimContainerStartLocked's
// copy of the same three conditions. Two copies of a concurrency predicate is
// one bug away from a double spawn (a container started twice, the second entry
// replacing the first, the first's root-owned group tracked by nothing) or a
// spawn into a pod being torn down. Both paths now ask the ONE predicate, so
// this table is what holds the mapping from its verdicts to the RPC taxonomy
// still: a caller reads NOT_FOUND for a pod that will not exist and
// NOT_UPDATABLE for a container it may not start, and both are
// FailedPrecondition rather than a retry-forever Internal.
func TestStartContainerRefusalsComeFromTheSharedClaim(t *testing.T) {
	const (
		podID   = "pod-claimrefuse"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)

	cases := []struct {
		name string
		// container is the one StartContainer is called on.
		container string
		// arrange puts the pod into the state the row is about.
		arrange    func(t *testing.T, rt *Runtime, p *pod)
		wantCode   codes.Code
		wantReason runtimev1.FailureReason
		wantMsg    string
	}{
		{
			// A pod being deleted must acquire no new process groups at all, and
			// it is not going to exist — so NOT_FOUND, not NOT_UPDATABLE.
			name:       "a_pod_being_deleted_is_not_found",
			container:  "bad",
			arrange:    func(_ *testing.T, _ *Runtime, p *pod) { p.mu.Lock(); p.stopping = true; p.mu.Unlock() },
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND,
			wantMsg:    "pod is being deleted",
		},
		{
			// This verb's contract is a container that never started; one that
			// has a process is RestartContainer's, and the message says so.
			name:       "a_container_that_has_a_process_is_not_updatable",
			container:  "good",
			arrange:    func(*testing.T, *Runtime, *pod) {},
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			wantMsg:    "use RestartContainer",
		},
		{
			// The claim itself: another start owns this container and is mid-spawn.
			name:      "a_start_already_in_flight_is_not_updatable",
			container: "bad",
			arrange: func(t *testing.T, rt *Runtime, p *pod) {
				cp := rt.findContainer(p, "bad")
				if cp == nil {
					t.Fatal("fixture: the waiting container has no entry to claim")
				}
				p.mu.Lock()
				cp.starting = true
				p.mu.Unlock()
			},
			wantCode:   codes.FailedPrecondition,
			wantReason: runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			wantMsg:    "a start is already in flight",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{
				Puller: &fakePuller{errByRef: map[string]error{
					badRef: errors.New("manifest unknown: no such image"),
				}},
				Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
				Waiter:   newBlockingWaiter(),
			})
			box := pullBox(rt, podID, pulledContainer("good", goodRef), pulledContainer("bad", badRef))
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil || resp.GetError() != nil {
				t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
			}
			rt.mu.Lock()
			p := rt.pods[podID]
			rt.mu.Unlock()
			if p == nil {
				t.Fatal("fixture: the created pod is not tracked")
			}
			tc.arrange(t, rt, p)

			got, err := rt.StartContainer(context.Background(),
				&runtimev1.StartContainerRequest{PodId: podID, Container: tc.container})
			if err != nil {
				t.Fatalf("StartContainer: %v", err)
			}
			if got.GetError() == nil {
				t.Fatalf("StartContainer succeeded; want a refusal (status %v)", got.GetStatus())
			}
			if got.GetError().GetCode() != int32(tc.wantCode) {
				t.Errorf("code = %d, want %d (%v)", got.GetError().GetCode(), int32(tc.wantCode), tc.wantCode)
			}
			if got.GetFailureReason() != tc.wantReason {
				t.Errorf("failure_reason = %v, want %v", got.GetFailureReason(), tc.wantReason)
			}
			if !strings.Contains(got.GetError().GetMessage(), tc.wantMsg) {
				t.Errorf("message = %q, want it to contain %q", got.GetError().GetMessage(), tc.wantMsg)
			}
		})
	}
}
