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

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- fixtures -------------------------------------------------------------

// slowPuller is a fakePuller that takes a measurable amount of wall time, so two
// start paths can be held inside image resolution AT THE SAME TIME. That overlap
// is the whole subject of the two race gates below: with an instant puller a
// spawn is atomic in practice and the double-spawn / late-spawn windows are
// unreachable from a test, which is exactly how they survived review.
//
// notifyRef + notified make the overlap deterministic rather than timed: the
// caller arms the trigger on one reference and then waits for that pull to have
// STARTED before it makes its own move, so no assertion depends on a sleep
// racing a scheduler. Arming is explicit because the same reference is pulled
// during CreatePod, and a trigger that fired there would release the caller
// before the run under test had begun.
type slowPuller struct {
	inner *fakePuller
	delay time.Duration

	mu        sync.Mutex
	notifyRef string
	notified  chan struct{}
}

// arm makes the next pull of ref close the returned channel.
func (s *slowPuller) arm(ref string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifyRef = ref
	s.notified = make(chan struct{})
	return s.notified
}

func (s *slowPuller) Pull(ctx context.Context, ref string, cred *image.RegistryCredential,
	policy image.PlatformPolicy, pull runtimev1.ImagePullPolicy) (*image.PullResult, error) {
	s.mu.Lock()
	if s.notified != nil && ref == s.notifyRef {
		close(s.notified)
		s.notified = nil
	}
	s.mu.Unlock()
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.inner.Pull(ctx, ref, cred, policy, pull)
}

// killLog records every process-group signal the runtime sends (the SignalGroup
// seam), so a test can assert that a process the daemon spawned was also killed
// by it — the only observable difference between "torn down" and "orphaned and
// running as root".
type killLog struct {
	mu   sync.Mutex
	sent map[int]int
}

func newKillLog() *killLog { return &killLog{sent: map[int]int{}} }

func (k *killLog) signal(pgid int, _ os.Signal) error {
	k.mu.Lock()
	k.sent[pgid]++
	k.mu.Unlock()
	return nil
}

func (k *killLog) signalled(pgid int) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.sent[pgid] > 0
}

// raceCommand is the distinct argv[0] each fixture container carries, which is
// how a recorded SpawnSpec is attributed to the container it belongs to (the
// fake backend passes argv through into the wrapped command).
func raceCommand(name string) string { return "/app-" + name }

// raceContainer is one pull-route container with an argv that names it.
func raceContainer(name, ref string) *runtimev1.Container {
	return &runtimev1.Container{Name: name, Image: ref, Command: []string{raceCommand(name)}}
}

// spawnedNames attributes each recorded spawn to its container, in spawn order.
// The pid a fakeSpawner handed out for the i'th spawn is 1001+i, which is the
// pairing every assertion below needs (spawn -> pid -> tracked or not).
func spawnedNames(t *testing.T, sp *fakeSpawner, names []string) map[int]string {
	t.Helper()
	sp.mu.Lock()
	specs := append([]supervisor.SpawnSpec(nil), sp.specs...)
	sp.mu.Unlock()
	out := make(map[int]string, len(specs))
	for i, spec := range specs {
		joined := strings.Join(spec.Argv, " ")
		hit := ""
		for _, n := range names {
			if strings.Contains(joined, raceCommand(n)) {
				hit = n
				break
			}
		}
		if hit == "" {
			t.Fatalf("spawn %d (argv %v) belongs to no fixture container", i, spec.Argv)
		}
		out[1001+i] = hit
	}
	return out
}

// trackedPIDs is the set of pids the pod's container list accounts for.
func trackedPIDs(rt *Runtime, podID string) map[int]bool {
	rt.mu.Lock()
	p, ok := rt.pods[podID]
	rt.mu.Unlock()
	out := map[int]bool{}
	if !ok {
		return out
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cp := range p.containers {
		if cp.proc != nil {
			out[cp.proc.PID()] = true
		}
	}
	return out
}

// --- F1: the double-spawn race -------------------------------------------

// TestConcurrentStartAndResumeSpawnEachContainerOnce is the single-flight gate
// for the START SEQUENCE, the half StartContainer's own claim does not cover.
//
// # Why this is not vacuous
//
// StartContainer takes a per-container `starting` claim under p.mu precisely so
// two concurrent starts cannot both spawn. startSequence took no claim at all:
// once StartContainer could resume a sequence (resumeInitSequence), the resumed
// sequence's spawn loop and an explicit StartContainer on a not-yet-reached
// container ran concurrently against the same container, both spawned a process,
// and setContainerLocked silently REPLACED the first entry with the second. The
// replaced process is root-owned, has a live reap record, and nothing tracks,
// signals, reaps or stops it — DeletePod iterates p.containers and would never
// see it. This test holds both paths inside image resolution at once (slowPuller)
// so the window is real, and asserts the two properties that make an orphan
// impossible: at most one spawn per container, and every spawn tracked.
func TestConcurrentStartAndResumeSpawnEachContainerOnce(t *testing.T) {
	const (
		podID   = "pod-startrace"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	sp := &fakeSpawner{}
	rt := newTestRuntime(t, Deps{
		Puller:   &slowPuller{inner: pull, delay: 40 * time.Millisecond},
		Spawner:  sp,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   newBlockingWaiter(),
	})
	box := pullBox(rt, podID, raceContainer("main-a", goodRef), raceContainer("main-b", goodRef))
	// A native SIDECAR, so the resumed init step is not waited to completion and
	// its entry stays in the tracked set — the tracking assertion below then holds
	// for every spawn, with no "a completed init container is untracked by design"
	// exemption to weaken it.
	side := raceContainer("side", badRef)
	side.RestartPolicy = runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
	box.InitContainers = []*runtimev1.Container{side}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	assertWaiting(t, rt, podID, "main-a", runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED)

	// The registry comes back, and the provider's retry worker asks for the
	// blocked init container and one of the blocked mains at the same time — the
	// resumed sequence and the explicit start now both want to spawn main-a.
	pull.healRef(badRef)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for _, name := range []string{"side", "main-a"} {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			<-gate
			if _, err := rt.StartContainer(context.Background(),
				&runtimev1.StartContainerRequest{PodId: podID, Container: n}); err != nil {
				t.Errorf("StartContainer(%s): %v", n, err)
			}
		}(name)
	}
	close(gate)
	wg.Wait()

	// main-b is only reachable through the resumed sequence, so waiting for it is
	// how the test knows the sequence ran to the end before it asserts.
	waitFor(t, 5*time.Second, "the resumed sequence to start main-b", func() bool {
		return statusNamed(t, rt, podID, "main-b").GetState().GetRunning() != nil
	})

	names := []string{"side", "main-a", "main-b"}
	spawns := spawnedNames(t, sp, names)
	counts := map[string]int{}
	for _, n := range spawns {
		counts[n]++
	}
	for _, n := range names {
		if counts[n] != 1 {
			t.Errorf("container %s spawned %d times, want exactly 1", n, counts[n])
		}
	}
	tracked := trackedPIDs(rt, podID)
	for pid, n := range spawns {
		if !tracked[pid] {
			t.Errorf("pid %d (container %s) was spawned but is tracked by nothing: a root-owned process group the pod cannot signal, reap or stop", pid, n)
		}
	}
}

// --- F2: the start-vs-delete race ----------------------------------------

// TestDeletePodKillsASpawnThatLandsDuringTeardown is the teardown-completeness
// gate.
//
// # Why this is not vacuous
//
// DeletePod snapshotted the pod's containers once under p.mu, stopped that
// snapshot, and then removed the pod's durable reap records. A StartContainer
// spawn that landed after the snapshot was in neither set: it was never
// signalled, and its reap record was deleted underneath it (or written after the
// deletion), so the startup reap could not collect it either. The result is a
// root-owned process group belonging to a pod the cluster has deleted, surviving
// a daemon restart. The slowPuller's notify channel puts the spawn strictly
// inside DeletePod's window, so this is a deterministic reproduction rather than
// a timing hope.
func TestDeletePodKillsASpawnThatLandsDuringTeardown(t *testing.T) {
	const (
		podID   = "pod-deleterace"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	sp := &fakeSpawner{}
	kills := newKillLog()
	slow := &slowPuller{inner: pull, delay: 25 * time.Millisecond}
	rt := newTestRuntime(t, Deps{
		Puller:      slow,
		Spawner:     sp,
		Unpacker:    &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:      newBlockingWaiter(),
		SignalGroup: kills.signal,
	})
	// Widen DeletePod's post-SIGKILL exit-observation wait well past the pull
	// delay above, so the late spawn lands INSIDE the teardown — between the
	// container snapshot and the reap-record removal — rather than after the
	// pod-lifetime context has been cancelled, which would abort the pull and
	// make the whole race unobservable (the ctx cancellation is a side effect of
	// teardown ORDER, not a guard: nothing between the pull and proc.Start
	// re-checks it).
	rt.exitObsGrace = 400 * time.Millisecond
	box := pullBox(rt, podID, raceContainer("good", goodRef), raceContainer("bad", badRef))
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	assertWaiting(t, rt, podID, "bad", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL)

	pull.healRef(badRef)
	notified := slow.arm(badRef)
	var wg sync.WaitGroup
	wg.Add(1)
	var startResp *runtimev1.StartContainerResponse
	go func() {
		defer wg.Done()
		got, err := rt.StartContainer(context.Background(),
			&runtimev1.StartContainerRequest{PodId: podID, Container: "bad"})
		if err != nil {
			t.Errorf("StartContainer: %v", err)
			return
		}
		startResp = got
	}()

	// Delete only once the retry is committed to a pull it cannot abandon.
	<-notified
	if _, err := rt.DeletePod(context.Background(),
		&runtimev1.DeletePodRequest{PodId: podID, GracePeriodSeconds: 0}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	wg.Wait()

	if startResp.GetError() == nil {
		t.Errorf("StartContainer succeeded for a pod being deleted: %v", startResp.GetStatus())
	} else if startResp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
		t.Errorf("failure_reason = %v, want NOT_FOUND for a pod being deleted", startResp.GetFailureReason())
	}

	// Every process this daemon spawned for the pod must have been signalled by
	// it: the "good" main through the ordinary teardown, the late "bad" spawn
	// through whatever path noticed it could not be tracked.
	for pid, n := range spawnedNames(t, sp, []string{"good", "bad"}) {
		if !kills.signalled(pid) {
			t.Errorf("pid %d (container %s) was spawned but never signalled; it survives the pod's deletion as a root-owned group", pid, n)
		}
	}
	if got := trackedPIDs(rt, podID); len(got) != 0 {
		t.Errorf("the deleted pod still tracks %d container processes: %v", len(got), got)
	}
	// And nothing durable is left to be resurrected: a reap record for a pod that
	// no longer exists is what the startup reap acts on.
	dir, err := rt.podReapDir(podID)
	if err != nil {
		t.Fatalf("podReapDir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read reap records: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("%d reap record(s) survive the pod's deletion: %v", len(entries), entries)
	}
}

// --- F3: the credential resolver's error text is not a status message ----

// TestCredentialResolverErrorNeverReachesTheStatus pins the confinement of the
// one error text on the start path that is derived from Secret material.
//
// # Why this is not vacuous
//
// The IMAGE_PULL_CREDENTIAL waiting message carried the CredentialResolver's
// error verbatim. That resolver reads docker-config Secrets, so its message can
// quote the bytes it failed to parse — and ContainerStateWaiting.message travels
// to the provider, into kine, and out through `kubectl describe pod` to anyone
// with pod-read access in the namespace. The typed reason already tells the
// provider what to do; the text buys nothing that justifies the disclosure.
func TestCredentialResolverErrorNeverReachesTheStatus(t *testing.T) {
	const (
		podID  = "pod-credtext"
		marker = "dockerconfigjson-auth-QUJDOnNlY3JldA"
	)
	rt := newTestRuntime(t, Deps{
		Credentials: &fakeCredentialResolver{
			err: fmt.Errorf(`parse secret "regcred": bad auth %s`, marker),
		},
		Puller:   &fakePuller{},
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   newBlockingWaiter(),
	})
	box := pullBox(rt, podID, pulledContainer("c", pullRef))
	box.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed %v; an unresolvable pull secret is container-class", resp.GetError())
	}
	if s := resp.String(); strings.Contains(s, marker) {
		t.Errorf("the CreatePod response carries the resolver's text: %s", s)
	}
	w := assertWaiting(t, rt, podID, "c", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL)
	if strings.Contains(w.GetMessage(), marker) {
		t.Errorf("waiting message = %q; it carries material the resolver read out of a Secret", w.GetMessage())
	}
	if !strings.Contains(w.GetMessage(), "regcred") {
		t.Errorf("waiting message = %q, want it to name the imagePullSecret that could not be resolved", w.GetMessage())
	}
}

// --- F4: an unrunnable container spec is InvalidArgument -----------------

// TestUnrunnableContainerSpecIsInvalidArgument pins the code the three
// caller-error routes in resolveBinary must produce.
//
// # Why this is not vacuous
//
// failureCode maps errInvalidPodBox to InvalidArgument and everything else to
// Internal, and these three sites classified their FailureReason as
// INVALID_POD_BOX without wrapping the sentinel — so a PodBox the caller wrote
// wrongly came back as codes.Internal, i.e. "the daemon is broken", which a
// client is entitled to retry forever. The typed reason and the gRPC code
// disagreed about whose fault it was.
func TestUnrunnableContainerSpecIsInvalidArgument(t *testing.T) {
	cases := []struct {
		name      string
		container *runtimev1.Container
	}{
		{"native_sentinel_without_a_command", &runtimev1.Container{Name: "c", Image: NativeImage}},
		{"native_command_is_not_absolute", &runtimev1.Container{Name: "c", Image: NativeImage, Command: []string{"sleep"}}},
		{"no_image_at_all", &runtimev1.Container{Name: "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const podID = "pod-invalidspec"
			rt := newTestRuntime(t, Deps{Puller: &fakePuller{}})
			p := &pod{
				box:     pullBox(rt, podID, tc.container),
				backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
			}
			_, reason, err := rt.startContainer(context.Background(), p,
				derivedRootfs(t, rt, podID), tc.container, false)
			if err == nil {
				t.Fatal("startContainer succeeded on an unrunnable container spec")
			}
			if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("reason = %v, want INVALID_POD_BOX", reason)
			}
			if !errors.Is(err, errInvalidPodBox) {
				t.Errorf("error %v does not wrap errInvalidPodBox", err)
			}
			if got := failureCode(err); got != codes.InvalidArgument {
				t.Errorf("gRPC code = %v, want %v (a PodBox the caller wrote wrongly is not the daemon's fault)",
					got, codes.InvalidArgument)
			}
		})
	}
}
