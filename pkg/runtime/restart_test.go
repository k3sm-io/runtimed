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
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRestartContainerReExecs is the M2.8 RestartContainer proof: a restart
// terminates the container's process group and re-spawns it from the same SPEC
// through the startContainer path (same SBPL profile + exec-shim drop), bumping
// restart_count; an unknown pod or container is NOT_FOUND.
func TestRestartContainerReExecs(t *testing.T) {
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
	// The restart SIGKILLs the old process group (grace 0); releasing the fake
	// waiter for the killed pid lets the kqueue-reaper stand-in collect the exit
	// (proc.Done closes) so RestartContainer can re-spawn.
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal

	mustCreatePod(t, rt, hostBinBox(rt, "pod-r"))

	sp.mu.Lock()
	spawnsBefore := len(sp.specs)
	sp.mu.Unlock()
	if spawnsBefore != 1 {
		t.Fatalf("spawns before restart = %d, want 1", spawnsBefore)
	}

	t.Run("re-execs-and-bumps-count", func(t *testing.T) {
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: "pod-r", Container: "main", Reason: "liveness probe failed", // grace 0 → immediate kill
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		if rc := resp.GetStatus().GetRestartCount(); rc != 1 {
			t.Errorf("restart_count = %d, want 1", rc)
		}
		if resp.GetStatus().GetState().GetRunning() == nil {
			t.Errorf("restarted container should be Running, got %+v", resp.GetStatus().GetState())
		}
		// A new process was spawned via startContainer (the re-exec).
		sp.mu.Lock()
		spawnsAfter := len(sp.specs)
		sp.mu.Unlock()
		if spawnsAfter != spawnsBefore+1 {
			t.Errorf("spawns after restart = %d, want %d (a re-exec)", spawnsAfter, spawnsBefore+1)
		}
		if !rec.sawKill() {
			t.Error("restart did not SIGKILL the old container process group")
		}
		// GetPodStatus surfaces the bumped count + the prior run's termination.
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-r"})
		cs := gs.GetStatus().GetContainerStatuses()
		if len(cs) != 1 || cs[0].GetRestartCount() != 1 {
			t.Fatalf("status restart_count not surfaced: %+v", cs)
		}
		if cs[0].GetLastTerminationState().GetTerminated() == nil {
			t.Error("last_termination_state not recorded for the replaced run")
		}
	})

	t.Run("not-found-pod", func(t *testing.T) {
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "nope", Container: "main"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
			t.Errorf("unknown pod reason = %v, want NOT_FOUND", resp.GetFailureReason())
		}
	})

	t.Run("not-found-container", func(t *testing.T) {
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{PodId: "pod-r", Container: "ghost"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
			t.Errorf("unknown container reason = %v, want NOT_FOUND", resp.GetFailureReason())
		}
	})

	// Release the post-restart container so its supervision goroutine ends.
	w.release(1002)
}

// TestRestartContainerDuringDeleteKillsTheLateSpawn is the F3 teardown-completeness
// gate for RestartContainer, the sibling of the StartContainer one
// (TestDeletePodKillsASpawnThatLandsDuringTeardown).
//
// # Why this is not vacuous
//
// StartContainer re-checks pod.stopping immediately before it installs its spawn
// and kills the group when the pod is going away; the start sequence does the
// same through installSpawned. RestartContainer did neither — it walked
// p.containers itself and wrote the replacement straight in. So a liveness
// restart racing a delete installed a root-owned process group into a pod whose
// teardown had already snapshotted what it would signal and had removed its
// durable reap records: nothing signals it, nothing reaps it, and it survives a
// daemon restart. The slowPuller's notify channel puts the re-spawn strictly
// inside the delete rather than hoping for it, so the window is reproduced and
// not merely hinted at.
func TestRestartContainerDuringDeleteKillsTheLateSpawn(t *testing.T) {
	const (
		podID = "pod-restartrace"
		ref   = "example.com/app:v1"
	)
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	kills := newKillLog()
	slow := &slowPuller{inner: &fakePuller{}, delay: 25 * time.Millisecond}
	rt := newTestRuntime(t, Deps{
		Puller:   slow,
		Spawner:  sp,
		Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}},
		Waiter:   w,
	})
	// The signal seam does double duty: it records every group this daemon
	// signals (the assertion below) and releases the fake waiter for the pid, so
	// a killed process is observed to exit and the restart can proceed past its
	// wait. The release is deduplicated because one pid is legitimately signalled
	// twice here — the restart kills the old group, and DeletePod's teardown
	// stops the same entry, which is still what p.containers holds — and
	// blockingWaiter.release closes a channel.
	var relMu sync.Mutex
	released := map[int]bool{}
	rt.signalGroup = func(pgid int, sig os.Signal) error {
		_ = kills.signal(pgid, sig)
		relMu.Lock()
		first := !released[pgid]
		released[pgid] = true
		relMu.Unlock()
		if first {
			w.release(pgid)
		}
		return nil
	}
	mustCreatePod(t, rt, pullBox(rt, podID, raceContainer("main", ref)))

	// Arm AFTER CreatePod: the same reference is pulled there, and a trigger that
	// fired on it would release the delete before the restart's re-spawn began.
	notified := slow.arm(ref)
	var wg sync.WaitGroup
	wg.Add(1)
	var restartResp *runtimev1.RestartContainerResponse
	go func() {
		defer wg.Done()
		got, err := rt.RestartContainer(context.Background(),
			&runtimev1.RestartContainerRequest{PodId: podID, Container: "main", Reason: "liveness probe failed"})
		if err != nil {
			t.Errorf("RestartContainer: %v", err)
			return
		}
		restartResp = got
	}()

	// Delete only once the re-spawn is committed to a pull it cannot abandon.
	<-notified
	if _, err := rt.DeletePod(context.Background(),
		&runtimev1.DeletePodRequest{PodId: podID, GracePeriodSeconds: 0}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	wg.Wait()

	if restartResp.GetError() == nil {
		t.Fatalf("RestartContainer succeeded for a pod being deleted: %v", restartResp.GetStatus())
	}
	if restartResp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
		t.Errorf("failure_reason = %v, want NOT_FOUND for a pod being deleted", restartResp.GetFailureReason())
	}
	// The replacement was spawned (pid 1002 — the fake spawner hands out 1001+i)
	// and must have been signalled by the daemon that created it. An unsignalled
	// pid here is the orphan this gate exists for.
	sp.mu.Lock()
	spawns := len(sp.specs)
	sp.mu.Unlock()
	if spawns != 2 {
		t.Fatalf("spawns = %d, want 2 (the original and the restart's replacement)", spawns)
	}
	if !kills.signalled(1002) {
		t.Error("the restart's replacement was spawned but never signalled: a root-owned " +
			"process group belonging to a pod the cluster has deleted")
	}
	// And it is tracked by nothing, because the install was refused — the pod is
	// gone from the runtime, so nothing could report it either.
	if tracked := trackedPIDs(rt, podID); len(tracked) != 0 {
		t.Errorf("deleted pod still tracks %v", tracked)
	}
}
