package runtime

import (
	"context"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRestartContainerReExecs is the M2.8 RestartContainer proof: a restart
// terminates the container's process group and re-spawns it FROM THE SAME SPEC
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

	mustCreatePod(t, rt, hostBinBox("pod-r"))

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
		// A NEW process was spawned via startContainer (the re-exec).
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
