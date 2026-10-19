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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestRestartContainerLastTerminationKeepsStartedAt pins that the run a restart
// replaces is reported with BOTH ends of its life: last_termination_state's
// started_at is the replaced instance's start, never null.
//
// # Why this is not vacuous
//
// The restart used to read the start only from the Running state, and the
// reaper's terminated record dropped it. So a container that crashed before the
// provider restarted it (already Terminated, the CrashLoopBackOff case), or one
// whose exit the reaper recorded before the restart's swap, reported
// lastState.terminated.startedAt as null. The first subtest restarts a container
// that is already Terminated and fails on that code; the second restarts a live
// container twice in a row, so each replaced run must carry the start of the
// instance the previous restart installed.
func TestRestartContainerLastTerminationKeepsStartedAt(t *testing.T) {
	restart := func(t *testing.T, rt *Runtime, podID string) *runtimev1.ContainerStatus {
		t.Helper()
		resp, err := rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: podID, Container: "main", Reason: "liveness probe failed",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("RestartContainer failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		return resp.GetStatus()
	}
	status := func(t *testing.T, rt *Runtime, podID string) *runtimev1.ContainerStatus {
		t.Helper()
		gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		cs := gs.GetStatus().GetContainerStatuses()
		if len(cs) != 1 {
			t.Fatalf("container statuses = %d, want 1", len(cs))
		}
		return cs[0]
	}
	// want is the replaced instance's status, captured while it ran.
	assertStart := func(t *testing.T, what string, got, want *runtimev1.ContainerStatus) {
		t.Helper()
		term := got.GetLastTerminationState().GetTerminated()
		if term == nil {
			t.Fatalf("%s: last_termination_state.terminated is nil", what)
		}
		if term.GetStartedAt() == nil {
			t.Fatalf("%s: last_termination_state.terminated.started_at is nil", what)
		}
		if wantAt := want.GetState().GetRunning().GetStartedAt(); !proto.Equal(term.GetStartedAt(), wantAt) {
			t.Errorf("%s: last_termination_state.terminated.started_at = %v, want the replaced instance's start %v",
				what, term.GetStartedAt().AsTime(), wantAt.AsTime())
		}
	}

	t.Run("already-terminated", func(t *testing.T) {
		const podID = "pod-startedat-crashed"
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		w.code = 2 // a crash, the CrashLoopBackOff case
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
		rel := releaseOnce(w)
		rt.signalGroup = (&recordingSignalGroup{onTerm: rel, onKill: rel}).signal

		mustCreatePod(t, rt, hostBinBox(rt, podID))
		running := status(t, rt, podID)
		started := running.GetState().GetRunning().GetStartedAt()
		if started == nil {
			t.Fatal("the first instance reports no Running started_at")
		}

		// The instance exits on its own, and the reaper records it Terminated
		// before any restart is issued.
		rel(1001)
		deadline := time.Now().Add(3 * time.Second)
		var crashed *runtimev1.ContainerStatus
		for crashed = status(t, rt, podID); crashed.GetState().GetTerminated() == nil; crashed = status(t, rt, podID) {
			if time.Now().After(deadline) {
				t.Fatal("the container did not terminate")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if at := crashed.GetState().GetTerminated().GetStartedAt(); !proto.Equal(at, started) {
			t.Errorf("terminated started_at = %v, want the instance's start %v", at.AsTime(), started.AsTime())
		}

		got := restart(t, rt, podID)
		assertStart(t, "restart of a terminated instance", got, running)
		assertStart(t, "GetPodStatus after the restart", status(t, rt, podID), running)
		rel(1002)
	})

	t.Run("back-to-back-restarts", func(t *testing.T) {
		const podID = "pod-startedat-twice"
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})
		rel := releaseOnce(w)
		rt.signalGroup = (&recordingSignalGroup{onTerm: rel, onKill: rel}).signal

		mustCreatePod(t, rt, hostBinBox(rt, podID))
		first := status(t, rt, podID)
		second := restart(t, rt, podID)
		assertStart(t, "first restart", second, first)
		third := restart(t, rt, podID)
		assertStart(t, "second restart", third, second)
		rel(1003)
	})
}
