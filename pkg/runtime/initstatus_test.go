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
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// codeByPIDWaiter reports a per-pid exit code the moment a listed pid is
// waited, and blocks every other pid until its context ends, so a test can
// complete one init container with a chosen code while the mains stay running.
type codeByPIDWaiter struct {
	mu    sync.Mutex
	codes map[int]int
}

func (w *codeByPIDWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	w.mu.Lock()
	code, ok := w.codes[pid]
	w.mu.Unlock()
	if ok {
		return code, 0, nil
	}
	<-ctx.Done()
	return 0, 0, ctx.Err()
}

// assertCompletedInit checks that statuses holds exactly one entry for name
// and that it is a Terminated state with the wanted exit code and reason.
func assertCompletedInit(t *testing.T, where string, statuses []*runtimev1.ContainerStatus, name string, code int32, reason string) {
	t.Helper()
	var found []*runtimev1.ContainerStatus
	for _, cs := range statuses {
		if cs.GetName() == name {
			found = append(found, cs)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: init_container_statuses has %d entries for %q, want 1 (%+v)", where, len(found), name, statuses)
	}
	term := found[0].GetState().GetTerminated()
	if term == nil {
		t.Fatalf("%s: %q state = %+v, want Terminated", where, name, found[0].GetState())
	}
	if term.GetExitCode() != code || term.GetReason() != reason {
		t.Errorf("%s: %q terminated exit=%d reason=%q, want exit=%d reason=%q",
			where, name, term.GetExitCode(), term.GetReason(), code, reason)
	}
	if term.GetStartedAt() == nil || term.GetFinishedAt() == nil {
		t.Errorf("%s: %q terminated started/finished = %v/%v, want both set",
			where, name, term.GetStartedAt(), term.GetFinishedAt())
	}
	if found[0].GetImage() == "" || found[0].GetContainerId() == "" {
		t.Errorf("%s: %q image/container_id = %q/%q, want both set",
			where, name, found[0].GetImage(), found[0].GetContainerId())
	}
	if found[0].GetReady() {
		t.Errorf("%s: %q ready = true, want false for a terminated init container", where, name)
	}
}

// TestPlainInitContainerReportsTerminatedAfterCompletion: a plain init
// container (no restart_policy) that exits 0 is reported under
// init_container_statuses as Terminated, exit 0, reason Completed, both in the
// CreatePod response and in GetPodStatus, while the main runs. Before the fix
// the completed init left the tracked set and reported nothing, so the node
// could never compute the pod Initialized.
func TestPlainInitContainerReportsTerminatedAfterCompletion(t *testing.T) {
	const podID = "pod-init-done"
	w := &codeByPIDWaiter{codes: map[int]int{1001: 0}}
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: w})
	box := hostBinBox(rt, podID)
	box.InitContainers = []*runtimev1.Container{{Name: "init", Image: "/bin/true"}}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp.GetError() != nil {
		t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
	}
	if got := resp.GetStatus().GetPhase(); got != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase = %v, want RUNNING", got)
	}
	assertCompletedInit(t, "CreatePod", resp.GetStatus().GetInitContainerStatuses(), "init", 0, "Completed")
	if n := len(resp.GetStatus().GetInitContainerStatuses()); n != 1 {
		t.Errorf("CreatePod: %d init statuses, want 1", n)
	}

	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	assertCompletedInit(t, "GetPodStatus", gs.GetStatus().GetInitContainerStatuses(), "init", 0, "Completed")
	if cs := gs.GetStatus().GetContainerStatuses(); len(cs) != 1 || cs[0].GetName() != "main" {
		t.Errorf("container_statuses = %+v, want only main", cs)
	}
}

// TestFailedPlainInitContainerReportsTerminatedError: a plain init container
// that runs and exits non-zero inside an existing pod (the StartContainer
// resume of an init step that was blocked on its image) is reported under
// init_container_statuses as Terminated with its exit code and reason Error,
// ahead of the init step it now blocks, in spec order.
func TestFailedPlainInitContainerReportsTerminatedError(t *testing.T) {
	const (
		podID   = "pod-init-fail"
		goodRef = "example.com/good:v1"
		badRef  = "example.com/bad:v1"
	)
	pull := &fakePuller{errByRef: map[string]error{
		badRef: errors.New("manifest unknown: no such image"),
	}}
	// init-a is the first spawn (pid 1001), once its image heals.
	w := &codeByPIDWaiter{codes: map[int]int{1001: 3}}
	rt := newTestRuntime(t, Deps{
		Puller:   pull,
		Spawner:  &fakeSpawner{},
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

	pull.healRef(badRef)
	if _, err := rt.StartContainer(context.Background(),
		&runtimev1.StartContainerRequest{PodId: podID, Container: "init-a"}); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}

	var ics []*runtimev1.ContainerStatus
	waitFor(t, 3*time.Second, "init-a to report terminated", func() bool {
		gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
		if err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		ics = gs.GetStatus().GetInitContainerStatuses()
		return len(ics) > 0 && ics[0].GetState().GetTerminated() != nil
	})
	assertCompletedInit(t, "GetPodStatus", ics, "init-a", 3, "Error")
	if len(ics) != 2 || ics[0].GetName() != "init-a" || ics[1].GetName() != "init-b" {
		t.Fatalf("init_container_statuses = %+v, want [init-a init-b] in spec order", ics)
	}
	if w := ics[1].GetState().GetWaiting(); w == nil || w.GetReason() != waitingPodInitializing {
		t.Errorf("init-b state = %+v, want Waiting %s", ics[1].GetState(), waitingPodInitializing)
	}
}
