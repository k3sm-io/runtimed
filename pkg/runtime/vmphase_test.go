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
	"testing"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// vmPhasePod builds an unregistered vm pod declaring mains (and optionally init
// containers) at the given starting phase, with no guest statuses folded yet.
func vmPhasePod(phase runtimev1.PodPhase, mains, inits []string) *pod {
	box := &runtimev1.PodBox{PodId: "pod-phase", Namespace: "default", Name: "p"}
	for _, n := range inits {
		box.InitContainers = append(box.InitContainers,
			&runtimev1.Container{Name: n, Image: "docker.io/library/busybox:latest"})
	}
	for _, n := range mains {
		box.Containers = append(box.Containers,
			&runtimev1.Container{Name: n, Image: "docker.io/library/busybox:latest"})
	}
	return &pod{box: box, backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, phase: phase}
}

// running/terminated build the two folded container states a guest event
// produces, so a table row reads as the state the guest reported.
func running() *runtimev1.ContainerState {
	return &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}}
}

func terminated(code, signal int32) *runtimev1.ContainerState {
	return &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
		ExitCode: code, Signal: signal, FinishedAt: nowProto(),
	}}
}

// TestVMPodPhaseFollowsItsContainers is the DEFECT GATE for a vm pod that never
// reached a terminal phase.
//
// The live symptom: a restartPolicy:Never vm pod whose single container ran to
// completion showed `kubectl` STATUS Completed — the terminated container status
// was folded correctly — against `.status.phase: Pending`, forever. The fold
// updated container_statuses and stopped there, so the phase stayed whatever
// createVMPod stamped (Running), and the provider's derivePhase, which will not
// promote a non-terminal runtime verdict to a terminal one and saw no running
// container to keep it at Running, fell through to Pending. A Job never
// finished, and a completed pod was never collected.
//
// The rows below are the whole derivation, including the two that must NOT
// conclude the pod: an init container's exit (init runs before any main, so
// counting it would report Succeeded for a workload that had not begun) and a
// main with no status yet.
func TestVMPodPhaseFollowsItsContainers(t *testing.T) {
	cases := []struct {
		name   string
		start  runtimev1.PodPhase
		mains  []string
		inits  []string
		states map[string]*runtimev1.ContainerState
		reason string
		want   runtimev1.PodPhase
	}{{
		name:  "nothing-folded-yet-leaves-the-phase-alone",
		start: runtimev1.PodPhase_POD_PHASE_PENDING,
		mains: []string{"app"},
		want:  runtimev1.PodPhase_POD_PHASE_PENDING,
	}, {
		name:   "a-running-main-is-Running",
		start:  runtimev1.PodPhase_POD_PHASE_PENDING,
		mains:  []string{"app"},
		states: map[string]*runtimev1.ContainerState{"app": running()},
		want:   runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		// The defect, minimally: exit 0 under restartPolicy Never.
		name:   "a-completed-main-exit-0-is-Succeeded",
		start:  runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains:  []string{"app"},
		states: map[string]*runtimev1.ContainerState{"app": terminated(0, 0)},
		want:   runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
	}, {
		name:   "a-completed-main-exit-nonzero-is-Failed",
		start:  runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains:  []string{"app"},
		states: map[string]*runtimev1.ContainerState{"app": terminated(42, 0)},
		want:   runtimev1.PodPhase_POD_PHASE_FAILED,
	}, {
		// A SIGKILLed container did not succeed, whatever its code reads. This
		// is the provider's own (ExitCode != 0 || Signal != 0) test; the two
		// ends of the seam must not disagree about what "completed" means.
		name:   "a-signalled-main-with-exit-0-is-Failed",
		start:  runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains:  []string{"app"},
		states: map[string]*runtimev1.ContainerState{"app": terminated(0, 9)},
		want:   runtimev1.PodPhase_POD_PHASE_FAILED,
	}, {
		name:  "one-running-one-completed-is-Running",
		start: runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains: []string{"a", "b"},
		states: map[string]*runtimev1.ContainerState{
			"a": running(), "b": terminated(0, 0),
		},
		want: runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		// Upstream never reports a terminal phase while a container runs,
		// whatever a sibling did — including a sibling that failed.
		name:  "one-running-one-failed-is-still-Running",
		start: runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains: []string{"a", "b"},
		states: map[string]*runtimev1.ContainerState{
			"a": running(), "b": terminated(7, 0),
		},
		want: runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		name:  "every-main-exit-0-is-Succeeded",
		start: runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains: []string{"a", "b"},
		states: map[string]*runtimev1.ContainerState{
			"a": terminated(0, 0), "b": terminated(0, 0),
		},
		want: runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
	}, {
		name:  "mixed-terminations-are-Failed",
		start: runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains: []string{"a", "b"},
		states: map[string]*runtimev1.ContainerState{
			"a": terminated(0, 0), "b": terminated(1, 0),
		},
		want: runtimev1.PodPhase_POD_PHASE_FAILED,
	}, {
		// A partially-folded pod is a fold in progress, not a verdict: leave the
		// phase where it was and let the next event resolve it. Reporting
		// Succeeded here would conclude a pod whose second main is about to run.
		name:  "one-completed-one-unreported-leaves-the-phase-alone",
		start: runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains: []string{"a", "b"},
		states: map[string]*runtimev1.ContainerState{
			"a": terminated(0, 0),
		},
		want: runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		// The init-container exclusion. A successful init exits 0 before any
		// main starts, so an accounting that walked the folded status map
		// instead of the declared mains would report Succeeded for a pod whose
		// workload had not begun.
		name:   "a-succeeded-init-does-not-conclude-the-pod",
		start:  runtimev1.PodPhase_POD_PHASE_RUNNING,
		mains:  []string{"app"},
		inits:  []string{"setup"},
		states: map[string]*runtimev1.ContainerState{"setup": terminated(0, 0)},
		want:   runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		name:  "a-succeeded-init-with-a-running-main-is-Running",
		start: runtimev1.PodPhase_POD_PHASE_PENDING,
		mains: []string{"app"},
		inits: []string{"setup"},
		states: map[string]*runtimev1.ContainerState{
			"setup": terminated(0, 0), "app": running(),
		},
		want: runtimev1.PodPhase_POD_PHASE_RUNNING,
	}, {
		// failVMPod's verdict outranks the container accounting: it records WHY
		// the machine died, which no container status carries, and a late event
		// from the dying guest must not de-escalate the pod back to Running.
		name:   "a-pod-level-failure-is-not-de-escalated-by-a-late-start",
		start:  runtimev1.PodPhase_POD_PHASE_FAILED,
		mains:  []string{"app"},
		states: map[string]*runtimev1.ContainerState{"app": running()},
		reason: "VMHostExited",
		want:   runtimev1.PodPhase_POD_PHASE_FAILED,
	}, {
		// A pod declaring no mains has nothing to conclude on. Mirrors the host
		// spine's mains == 0 guard.
		name:   "no-declared-mains-leaves-the-phase-alone",
		start:  runtimev1.PodPhase_POD_PHASE_RUNNING,
		inits:  []string{"setup"},
		states: map[string]*runtimev1.ContainerState{"setup": terminated(0, 0)},
		want:   runtimev1.PodPhase_POD_PHASE_RUNNING,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := vmPhasePod(tc.start, tc.mains, tc.inits)
			p.reason = tc.reason
			for name, state := range tc.states {
				st := p.guestContainerLocked(name, "docker.io/library/busybox:latest")
				st.State = state
				st.Ready = state.GetRunning() != nil
			}
			recomputeVMPhaseLocked(p)
			if p.phase != tc.want {
				t.Errorf("phase = %v, want %v", p.phase, tc.want)
			}
		})
	}
}

// TestVMPodTerminalPhaseIsFoldedAndPublished is the END-TO-END half of the
// defect gate: it drives the real event fold (applyGuestContainerEvent), so it
// asserts the property the live pod lacked — a terminated container status and a
// TERMINAL pod phase, reported together and announced on WatchPodStatus.
//
// The publish half matters as much as the phase: WatchPodStatus is the
// provider's only event-driven notice that a pod moved. A terminal transition
// nothing publishes is a completed pod that only a resync would ever collect.
func TestVMPodTerminalPhaseIsFoldedAndPublished(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit *guestv1.ContainerExited
		want runtimev1.PodPhase
	}{
		{"exit-0-reaches-Succeeded", &guestv1.ContainerExited{ExitCode: 0}, runtimev1.PodPhase_POD_PHASE_SUCCEEDED},
		{"exit-42-reaches-Failed", &guestv1.ContainerExited{ExitCode: 42}, runtimev1.PodPhase_POD_PHASE_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{VMBackend: &fakeVMBackend{available: true}})
			p := addVMPod(t, rt, "pod-vm-phase", "app")
			events, cancel := rt.broker.subscribe(p.box.GetPodId())
			defer cancel()

			rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
				Container: "app",
				Started:   &guestv1.ContainerStarted{Pid: 7},
			})
			rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
				Container: "app",
				Exited:    tc.exit,
			})

			p.mu.Lock()
			phase := p.phase
			p.mu.Unlock()
			if phase != tc.want {
				t.Fatalf("phase = %v, want %v — a vm pod whose only container terminated must reach a terminal phase, "+
					"or the provider reports Pending against a Completed container status forever", phase, tc.want)
			}

			// The last event on the wire carries the same verdict, with the
			// container's own terminated state beside it.
			var last *runtimev1.PodStatus
			deadline := time.After(5 * time.Second)
			for last.GetPhase() != tc.want {
				select {
				case ev := <-events:
					last = ev.GetStatus()
				case <-deadline:
					t.Fatalf("no published status reached %v (last: %v)", tc.want, last.GetPhase())
				}
			}
			cs := last.GetContainerStatuses()
			if len(cs) != 1 {
				t.Fatalf("published %d container statuses, want 1", len(cs))
			}
			if term := cs[0].GetState().GetTerminated(); term == nil {
				t.Errorf("the published container status is not terminated: %v", cs[0].GetState())
			} else if term.GetExitCode() != tc.exit.GetExitCode() {
				t.Errorf("exit code = %d, want %d", term.GetExitCode(), tc.exit.GetExitCode())
			}
		})
	}
}
