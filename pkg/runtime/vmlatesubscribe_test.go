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

	"k3sm.io/runtimed/pkg/guestagent"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVMPodFoldsStateFromALateSubscribe is the host half of the Pending-forever
// defect, driven through both real halves.
//
// The guest starts its containers and only then serves the agent, so by the time
// the daemon subscribes every ContainerStarted has already been published. With a
// live-only stream the daemon learned nothing: `kubectl get pod` showed Pending,
// Ready=False (ContainersNotReady) and NO containerStatuses at all, for a guest
// that was demonstrably running the container.
//
// Nothing here is faked except the seams that would need a Linux kernel: the
// guestagent.Events bus, the shipped guestagent.Server, the gRPC round trip and
// the daemon's own fold are all production code.
func TestVMPodFoldsStateFromALateSubscribe(t *testing.T) {
	const podID = "pod-late"

	cases := []struct {
		name string
		// published happens BEFORE the daemon subscribes — the whole point.
		published  []guestagent.ContainerEvent
		wantStates map[string]string // container -> "running" | "terminated"
		wantReady  map[string]bool
	}{
		{
			name: "a-running-container-is-reported-running",
			published: []guestagent.ContainerEvent{
				{Container: "app", At: time.Now(), Started: &guestagent.ContainerStarted{PID: 93}},
			},
			wantStates: map[string]string{"app": "running"},
			wantReady:  map[string]bool{"app": true},
		},
		{
			name: "a-completed-init-and-a-running-main-are-both-reported",
			published: []guestagent.ContainerEvent{
				{Container: "init", At: time.Now(), Started: &guestagent.ContainerStarted{PID: 7}},
				{Container: "init", At: time.Now(), Exited: &guestagent.ContainerExited{ExitCode: 0}},
				{Container: "app", At: time.Now(), Started: &guestagent.ContainerStarted{PID: 93}},
			},
			wantStates: map[string]string{"init": "terminated", "app": "running"},
			wantReady:  map[string]bool{"init": false, "app": true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := guestagent.NewEvents(0)
			for _, ev := range tc.published {
				events.Publish(ev)
			}
			dial := startRealGuestAgent(t, podID, guestagent.Deps{
				Runner: stubRunner{names: []string{"init", "app"}},
				Events: events,
			})
			rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
			p := addVMPod(t, rt, podID, "init", "app")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			watchDone := make(chan struct{})
			go func() {
				defer close(watchDone)
				_ = rt.watchGuestContainerEvents(ctx, p)
			}()

			deadline := time.Now().Add(10 * time.Second)
			var got map[string]*runtimev1.ContainerStatus
			for {
				got = containerStatesByName(rt.podStatus(p))
				if len(got) >= len(tc.wantStates) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the daemon never learned any container state from a late subscribe; statuses = %v", got)
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			<-watchDone

			for name, want := range tc.wantStates {
				st, ok := got[name]
				if !ok {
					t.Errorf("no container status for %q; kubectl would show the pod Pending with no containerStatuses", name)
					continue
				}
				switch want {
				case "running":
					if st.GetState().GetRunning() == nil {
						t.Errorf("container %q state = %+v, want Running", name, st.GetState())
					}
				case "terminated":
					if st.GetState().GetTerminated() == nil {
						t.Errorf("container %q state = %+v, want Terminated", name, st.GetState())
					}
				}
				if st.GetReady() != tc.wantReady[name] {
					t.Errorf("container %q ready = %v, want %v", name, st.GetReady(), tc.wantReady[name])
				}
			}
		})
	}
}

// containerStatesByName indexes a pod status's container statuses by name.
func containerStatesByName(st *runtimev1.PodStatus) map[string]*runtimev1.ContainerStatus {
	out := map[string]*runtimev1.ContainerStatus{}
	for _, c := range st.GetContainerStatuses() {
		out[c.GetName()] = c
	}
	return out
}
