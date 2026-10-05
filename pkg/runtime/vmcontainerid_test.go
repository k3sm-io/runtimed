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
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/crilog"
)

// TestVMContainerStatesCarryTheContainerID is the defect gate for a vm
// container that never got a container id. The embedder's logs handler, like
// the upstream kubelet, refuses logs for a terminated container with no id, so a
// finished vm Pod's `kubectl logs` failed with "container is terminated" while a
// native Completed pod's worked. Every row asserts the fold mints an id on
// start, carries it (with the start time and the log file) into the terminated
// state, and keeps it distinct per container.
func TestVMContainerStatesCarryTheContainerID(t *testing.T) {
	for _, tc := range []struct {
		name string
		// conclude terminates the started containers: a guest Exited event, or
		// the machine dying under them (failVMPod).
		conclude func(rt *Runtime, p *pod, container string)
		reason   string
	}{
		{"guest-exit", func(rt *Runtime, p *pod, c string) {
			rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
				Container: c, Exited: &guestv1.ContainerExited{ExitCode: 0},
			})
		}, "Completed"},
		{"machine-died", func(rt *Runtime, p *pod, _ string) {
			rt.failVMPod(p, "VMHostExited", "the guest is gone")
		}, "VMHostExited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{VMBackend: &fakeVMBackend{available: true}})
			p := addVMPod(t, rt, "pod-vm-cid", "app", "side")
			writers := map[string]*crilog.Writer{}
			for _, c := range []string{"app", "side"} {
				w, err := crilog.Open(filepath.Join(t.TempDir(), c, "0.log"))
				if err != nil {
					t.Fatalf("open writer: %v", err)
				}
				t.Cleanup(func() { _ = w.Close() })
				writers[c] = w
			}
			p.guestLogs = writers

			// Before any start a container has no id, as upstream.
			p.mu.Lock()
			seeded := proto.Clone(p.guestContainerLocked("app", "busybox")).(*runtimev1.ContainerStatus)
			p.mu.Unlock()
			if seeded.GetContainerId() != "" {
				t.Fatalf("a never-started container has id %q, want none", seeded.GetContainerId())
			}

			for i, c := range []string{"app", "side"} {
				rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
					Container: c, Started: &guestv1.ContainerStarted{Pid: int32(7 + i)},
				})
			}
			p.mu.Lock()
			runningApp := proto.Clone(p.guestContainers["app"]).(*runtimev1.ContainerStatus)
			runningSide := proto.Clone(p.guestContainers["side"]).(*runtimev1.ContainerStatus)
			p.mu.Unlock()

			id := runningApp.GetContainerId()
			if id == "" {
				t.Fatal("a started vm container has no container id")
			}
			if len(id) != 64 {
				t.Errorf("container id %q is not a hex sha256", id)
			}
			if runningApp.GetState().GetRunning() == nil {
				t.Fatalf("after Started the state is %v, want Running", runningApp.GetState())
			}
			if runningSide.GetContainerId() == "" || runningSide.GetContainerId() == id {
				t.Errorf("two containers got ids %q and %q, want two distinct ids", id, runningSide.GetContainerId())
			}
			if got, want := runningApp.GetLogPath(), writers["app"].Path(); got != want {
				t.Errorf("status log_path = %q, want %q", got, want)
			}

			tc.conclude(rt, p, "app")

			p.mu.Lock()
			after := proto.Clone(p.guestContainers["app"]).(*runtimev1.ContainerStatus)
			p.mu.Unlock()
			term := after.GetState().GetTerminated()
			if term == nil {
				t.Fatalf("after %s the state is %v, want Terminated", tc.name, after.GetState())
			}
			if term.GetReason() != tc.reason {
				t.Errorf("reason = %q, want %q", term.GetReason(), tc.reason)
			}
			if after.GetContainerId() != id {
				t.Errorf("status container id changed %q -> %q", id, after.GetContainerId())
			}
			if term.GetContainerId() != id {
				t.Errorf("terminated container_id = %q, want %q — the logs handler refuses a terminated container with no id",
					term.GetContainerId(), id)
			}
			if term.GetStartedAt() == nil {
				t.Error("terminated started_at is nil, want the Running state's start time")
			} else if !proto.Equal(term.GetStartedAt(), runningApp.GetState().GetRunning().GetStartedAt()) {
				t.Errorf("terminated started_at = %v, want %v",
					term.GetStartedAt().AsTime(), runningApp.GetState().GetRunning().GetStartedAt().AsTime())
			}
			if got, want := term.GetLogPath(), runningApp.GetLogPath(); got != want || got == "" {
				t.Errorf("terminated log_path = %q, want the status log_path %q", got, want)
			}
		})
	}
}
