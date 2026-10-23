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
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/guestagent"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fastExitAgent is a guest whose container printed one line and exited before
// the host's log follower had that line: the exit report goes out at once,
// while the first Logs connection holds the line for inFlight before sending
// it, the way an entry still crossing the boundary arrives after the exit
// event that overtook it. Later connections serve the retained line at or
// after their since_time and end, as a guest serves a container that exited.
type fastExitAgent struct {
	guestv1.UnimplementedGuestAgentServer

	line     *runtimev1.LogEntry
	inFlight time.Duration

	mu       sync.Mutex
	connects int
}

func (a *fastExitAgent) ContainerEvents(_ *guestv1.ContainerEventsRequest, gs guestv1.GuestAgent_ContainerEventsServer) error {
	if err := gs.Send(&guestv1.ContainerEvent{
		Container: "app",
		Timestamp: timestamppb.Now(),
		Exited:    &guestv1.ContainerExited{ExitCode: 1},
	}); err != nil {
		return err
	}
	<-gs.Context().Done()
	return nil
}

func (a *fastExitAgent) Logs(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error {
	a.mu.Lock()
	a.connects++
	first := a.connects == 1
	a.mu.Unlock()
	if first {
		select {
		case <-time.After(a.inFlight):
		case <-gs.Context().Done():
			return nil
		}
	}
	if ts := req.GetSinceTime(); ts.IsValid() && a.line.GetTimestamp().AsTime().Before(ts.AsTime()) {
		return nil
	}
	return gs.Send(a.line)
}

// startVMLogFollower gives a test vm pod's container a log file and starts its
// follower, as the vm pod assembly does, and returns the file's path.
func startVMLogFollower(t *testing.T, rt *Runtime, p *pod, container string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "0.log")
	w, err := crilog.Open(path)
	if err != nil {
		t.Fatalf("open the container log: %v", err)
	}
	p.mu.Lock()
	p.guestLogs = map[string]*crilog.Writer{container: w}
	p.mu.Unlock()
	rt.startGuestLogFollower(p, container)
	return path
}

// TestFastExitContainerLogLineReachesTheFile is the gate: a vm container
// that prints one line and exits within its first second must have that line
// in its CRI log file by the time its exit is recorded.
//
// The kubelet restarts a crashed container as soon as it sees the exit, the
// restart opens the next instance's file, and the guest's restart discards the
// old instance's retained output. So an exit recorded before the line reached
// the file is a `kubectl logs --previous` that stays empty, which is what the
// rig saw while restartCount and lastState were right. The guest here reports
// the exit before the line has crossed; the host must hold the exit until the
// file has it.
func TestFastExitContainerLogLineReachesTheFile(t *testing.T) {
	const podID = "pod-fast-exit"
	agent := &fastExitAgent{
		line: &runtimev1.LogEntry{
			Line:      []byte("run 2 exiting 1"),
			Timestamp: timestamppb.New(time.Now()),
			Stream:    runtimev1.LogStream_LOG_STREAM_STDOUT,
		},
		inFlight: 300 * time.Millisecond,
	}
	dial, _ := startFakeGuestAgent(t, agent)
	rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
	p := addVMPod(t, rt, podID, "app")
	path := startVMLogFollower(t, rt, p, "app")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	watched := make(chan error, 1)
	go func() { watched <- rt.watchGuestContainerEvents(ctx, p) }()
	defer func() { cancel(); <-watched }()

	waitGuestContainer(t, p, "app", func(st *runtimev1.ContainerStatus) bool {
		return st.GetState().GetTerminated() != nil
	})
	// Read at the moment the exit is observable, as the kubelet would act on it.
	lines := readCRILog(t, path)
	if len(lines) != 1 || lines[0].payload != "run 2 exiting 1" {
		t.Fatalf("the log file holds %v when the exit is recorded, want the container's one line: "+
			"the exit was recorded before its output reached the file", lines)
	}
}

// TestVMContainerOutputBeforeExitIsAllInTheFile drives the real guest agent and
// capture: a container that is followed live writes far more than the live
// channel buffers, then exits. Every line must be in the file, in order, by the
// time the exit is recorded. The guest's live delivery never blocks the
// container's pump, so a follower behind a fast writer had entries dropped from
// its channel and lost for good; it now fetches them from the ring.
func TestVMContainerOutputBeforeExitIsAllInTheFile(t *testing.T) {
	const (
		podID = "pod-chatty-exit"
		lines = 3000 // under the ring's entry bound, far over the live buffer
	)
	capture := guestagent.NewCapture(0, 0, 0)
	events := guestagent.NewEvents(0)
	out := capture.Writer("app", guestagent.StreamStdout)
	dial := startRealGuestAgent(t, podID, guestagent.Deps{
		Runner: stubRunner{names: []string{"app"}},
		Logs:   capture,
		Events: events,
	})
	rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
	p := addVMPod(t, rt, podID, "app")
	path := startVMLogFollower(t, rt, p, "app")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	watched := make(chan error, 1)
	go func() { watched <- rt.watchGuestContainerEvents(ctx, p) }()
	defer func() { cancel(); events.Close(); <-watched }()

	// The follower is live once the first line is in the file.
	if _, err := fmt.Fprintln(out, "ready"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(readCRILog(t, path)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the follower never wrote the first line")
		}
		time.Sleep(5 * time.Millisecond)
	}

	for i := 0; i < lines; i++ {
		if _, err := fmt.Fprintf(out, "line %d\n", i); err != nil {
			t.Fatal(err)
		}
	}
	// The guest's exit path: the pumps drain, the stream ends, then the exit
	// is published.
	_ = out.Close()
	if !capture.Drain("app", time.Second) {
		t.Fatal("the capture did not drain after its only writer closed")
	}
	capture.Close("app")
	events.Publish(guestagent.ContainerEvent{Container: "app", At: time.Now(), Exited: &guestagent.ContainerExited{ExitCode: 0}})

	waitGuestContainer(t, p, "app", func(st *runtimev1.ContainerStatus) bool {
		return st.GetState().GetTerminated() != nil
	})
	got := readCRILog(t, path)
	if len(got) != lines+1 {
		t.Fatalf("the log file holds %d lines when the exit is recorded, want %d: output was lost", len(got), lines+1)
	}
	for i := 0; i < lines; i++ {
		if want := fmt.Sprintf("line %d", i); got[i+1].payload != want {
			t.Fatalf("line %d = %q, want %q", i+1, got[i+1].payload, want)
		}
	}
}
