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
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/crilog"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// stoppingGuest is a guest whose containers answer the stop signal the way a
// shell trap does: one line up front, then, only once the host has asked the
// guest to stop (stop closes), lines more and a clean end of stream. With stuck
// set, it instead holds the stream open and silent until the host gives up on it,
// which is a stream nothing will ever end.
type stoppingGuest struct {
	guestv1.UnimplementedGuestAgentServer

	lines int
	stuck bool

	stop chan struct{}
	// ended receives one value per container as its first connection's handler
	// finishes.
	ended chan string
	// connected receives one value per container once its first line is sent.
	connected chan string
}

func newStoppingGuest(containers, lines int, stuck bool) *stoppingGuest {
	return &stoppingGuest{
		lines:     lines,
		stuck:     stuck,
		stop:      make(chan struct{}),
		ended:     make(chan string, containers),
		connected: make(chan string, containers),
	}
}

func (g *stoppingGuest) Logs(req *runtimev1.GetLogsRequest, gs guestv1.GuestAgent_LogsServer) error {
	if req.GetSinceTime() != nil {
		return nil // a reconnect: everything retained was already sent
	}
	name := req.GetContainer()
	defer func() { g.ended <- name }()
	at := time.Now()
	send := func(line string) error {
		at = at.Add(time.Millisecond)
		return gs.Send(&runtimev1.LogEntry{
			Line:      []byte(line),
			Timestamp: timestamppb.New(at),
			Stream:    runtimev1.LogStream_LOG_STREAM_STDOUT,
		})
	}
	if err := send(name + " up"); err != nil {
		return err
	}
	g.connected <- name
	if g.stuck {
		<-gs.Context().Done()
		return nil
	}
	select {
	case <-g.stop:
	case <-gs.Context().Done():
		return nil
	}
	for i := range g.lines {
		if err := send(fmt.Sprintf("%s term %d", name, i)); err != nil {
			return err
		}
	}
	return nil
}

// startStopFollowers gives each container its own log file and follower, and
// returns once every follower's first connection is live. It returns the paths.
func startStopFollowers(ctx context.Context, t *testing.T, rt *Runtime, p *pod, g *stoppingGuest, containers ...string) map[string]string {
	t.Helper()
	paths := make(map[string]string, len(containers))
	writers := make(map[string]*crilog.Writer, len(containers))
	for _, name := range containers {
		paths[name] = filepath.Join(t.TempDir(), "0.log")
		w, err := crilog.Open(paths[name])
		if err != nil {
			t.Fatalf("open the log of %s: %v", name, err)
		}
		writers[name] = w
	}
	p.mu.Lock()
	p.guestLogs = writers
	p.mu.Unlock()
	for _, name := range containers {
		rt.startGuestLogFollower(p, name)
	}
	for range containers {
		select {
		case <-g.connected:
		case <-ctx.Done():
			t.Fatal("a follower never connected to the guest")
		}
	}
	return paths
}

// deleteVMPod runs DeletePod and returns how long it held, failing the test if it
// outlives ctx: a stop a stuck stream can hold must read as this failure, not as a
// hung test binary.
func deleteVMPod(ctx context.Context, t *testing.T, rt *Runtime, podID string, grace int64) time.Duration {
	t.Helper()
	began := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := rt.DeletePod(ctx, &runtimev1.DeletePodRequest{PodId: podID, GracePeriodSeconds: grace})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("DeletePod did not return: a log stream held the stop")
	}
	return time.Since(began)
}

// TestVMContainerOutputDuringStopReachesItsLog is the gate for a vm pod's
// termination output. A container's SIGTERM handler runs while the guest stops,
// and what it prints must land in the container's log file, as it does upstream,
// while a stream that never ends must not hold the delete.
func TestVMContainerOutputDuringStopReachesItsLog(t *testing.T) {
	containers := []string{"web", "client"}

	// wantLines reads each container's file and pins the whole sequence.
	wantLines := func(t *testing.T, paths map[string]string, lines int) {
		t.Helper()
		for name, path := range paths {
			got := readCRILog(t, path)
			if len(got) != lines+1 {
				t.Errorf("%s: the log file holds %d lines, want %d: output written after the stop signal was lost",
					name, len(got), lines+1)
				continue
			}
			if got[0].payload != name+" up" {
				t.Errorf("%s: first line = %q", name, got[0].payload)
			}
			for i := range lines {
				if want := fmt.Sprintf("%s term %d", name, i); got[i+1].payload != want {
					t.Errorf("%s: line %d = %q, want %q", name, i+1, got[i+1].payload, want)
				}
			}
		}
	}

	t.Run("output the guest writes before the stop returns", func(t *testing.T) {
		const lines = 2
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		g := newStoppingGuest(len(containers), lines, false)
		dial, _ := startFakeGuestAgent(t, g)
		vmb := &fakeVMBackend{available: true}
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: vmb})
		rt.vmStopLogDrain = 30 * time.Second
		p := addVMPod(t, rt, "pod-stop-output", containers...)
		paths := startStopFollowers(ctx, t, rt, p, g, containers...)

		// The guest's whole stop happens inside StopVM, as on the rig: the stop
		// signal, the trap's output, the end of each stream.
		vmb.stopHook = func(string) {
			close(g.stop)
			for range containers {
				select {
				case <-g.ended:
				case <-ctx.Done():
				}
			}
		}
		deleteVMPod(ctx, t, rt, "pod-stop-output", 30)
		wantLines(t, paths, lines)
	})

	t.Run("output still crossing when the stop returns", func(t *testing.T) {
		// Far more than a stream delivers in the moment after StopVM returns, so
		// a delete that cancels the followers there, rather than draining them,
		// cuts the file short.
		const lines = 2000
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		g := newStoppingGuest(len(containers), lines, false)
		dial, _ := startFakeGuestAgent(t, g)
		vmb := &fakeVMBackend{available: true}
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: vmb})
		rt.vmStopLogDrain = 30 * time.Second
		p := addVMPod(t, rt, "pod-stop-crossing", containers...)
		paths := startStopFollowers(ctx, t, rt, p, g, containers...)

		vmb.stopHook = func(string) { close(g.stop) }
		deleteVMPod(ctx, t, rt, "pod-stop-crossing", 30)
		wantLines(t, paths, lines)
	})

	t.Run("a stuck stream holds the stop only to the drain bound", func(t *testing.T) {
		const bound = 100 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		g := newStoppingGuest(len(containers), 0, true)
		dial, _ := startFakeGuestAgent(t, g)
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		rt.vmStopLogDrain = bound
		p := addVMPod(t, rt, "pod-stop-stuck", containers...)
		startStopFollowers(ctx, t, rt, p, g, containers...)

		held := deleteVMPod(ctx, t, rt, "pod-stop-stuck", 30)
		if held < bound {
			t.Errorf("the delete returned after %v, under the %v bound: it did not wait for the followers", held, bound)
		}
		// The bound ends the streams, so neither follower outlives the delete.
		for range containers {
			select {
			case <-g.ended:
			case <-ctx.Done():
				t.Fatal("a stuck stream outlived the delete")
			}
		}
	})

	t.Run("a stuck stream cannot hold the stop past the grace period", func(t *testing.T) {
		const (
			grace = int64(1)
			slack = 5 * time.Second // scheduling room under -race, nothing more
		)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		g := newStoppingGuest(len(containers), 0, true)
		dial, _ := startFakeGuestAgent(t, g)
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		rt.vmStopLogDrain = time.Hour
		p := addVMPod(t, rt, "pod-stop-stuck-grace", containers...)
		startStopFollowers(ctx, t, rt, p, g, containers...)

		if held := deleteVMPod(ctx, t, rt, "pod-stop-stuck-grace", grace); held > time.Duration(grace)*time.Second+slack {
			t.Errorf("the delete held for %v against a %ds grace", held, grace)
		}
	})

	t.Run("the drain bound", func(t *testing.T) {
		const ceiling = 2 * time.Second
		for _, tc := range []struct {
			name      string
			graceLeft time.Duration
			ceiling   time.Duration
			want      time.Duration
		}{
			{"grace to spare stops at the ceiling", time.Minute, ceiling, ceiling},
			{"the grace left cuts the ceiling", time.Second, ceiling, time.Second},
			{"a spent grace still gets the floor", 0, ceiling, vmStopLogDrainFloor},
			{"an overrun grace still gets the floor", -time.Minute, ceiling, vmStopLogDrainFloor},
			{"a ceiling under the floor wins", 0, time.Millisecond, time.Millisecond},
			{"an unset ceiling is the default", time.Minute, 0, defaultVMStopLogDrain},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rt := &Runtime{vmStopLogDrain: tc.ceiling}
				if got := rt.guestStopLogDrainBound(tc.graceLeft); got != tc.want {
					t.Errorf("bound = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("no follower starts once the guest has gone", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, "pod-stop-late", "app")
		rt.finishGuestLogFollowers(p, time.Second)
		rt.startGuestLogFollower(p, "app")
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.guestLogFollow) != 0 {
			t.Error("a follower started after the guest had gone, and nothing would end it")
		}
	})

	t.Run("cancelling supervision without a stop still ends the follower", func(t *testing.T) {
		// A daemon shutdown and a failed assembly cancel the pod with no delete in
		// progress; a follower they left running would be a leak.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		g := newStoppingGuest(1, 0, true)
		dial, _ := startFakeGuestAgent(t, g)
		rt := newTestRuntime(t, Deps{GuestDialer: dial, VMBackend: &fakeVMBackend{available: true}})
		p := addVMPod(t, rt, "pod-stop-cancelled", "app")
		startStopFollowers(ctx, t, rt, p, g, "app")

		p.cancel()
		select {
		case <-g.ended:
		case <-ctx.Done():
			t.Fatal("the follower outlived its pod's supervision")
		}
	})
}
