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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errWaitWedge is a canned ExitWaiter error used to drive watchContainerExit's
// wait-error branch (which sets term.Message itself).
var errWaitWedge = errors.New("supervisor wait failed")

// pipeSpawner drives the real supervisor.Process log pipes: it writes payload to
// the child's stdout fd and closes both write ends, simulating a container that
// emitted its final output and then exited. It is how these tests push bytes
// through the pumps (not a pre-populated buffer), so the pump-vs-reaper drain
// ordering is exercised end-to-end. payload stays well under the OS pipe buffer
// so the synchronous write in Spawn (before the pump goroutines start) never
// blocks.
//
// Both writes go through a DUP of the handed fd rather than the fd itself: the
// Process still owns those descriptors, and closing one here would free its
// number for the very next dup, aliasing the two streams. (The same reason the
// supervisor's own fakes dup; see writeAndClose there.)
type pipeSpawner struct{ payload string }

func (s pipeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if s.payload != "" {
		// Written VERBATIM: the payloads here deliberately end without a newline
		// (a crashing container's last write), and that is what makes the final
		// chunk carry the CRI partial tag.
		if err := writeRawToStreamDup(spec.StdoutFD, s.payload); err != nil {
			return 0, err
		}
	}
	return 4242, nil
}

// cannedWaiter is an ExitWaiter returning a fixed (code, sig, err) — enough to drive
// every terminated-state branch (clean exit, non-zero, signal-kill, wait error).
type cannedWaiter struct {
	code, sig int
	err       error
}

func (w cannedWaiter) WaitExit(context.Context, int) (int, int, error) { return w.code, w.sig, w.err }

// startTermProc builds and Starts a real supervisor.Process whose pipes are fed
// by a pipeSpawner(payload), reaped by w, and whose output is written to a real
// CRI log file under dir — returning the containerProc that wraps it.
//
// decorate (optional) wraps the log sink so a test can gate the pumps' delivery
// timing; nil writes straight through to the file.
func startTermProc(t *testing.T, dir, name, payload string, w supervisor.ExitWaiter,
	decorate func(supervisor.LogSink) supervisor.LogSink) *containerProc {
	t.Helper()
	return startTermProcSpawner(t, dir, name, pipeSpawner{payload: payload}, w, decorate)
}

// startTermProcSpawner is startTermProc over an arbitrary supervisor.Spawner, so a
// test can drive a pipe whose write-end is held open past the child's exit (the
// leaked-grandchild case) instead of the EOF-on-exit pipeSpawner.
func startTermProcSpawner(t *testing.T, dir, name string, spawner supervisor.Spawner,
	w supervisor.ExitWaiter, decorate func(supervisor.LogSink) supervisor.LogSink) *containerProc {
	t.Helper()
	path := filepath.Join(dir, name, "0.log")
	logw, err := crilog.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = logw.Close() })
	fan := &logFanout{}

	var sink supervisor.LogSink = containerLogSink(logw, fan)
	if decorate != nil {
		sink = decorate(sink)
	}
	proc := supervisor.NewProcess(spawner, w,
		supervisor.SpawnSpec{Path: "/term-test", Argv: []string{"/term-test"}}, sink)
	if err := proc.Start(context.Background()); err != nil {
		t.Fatalf("start %s process: %v", name, err)
	}
	return &containerProc{
		name:   name,
		logw:   logw,
		fanout: fan,
		proc:   proc,
		state: &runtimev1.ContainerStatus{
			Name:    name,
			Image:   "/term-test",
			LogPath: path,
			State:   &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}},
		},
	}
}

// heldWriteEnd is a supervisor.Spawner that writes payload to the child's stdout
// fd and then DUPS the STDERR write-end into an independent descriptor it holds
// open — modeling a forked grandchild that inherits and retains a pipe after the
// direct child exits. Because a write-end stays open, one supervisor pump never
// reaches EOF and LogsDrained never closes, so watchContainerExit can only
// finalize via its bounded drainGrace timeout. release() closes the held fd (test
// cleanup) so the pump goroutine can finally drain and exit.
type heldWriteEnd struct {
	payload string

	mu   sync.Mutex
	held *os.File
}

func (s *heldWriteEnd) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if spec.StdoutFD == 0 || spec.StderrFD == 0 {
		return 4242, nil
	}
	if s.payload != "" {
		if err := writeRawToStreamDup(spec.StdoutFD, s.payload); err != nil {
			return 0, err
		}
	}
	// Keep a dup of the stderr write-end open (independent of the parent's copy,
	// which Start closes right after Spawn returns).
	dupFD, err := unix.Dup(int(spec.StderrFD))
	if err != nil {
		return 0, fmt.Errorf("dup stderr fd: %w", err)
	}
	s.mu.Lock()
	s.held = os.NewFile(uintptr(dupFD), "held-stderr")
	s.mu.Unlock()
	return 4242, nil
}

func (s *heldWriteEnd) release() {
	s.mu.Lock()
	h := s.held
	s.held = nil
	s.mu.Unlock()
	if h != nil {
		_ = h.Close()
	}
}

// TestContainerExitFinalizesTerminatedState is the B11 gate, re-targeted onto
// the on-disk split.
//
// runtimed NO LONGER synthesizes a FallbackToLogsOnError termination message:
// that message is the tail of the container's LOG FILE, and runtimed does not
// read log files — the node computes it from ContainerStatus.log_path exactly as
// the kubelet computes it from the file containerd wrote. What runtimed still
// owns, and what is asserted here, is everything that makes the node's
// computation possible and correct: the terminated reason taxonomy, an
// already-set wait-error message that must not be clobbered, the log_path the
// node resolves, and — load-bearing — the DRAIN-WAIT that holds the terminated
// publish until both pumps have flushed the dying child's final output into the
// file. Without that wait the node reads the tail and finds the line BEFORE the
// panic.
func TestContainerExitFinalizesTerminatedState(t *testing.T) {
	const lastLine = "panic: runtime error: index out of range [9] with length 3"
	failLog := "booting service\nhandling request\n" + lastLine // last token at EOF (no trailing \n)

	cases := []struct {
		name       string
		payload    string
		waiter     supervisor.ExitWaiter
		oomKilled  bool
		wantReason string
		check      func(t *testing.T, term *runtimev1.ContainerStateTerminated)
	}{
		{
			// A non-zero exit gets NO message from runtimed. The output is in
			// the file the terminated state names, which is the node's input.
			name:       "failure-leaves-the-message-to-the-node",
			payload:    failLog,
			waiter:     cannedWaiter{code: 1},
			wantReason: "Error",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != "" {
					t.Errorf("message = %q, want empty: the log-tail fallback is the node's, computed from log_path",
						term.GetMessage())
				}
				if term.GetLogPath() == "" {
					t.Error("terminated state carries no log_path; the node has nothing to read the tail from")
				}
			},
		},
		{
			// Negative (conformance-load-bearing): exit-0 (Completed) has an
			// empty message — upstream [NodeConformance] asserts that.
			name:       "success-exit-0-has-no-message",
			payload:    "all good\nstill good\ndone",
			waiter:     cannedWaiter{code: 0},
			wantReason: "Completed",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != "" {
					t.Errorf("exit-0 message = %q, want empty", term.GetMessage())
				}
			},
		},
		{
			// Negative: a message set on the wait-error path is not clobbered.
			name:       "wait-error-message-preserved",
			payload:    "noise\nmore noise\neven more noise",
			waiter:     cannedWaiter{code: 1, err: errWaitWedge},
			wantReason: "Error",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != errWaitWedge.Error() {
					t.Errorf("message = %q, want the preserved wait error %q", term.GetMessage(), errWaitWedge.Error())
				}
			},
		},
		{
			// Signal-kill (OOMKilled, sig 9 / code 137): term.Reason stays
			// "OOMKilled" (the M2.5 OOM test depends on it).
			name:       "oomkill-signal-reason-preserved",
			payload:    "allocating\nallocating more\n" + lastLine,
			waiter:     cannedWaiter{code: 137, sig: 9},
			oomKilled:  true,
			wantReason: "OOMKilled",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != "" {
					t.Errorf("OOMKilled message = %q, want empty", term.GetMessage())
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{})
			box := hostBinBox(rt, "pod-term")
			cp := startTermProc(t, box.GetLogDirectory(), "main", tc.payload, tc.waiter, nil)
			p := &pod{box: box, oomKilled: tc.oomKilled, containers: []*containerProc{cp}}

			rt.watchContainerExit(context.Background(), p, cp, nil)

			term := cp.state.GetState().GetTerminated()
			if term == nil {
				t.Fatal("container has no terminated state")
			}
			if term.GetReason() != tc.wantReason {
				t.Errorf("reason = %q, want %q (reason must be preserved)", term.GetReason(), tc.wantReason)
			}
			tc.check(t, term)
		})
	}

	// race-faithful: drive the real pipes and make the pump-vs-reaper drain
	// ordering load-bearing. The pumps' FIRST sink delivery is gated (sleeps) so
	// that when the reaper unblocks Wait, the final line is provably not yet in
	// the FILE — only the drain-wait in watchContainerExit makes it land. Run
	// under -race, this also exercises the concurrent pump writes against the
	// same crilog.Writer.
	t.Run("race-faithful-real-pipe-drains-into-the-file-before-finalizing", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		const last = "fatal error: concurrent map writes"
		payload := "starting\nworking\n" + last

		gate := func(orig supervisor.LogSink) supervisor.LogSink {
			var once sync.Once
			return func(stream crilog.Stream, chunk []byte, partial bool) error {
				once.Do(func() { time.Sleep(50 * time.Millisecond) })
				return orig(stream, chunk, partial)
			}
		}
		box := hostBinBox(rt, "pod-term-race")
		cp := startTermProc(t, box.GetLogDirectory(), "main", payload, cannedWaiter{code: 2}, gate)
		p := &pod{box: box, containers: []*containerProc{cp}}

		rt.watchContainerExit(context.Background(), p, cp, nil)

		lines := readCRILog(t, cp.state.GetLogPath())
		if len(lines) == 0 {
			t.Fatal("the container log file is empty after the drain-wait")
		}
		if got := lines[len(lines)-1].payload; got != last {
			t.Fatalf("the final log line is %q, want %q — it was lost to the pump/reaper race\n"+
				"(the drain-wait before finalizing is what makes it land)", got, last)
		}
		// EOF without a trailing newline: the CRI tag must say the line is
		// incomplete, so a reader does not present it as a whole one.
		if got := lines[len(lines)-1].tag; got != "P" {
			t.Errorf("the unterminated final line carries tag %q, want P", got)
		}
	})

	// held-open pipe → bounded finalize, NO hang: a forked grandchild holds a
	// write-end open after the direct child exits, so one supervisor pump never
	// reaches EOF and LogsDrained never closes. watchContainerExit must still
	// finalize the terminated status within ~drainGrace, never wedge the pod in
	// Running forever. Run under -race.
	t.Run("held-open-pipe-bounded-finalize-no-hang", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		rt.drainGrace = 60 * time.Millisecond // small + real so the timeout arm is fast

		const lastLine = "panic: held-pipe diagnostic"
		held := &heldWriteEnd{payload: "starting\nworking\n" + lastLine}
		t.Cleanup(held.release) // let the pipe finally EOF so the pump goroutine exits

		box := hostBinBox(rt, "pod-held")
		cp := startTermProcSpawner(t, box.GetLogDirectory(), "main", held, cannedWaiter{code: 2}, nil)
		p := &pod{box: box, containers: []*containerProc{cp}}

		done := make(chan struct{})
		go func() {
			rt.watchContainerExit(context.Background(), p, cp, nil)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("watchContainerExit hung on a held-open pipe (drain-wait was not bounded)")
		}

		// Prove we finalized via the timeout, not EOF: LogsDrained is still open.
		select {
		case <-cp.proc.LogsDrained():
			t.Fatal("LogsDrained closed; the held-open-pipe case did not exercise the bounded timeout")
		default:
		}

		if cp.state.GetState().GetTerminated() == nil {
			t.Fatal("container has no terminated state after the bounded drain")
		}
	})

	// capture despite request-ctx cancel: under the M2 daemon split the CreatePod
	// ctx is canceled when the unary handler returns. The output must still reach
	// the log file, proving watchContainerExit + the reaper run on the detached
	// pod-lifetime ctx, not the request ctx.
	t.Run("capture-despite-request-ctx-cancel", func(t *testing.T) {
		const lastLine = "fatal: detached-supervision diagnostic"
		w := newBlockingWaiter()
		w.code = 1
		rt := newTestRuntime(t, Deps{
			Spawner: pipeSpawner{payload: "boot\nserve\n" + lastLine},
			Waiter:  w,
		})
		box := hostBinBox(rt, "pod-detach")

		ctx, cancel := context.WithCancel(context.Background())
		resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}

		cancel()        // the unary RPC returns → request ctx is canceled
		w.release(4242) // pipeSpawner's pid: now the container exits

		if reason := waitTerminatedReason(t, rt, "pod-detach", 3*time.Second); reason != "Error" {
			t.Fatalf("terminated reason = %q, want Error (a canceled request ctx must not corrupt the exit)", reason)
		}
		lines := readCRILog(t, filepath.Join(box.GetLogDirectory(), "main", "0.log"))
		if len(lines) == 0 || lines[len(lines)-1].payload != lastLine {
			t.Errorf("the log file holds %v, want it to end with %q despite request-ctx cancel (detach failed)",
				lines, lastLine)
		}
	})
}
