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
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// errWaitWedge is a canned ExitWaiter error used to drive watchContainerExit's
// wait-error branch (which sets term.Message itself).
var errWaitWedge = errors.New("supervisor wait failed")

// pipeSpawner drives the REAL supervisor.Process log pipe: it writes payload to the
// child's combined-output fd (spec.LogFD) and closes it, simulating a container that
// emitted its final output and then exited. It is how the FallbackToLogsOnError tests
// push bytes THROUGH the pump (not a pre-populated buffer), so the pump-vs-reaper
// drain ordering is exercised end-to-end. payload stays well under the OS pipe buffer
// so the synchronous write in Spawn (before the pump goroutine starts) never blocks.
type pipeSpawner struct{ payload string }

func (s pipeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if spec.LogFD != 0 && s.payload != "" {
		w := os.NewFile(spec.LogFD, "logfd")
		_, _ = w.WriteString(s.payload)
		_ = w.Close()
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

// startTermProc builds and Starts a real supervisor.Process whose pipe is fed by a
// pipeSpawner(payload) and reaped by w, returning the containerProc that wraps it.
// decorate (optional) wraps the log sink so a test can gate the pump's delivery
// timing; nil writes straight into the container's logBuffer.
func startTermProc(t *testing.T, name, payload string, w supervisor.ExitWaiter, decorate func(supervisor.LogSink) supervisor.LogSink) *containerProc {
	t.Helper()
	return startTermProcSpawner(t, name, pipeSpawner{payload: payload}, w, decorate)
}

// startTermProcSpawner is startTermProc over an arbitrary supervisor.Spawner, so a
// test can drive a pipe whose write-end is held open past the child's exit (the
// leaked-grandchild case) instead of the EOF-on-exit pipeSpawner.
func startTermProcSpawner(t *testing.T, name string, spawner supervisor.Spawner, w supervisor.ExitWaiter, decorate func(supervisor.LogSink) supervisor.LogSink) *containerProc {
	t.Helper()
	logs := newLogBuffer(nil)
	var sink supervisor.LogSink = logs.write
	if decorate != nil {
		sink = decorate(logs.write)
	}
	proc := supervisor.NewProcess(spawner, w,
		supervisor.SpawnSpec{Path: "/term-test", Argv: []string{"/term-test"}}, sink)
	if err := proc.Start(context.Background()); err != nil {
		t.Fatalf("start %s process: %v", name, err)
	}
	return &containerProc{
		name: name,
		logs: logs,
		proc: proc,
		state: &runtimev1.ContainerStatus{
			Name:  name,
			Image: "/term-test",
			State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()}},
		},
	}
}

// heldWriteEnd is a supervisor.Spawner that writes payload to the child's combined
// stdout+stderr fd and then DUPS that write-end into an independent descriptor it
// holds open — modeling a forked grandchild that inherits and retains the pipe after
// the direct child exits. Because a write-end stays open, the supervisor pump never
// reaches EOF and LogsDrained never closes, so watchContainerExit can only finalize
// via its bounded drainGrace timeout. release() closes the held fd (test cleanup) so
// the pump goroutine can finally drain and exit.
type heldWriteEnd struct {
	payload string

	mu   sync.Mutex
	held *os.File
}

func (s *heldWriteEnd) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	if spec.LogFD == 0 {
		return 4242, nil
	}
	// Dup the inherited write-end into a fd of our own (independent of the parent's
	// logW, which Start closes right after Spawn returns) and keep it open.
	dupFD, err := unix.Dup(int(spec.LogFD))
	if err != nil {
		return 0, fmt.Errorf("dup logfd: %w", err)
	}
	held := os.NewFile(uintptr(dupFD), "held-logfd")
	if s.payload != "" {
		if _, err := held.WriteString(s.payload); err != nil {
			_ = held.Close()
			return 0, fmt.Errorf("write held logfd: %w", err)
		}
	}
	s.mu.Lock()
	s.held = held
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

// TestTerminationMessageFallbackToLogs is the B11 gate: a FAILED container with no
// termination message gets one synthesized from the tail of its combined log
// (terminationMessagePolicy=FallbackToLogsOnError, which runtimed applies
// unconditionally — see watchContainerExit). It asserts the conformance-load-bearing
// negatives too: exit-0 stays empty, an already-set wait-error message is never
// clobbered, and term.Reason is preserved (OOMKilled). The byte/line caps and the
// real pump-vs-reaper drain ordering are exercised in dedicated subtests.
func TestTerminationMessageFallbackToLogs(t *testing.T) {
	const lastLine = "panic: runtime error: index out of range [9] with length 3"
	failLog := "booting service\nhandling request\n" + lastLine // last token returned at EOF (no trailing \n)

	cases := []struct {
		name       string
		payload    string
		waiter     supervisor.ExitWaiter
		oomKilled  bool
		wantReason string
		check      func(t *testing.T, term *runtimev1.ContainerStateTerminated)
	}{
		{
			// Happy path: a non-zero exit with an empty message falls back to the log tail.
			name:       "failure-empty-falls-back-to-log-tail",
			payload:    failLog,
			waiter:     cannedWaiter{code: 1},
			wantReason: "Error",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if !strings.Contains(term.GetMessage(), lastLine) {
					t.Errorf("message = %q, want it to contain the final log line %q", term.GetMessage(), lastLine)
				}
			},
		},
		{
			// Negative (conformance-load-bearing): exit-0 (Completed) gets NO fallback —
			// upstream [NodeConformance] asserts a successful container has an empty
			// termination message, even though the log here is non-empty.
			name:       "success-exit-0-no-fallback",
			payload:    "all good\nstill good\ndone",
			waiter:     cannedWaiter{code: 0},
			wantReason: "Completed",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != "" {
					t.Errorf("exit-0 message = %q, want empty (success has no termination message)", term.GetMessage())
				}
			},
		},
		{
			// Negative: a message already set on the wait-error path is not clobbered.
			name:       "wait-error-message-not-clobbered",
			payload:    "noise\nmore noise\neven more noise",
			waiter:     cannedWaiter{code: 1, err: errWaitWedge},
			wantReason: "Error",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if term.GetMessage() != errWaitWedge.Error() {
					t.Errorf("message = %q, want the preserved wait error %q (must not clobber)", term.GetMessage(), errWaitWedge.Error())
				}
			},
		},
		{
			// Signal-kill (OOMKilled, sig 9 / code 137) with an empty message falls back,
			// AND term.Reason stays "OOMKilled" (the M2.5 OOM test depends on it).
			name:       "oomkill-signal-empty-falls-back-reason-preserved",
			payload:    "allocating\nallocating more\n" + lastLine,
			waiter:     cannedWaiter{code: 137, sig: 9},
			oomKilled:  true,
			wantReason: "OOMKilled",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				if !strings.Contains(term.GetMessage(), lastLine) {
					t.Errorf("OOMKilled message = %q, want it to contain the final log line %q", term.GetMessage(), lastLine)
				}
			},
		},
		{
			// Cap: a container emitting >80 lines / >2048 bytes is truncated to the LAST
			// 80 lines AND last 2048 bytes (tail-biased): the LAST line survives, the
			// FIRST does not.
			name:       "cap-80-lines-2048-bytes-tail-biased",
			payload:    capPayload(),
			waiter:     cannedWaiter{code: 2},
			wantReason: "Error",
			check: func(t *testing.T, term *runtimev1.ContainerStateTerminated) {
				msg := term.GetMessage()
				if len(msg) > maxTerminationMessageLogBytes {
					t.Errorf("message is %d bytes, want <= %d", len(msg), maxTerminationMessageLogBytes)
				}
				if lines := strings.Count(msg, "\n") + 1; lines > maxTerminationMessageLogLines {
					t.Errorf("message has %d lines, want <= %d", lines, maxTerminationMessageLogLines)
				}
				if !strings.Contains(msg, capLastLine) {
					t.Errorf("message must contain the LAST log line %q (tail-biased):\n%s", capLastLine, msg)
				}
				if strings.Contains(msg, capFirstLine) {
					t.Errorf("message must NOT contain the FIRST log line %q (tail-biased)", capFirstLine)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{})
			cp := startTermProc(t, "main", tc.payload, tc.waiter, nil)
			p := &pod{box: hostBinBox(rt, "pod-term"), oomKilled: tc.oomKilled, containers: []*containerProc{cp}}

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

	// race-faithful: drive the REAL pipe and make the pump-vs-reaper drain ordering
	// load-bearing. The pump's FIRST sink delivery is gated (sleeps) so that when the
	// reaper unblocks Wait, the final line is provably NOT yet in the buffer — only the
	// drain-wait in watchContainerExit makes it land. A snapshot taken straight after
	// Wait (the pre-fix behavior) would see an empty buffer. Run under -race, this also
	// exercises the concurrent pump-write vs. snapshot-read on the logBuffer.
	t.Run("race-faithful-real-pipe-drains-before-snapshot", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		const last = "fatal error: concurrent map writes"
		payload := "starting\nworking\n" + last

		gate := func(orig supervisor.LogSink) supervisor.LogSink {
			var once sync.Once
			return func(line []byte) {
				once.Do(func() { time.Sleep(50 * time.Millisecond) })
				orig(line)
			}
		}
		cp := startTermProc(t, "main", payload, cannedWaiter{code: 2}, gate)
		p := &pod{box: hostBinBox(rt, "pod-term-race"), containers: []*containerProc{cp}}

		rt.watchContainerExit(context.Background(), p, cp, nil)

		term := cp.state.GetState().GetTerminated()
		if term == nil {
			t.Fatal("container has no terminated state")
		}
		if !strings.Contains(term.GetMessage(), last) {
			t.Fatalf("final log line lost to the pump/reaper race.\n got: %q\nwant contains: %q\n"+
				"(the drain-wait before snapshot is what makes the last line land)", term.GetMessage(), last)
		}
	})

	// held-open pipe → bounded snapshot, NO hang: a forked grandchild holds the
	// stdout/stderr write-end open after the direct child exits, so the supervisor
	// pump never reaches EOF and LogsDrained never closes. watchContainerExit MUST
	// still finalize the terminated status within ~drainGrace (snapshotting whatever
	// tail is buffered), never wedge the pod in Running forever. Run under -race.
	t.Run("held-open-pipe-bounded-snapshot-no-hang", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{})
		rt.drainGrace = 60 * time.Millisecond // small + real so the timeout arm is fast

		const lastLine = "panic: held-pipe diagnostic"
		// Every line (incl. the diagnostic) is newline-terminated so the pump delivers
		// it to the buffer before blocking on the never-closing pipe — the missing EOF
		// is what keeps LogsDrained from closing, not a missing final line.
		held := &heldWriteEnd{payload: "starting\nworking\n" + lastLine + "\n"}
		t.Cleanup(held.release) // let the pipe finally EOF so the pump goroutine exits

		cp := startTermProcSpawner(t, "main", held, cannedWaiter{code: 2}, nil)
		p := &pod{box: hostBinBox(rt, "pod-held"), containers: []*containerProc{cp}}

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

		term := cp.state.GetState().GetTerminated()
		if term == nil {
			t.Fatal("container has no terminated state after the bounded drain")
		}
		if !strings.Contains(term.GetMessage(), lastLine) {
			t.Errorf("message = %q, want the buffered tail %q (partial snapshot on the drain timeout)", term.GetMessage(), lastLine)
		}
	})

	// capture despite request-ctx cancel: under the M2 daemon split the CreatePod ctx
	// is canceled when the unary handler returns. The fallback must STILL capture the
	// log tail, proving watchContainerExit + the reaper run on the detached pod-lifetime
	// ctx, not the request ctx. Pre-detach this is a silent no-op: canceling makes the
	// reaper record a bogus context-canceled exit and the drain-wait snapshot nothing.
	t.Run("capture-despite-request-ctx-cancel", func(t *testing.T) {
		const lastLine = "fatal: detached-supervision diagnostic"
		w := newBlockingWaiter()
		w.code = 1 // a failing container → the fallback fires
		rt := newTestRuntime(t, Deps{
			Spawner: pipeSpawner{payload: "boot\nserve\n" + lastLine},
			Waiter:  w,
		})

		ctx, cancel := context.WithCancel(context.Background())
		resp, err := rt.CreatePod(ctx, &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-detach")})
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
		gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-detach"})
		msg := gs.GetStatus().GetContainerStatuses()[0].GetState().GetTerminated().GetMessage()
		if !strings.Contains(msg, lastLine) {
			t.Errorf("message = %q, want the captured tail %q despite request-ctx cancel (detach failed)", msg, lastLine)
		}
	})

	// UTF-8 boundary: the 2048-byte tail cut must round UP to a rune boundary so
	// term.Message is valid UTF-8 (a sliced multi-byte rune would corrupt it), while
	// still honoring the byte cap.
	t.Run("utf8-tail-cut-rounds-to-rune-boundary", func(t *testing.T) {
		logs := newLogBuffer(nil)
		// One line of 3-byte runes longer than the byte cap, so the last-2048-byte cut
		// lands INSIDE a rune (2048 % 3 != 0): the naive slice would start on a UTF-8
		// continuation byte.
		logs.write([]byte(strings.Repeat("世", 1000))) // 3000 bytes > 2048
		msg := terminationMessageFromLogs(logs)
		if len(msg) > maxTerminationMessageLogBytes {
			t.Errorf("len(msg) = %d, want <= %d (byte cap must hold)", len(msg), maxTerminationMessageLogBytes)
		}
		if !utf8.ValidString(msg) {
			t.Errorf("message is not valid UTF-8 after the tail cut (rune sliced)")
		}
		if !strings.HasSuffix(msg, "世") {
			t.Error("message lost its tail end (the cut should trim only the leading partial rune)")
		}
	})
}

// capPayload renders 120 distinct log lines (> the 80-line cap, and > 2048 bytes once
// joined) so both the line cap and the byte cap engage; capFirstLine / capLastLine are
// the first and last lines, for the tail-biased truncation assertions.
const (
	capFirstLine = "L000-padding-padding-padding"
	capLastLine  = "L119-padding-padding-padding"
)

func capPayload() string {
	var b strings.Builder
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "L%03d-padding-padding-padding\n", i)
	}
	return b.String()
}
