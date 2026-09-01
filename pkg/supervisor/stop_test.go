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

package supervisor

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// recordingSignaller records the signals sent to process groups, in order.
type recordingSignaller struct {
	mu   sync.Mutex
	sent []os.Signal
}

func (r *recordingSignaller) signal(_ int, sig os.Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sig)
	return nil
}

func (r *recordingSignaller) signals() []os.Signal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]os.Signal, len(r.sent))
	copy(out, r.sent)
	return out
}

// TestGracefulStop covers the M2.4 SIGTERM → grace → SIGKILL escalation raced
// against the reaper. The two signal values are arbitrary os.Signal sentinels
// (GracefulStop forwards them verbatim); os.Interrupt/os.Kill keep it portable.
func TestGracefulStop(t *testing.T) {
	const pgid = 4242
	term, kill := os.Interrupt, os.Kill

	t.Run("grace-zero-immediate-sigkill", func(t *testing.T) {
		rec := &recordingSignaller{}
		exited := make(chan struct{}) // never closes
		esc, _, err := GracefulStop(context.Background(), pgid, 0, exited, term, kill, rec.signal, testExitWait)
		if err != nil {
			t.Fatal(err)
		}
		if !esc {
			t.Error("grace 0 should escalate (immediate kill)")
		}
		if got := rec.signals(); len(got) != 1 || got[0] != kill {
			t.Errorf("grace 0 signals = %v, want [SIGKILL] only", got)
		}
	})

	t.Run("sigterm-then-voluntary-exit-no-sigkill", func(t *testing.T) {
		rec := &recordingSignaller{}
		exited := make(chan struct{})
		close(exited) // the reaper already observed the exit
		// A long grace: if the timer were not raced against exited this would block
		// for 10s; a prompt return proves the timer was stopped on early exit.
		done := make(chan struct{})
		var esc bool
		var err error
		go func() {
			esc, _, err = GracefulStop(context.Background(), pgid, 10*time.Second, exited, term, kill, rec.signal, testExitWait)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("GracefulStop blocked on the timer despite an early exit (timer not stopped)")
		}
		if err != nil {
			t.Fatal(err)
		}
		if esc {
			t.Error("a voluntary exit within grace must NOT escalate to SIGKILL")
		}
		if got := rec.signals(); len(got) != 1 || got[0] != term {
			t.Errorf("signals = %v, want [SIGTERM] only (reaper collected the exit)", got)
		}
	})

	t.Run("sigterm-then-deadline-sigkill", func(t *testing.T) {
		rec := &recordingSignaller{}
		exited := make(chan struct{}) // never closes — the pod ignores SIGTERM
		esc, _, err := GracefulStop(context.Background(), pgid, 15*time.Millisecond, exited, term, kill, rec.signal, testExitWait)
		if err != nil {
			t.Fatal(err)
		}
		if !esc {
			t.Error("a deadline expiry must escalate to SIGKILL")
		}
		if got := rec.signals(); len(got) != 2 || got[0] != term || got[1] != kill {
			t.Errorf("signals = %v, want [SIGTERM, SIGKILL]", got)
		}
	})

	t.Run("ctx-cancel-escalates", func(t *testing.T) {
		rec := &recordingSignaller{}
		exited := make(chan struct{}) // never closes
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		esc, _, err := GracefulStop(ctx, pgid, 10*time.Second, exited, term, kill, rec.signal, testExitWait)
		if err != nil {
			t.Fatal(err)
		}
		if !esc {
			t.Error("ctx cancellation should escalate to SIGKILL (no half-stopped pod)")
		}
		if got := rec.signals(); len(got) != 2 || got[1] != kill {
			t.Errorf("signals = %v, want [SIGTERM, SIGKILL]", got)
		}
	})
}

// testExitWait is the post-kill exit-observation bound the tests above pass:
// small and real, so a subtest whose fake never reports an exit finishes in
// milliseconds instead of DefaultExitObservationGrace.
const testExitWait = 30 * time.Millisecond

// gatedWaiter is a controllable ExitWaiter: WaitExit announces that the reaper
// has entered the wait (entered), then withholds the exit until the test
// releases it — or reports ctx.Err() if the supervision context is cancelled
// first, exactly as KqueueReaper.WaitExit does at its poll-loop ctx check. That
// second arm is what makes the teardown race constructible: it is the path a
// premature p.cancel() takes the process down, replacing a real SIGKILL status
// with "context canceled".
type gatedWaiter struct {
	code, sig int
	entered   chan struct{}
	released  chan struct{}
	once      sync.Once
}

func newGatedWaiter(code, sig int) *gatedWaiter {
	return &gatedWaiter{
		code:     code,
		sig:      sig,
		entered:  make(chan struct{}),
		released: make(chan struct{}),
	}
}

func (w *gatedWaiter) WaitExit(ctx context.Context, _ int) (int, int, error) {
	close(w.entered)
	select {
	case <-w.released:
		return w.code, w.sig, nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

// release delivers the withheld exit (idempotent, so a test can release from a
// signal hook and again in cleanup).
func (w *gatedWaiter) release() { w.once.Do(func() { close(w.released) }) }

// TestGracefulStopAwaitsReaperObservation pins B40's teardown race: every path
// that sends SIGKILL must WAIT for the reaper's exit observation (bounded)
// before returning, because the caller cancels the pod-lifetime supervision
// context the instant it returns.
//
// The interleaving is CONSTRUCTED, never raced for: the exit is withheld by a
// controllable fake past the point the pre-B40 code returned. A gate that
// SIGKILLs a real process cannot bite here — the window between "kill sent" and
// "reaper observed" is microseconds, so a real process almost never occupies it
// and the test would pass by luck against the unfixed code.
func TestGracefulStopAwaitsReaperObservation(t *testing.T) {
	const pgid = 4242
	term, kill := os.Interrupt, os.Kill

	// stillBlocked reports whether done has not fired within a short settle
	// window. The window only has to be long enough for the UNFIXED code — which
	// returns immediately after signalling — to land; the fixed code stays
	// blocked for as long as the fake withholds the exit, so a longer window
	// makes the assertion stronger, never flakier.
	stillBlocked := func(t *testing.T, done <-chan struct{}) bool {
		t.Helper()
		select {
		case <-done:
			return false
		case <-time.After(100 * time.Millisecond):
			return true
		}
	}

	// The three escalation arms, each of which sends killSig and must then wait.
	arms := []struct {
		name  string
		ctx   func() context.Context
		grace time.Duration
	}{
		{"grace-zero-immediate-kill", context.Background, 0},
		{"grace-deadline-escalation", context.Background, 10 * time.Millisecond},
		{"ctx-cancel-escalation", func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, 10 * time.Second},
	}
	for _, arm := range arms {
		t.Run(arm.name+"-blocks-until-observed", func(t *testing.T) {
			rec := &recordingSignaller{}
			exited := make(chan struct{}) // the reaper has NOT observed the exit yet
			done := make(chan struct{})
			var esc, obs bool
			var err error
			go func() {
				esc, obs, err = GracefulStop(arm.ctx(), pgid, arm.grace, exited, term, kill, rec.signal, 5*time.Second)
				close(done)
			}()
			if !stillBlocked(t, done) {
				t.Fatal("GracefulStop returned before the reaper observed the exit: the caller's p.cancel() can now preempt the reaper and record a bogus context-canceled termination")
			}
			if got := rec.signals(); len(got) == 0 || got[len(got)-1] != kill {
				t.Errorf("signals = %v, want SIGKILL sent before the wait", got)
			}
			close(exited) // the reaper recorded the final status
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("GracefulStop did not return after the exit was observed")
			}
			if err != nil {
				t.Fatal(err)
			}
			if !esc {
				t.Error("escalated = false, want true (killSig was sent)")
			}
			if !obs {
				t.Error("observed = false, want true (the exit was reported before the bound)")
			}
		})
	}

	t.Run("observation-timeout-returns-and-is-distinguishable", func(t *testing.T) {
		rec := &recordingSignaller{}
		exited := make(chan struct{}) // never closes: the process refuses to die
		done := make(chan struct{})
		var esc, obs bool
		var err error
		start := time.Now()
		go func() {
			esc, obs, err = GracefulStop(context.Background(), pgid, 0, exited, term, kill, rec.signal, 40*time.Millisecond)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("GracefulStop hung on an exit that never arrives: teardown must be bounded")
		}
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
			t.Errorf("returned after %v, want >= the 40ms observation bound", elapsed)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !esc {
			t.Error("escalated = false, want true (killSig was sent)")
		}
		if obs {
			t.Error("observed = true on the timeout path: the caller cannot tell an unobserved teardown from a clean one")
		}
	})

	t.Run("signal-error-does-not-wait", func(t *testing.T) {
		// A failed kill has nothing to observe; blocking for the bound would add
		// the full timeout to every teardown of an unsignalable group.
		exited := make(chan struct{})
		done := make(chan struct{})
		var obs bool
		var err error
		go func() {
			_, obs, err = GracefulStop(context.Background(), pgid, 0, exited, term, kill,
				func(int, os.Signal) error { return errors.New("no such process group") }, 10*time.Second)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("GracefulStop waited for an observation after the kill itself failed")
		}
		if err == nil {
			t.Error("err = nil, want the signal error")
		}
		if obs {
			t.Error("observed = true after a failed kill")
		}
	})

	// The reason the wait exists: the terminated status the reaper records must
	// report the SIGKILL the daemon actually sent, not the pod-lifetime cancel
	// the teardown fires on the very next line.
	t.Run("terminated-status-reports-the-kill-not-the-cancel", func(t *testing.T) {
		w := newGatedWaiter(137, 9) // 128+SIGKILL, signal 9 — a real kill status
		t.Cleanup(w.release)
		proc := NewProcess(&fakeSpawner{pid: pgid}, w,
			SpawnSpec{Path: "/bin/sleep", Argv: []string{"/bin/sleep", "600"}}, nil)

		// podCtx is the pod-lifetime supervision context (pkg/runtime's p.supCtx):
		// the reaper runs under it and DeletePod cancels it right after the stop.
		podCtx, podCancel := context.WithCancel(context.Background())
		defer podCancel()
		if err := proc.Start(podCtx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		<-w.entered // the reaper is in WaitExit, as it is for any live container

		// The group dies a short moment after the SIGKILL lands — the ordinary
		// case (signal delivery, then exit, then the reaper's kqueue poll). That
		// delay is the whole window: the unfixed GracefulStop returns inside it.
		signal := func(_ int, sig os.Signal) error {
			if sig == kill {
				go func() {
					time.Sleep(25 * time.Millisecond)
					w.release()
				}()
			}
			return nil
		}

		esc, obs, err := GracefulStop(context.Background(), pgid, 0, proc.Done(), term, kill, signal, 5*time.Second)
		// Mirror pkg/runtime's DeletePod: the pod-lifetime cancel fires as soon as
		// the stop returns.
		podCancel()
		if err != nil {
			t.Fatal(err)
		}
		if !esc || !obs {
			t.Fatalf("escalated=%v observed=%v, want both true", esc, obs)
		}

		code, sig, waitErr := proc.Wait(context.Background())
		if waitErr != nil {
			t.Errorf("terminated with err %v, want none — the pod-lifetime cancel masked a real kill", waitErr)
		}
		if code != 137 || sig != 9 {
			t.Errorf("terminated (code=%d sig=%d), want (137, 9): the container was SIGKILLed, and that is what its status must say", code, sig)
		}
	})
}
