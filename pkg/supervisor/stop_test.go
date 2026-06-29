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
		esc, err := GracefulStop(context.Background(), pgid, 0, exited, term, kill, rec.signal)
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
			esc, err = GracefulStop(context.Background(), pgid, 10*time.Second, exited, term, kill, rec.signal)
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
		esc, err := GracefulStop(context.Background(), pgid, 15*time.Millisecond, exited, term, kill, rec.signal)
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
		esc, err := GracefulStop(ctx, pgid, 10*time.Second, exited, term, kill, rec.signal)
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
