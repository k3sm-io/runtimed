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

package guestinit

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// consoleHandler writes the reaper's log into the SAME ordered record the fake
// Proc appends its syscalls to.
//
// That shared record is the whole point: the property under test is not "the
// reason was logged" and not "the machine powered off" — both were already true —
// but that the first happened BEFORE the second. Two separate observers cannot
// express that; one interleaved log can.
type consoleHandler struct {
	proc *fakeProc
	slog.Handler
}

func (h *consoleHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *consoleHandler) Handle(_ context.Context, rec slog.Record) error {
	h.proc.mu.Lock()
	h.proc.log = append(h.proc.log, "log:"+rec.Message)
	h.proc.mu.Unlock()
	return nil
}

func (h *consoleHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *consoleHandler) WithGroup(string) slog.Handler      { return h }

// consoleReaper builds a reaper whose log and whose Proc calls land in one
// ordered record.
func consoleReaper(t *testing.T) (*Reaper, *fakeProc) {
	t.Helper()
	proc := newFakeProc()
	return NewReaper(proc, nil, ReaperOptions{Logger: slog.New(&consoleHandler{proc: proc})}), proc
}

// indexOf returns the position of the first record entry with the given prefix,
// or -1.
func indexOf(record []string, prefix string) int {
	for i, e := range record {
		if strings.HasPrefix(e, prefix) {
			return i
		}
	}
	return -1
}

// TestFatalReasonReachesTheConsoleBeforePoweroff is the gate on a diagnosability
// defect that cost real debugging time: nats:2.10-alpine would not start, and the
// ENTIRE guest console was
//
//	level=INFO msg="stopping the guest" containers=0 grace=30s
//	level=INFO msg="powering off the guest"
//
// with no "guest init failed" line anywhere. Every fatal path in the guest's
// run() returned errors.Join(err, reaper.Stop(...)); Go evaluates that Join —
// Stop, and its deferred Poweroff — before the caller sees the error, so the
// machine was already gone by the time main() logged the reason. What an operator
// was left with read as "the pod had no containers", the exact wrong diagnosis.
//
// The contract is stated on Reaper.Fail: no fatal guest-init path may power off
// without having written its reason to the console first.
func TestFatalReasonReachesTheConsoleBeforePoweroff(t *testing.T) {
	t.Run("the-reason-is-written-before-poweroff", func(t *testing.T) {
		r, proc := consoleReaper(t)
		reason := errors.New("start container nats: no executable for argv[0]")

		if err := r.Fail(context.Background(), 0, reason); !errors.Is(err, reason) {
			t.Errorf("Fail returned %v; it must still carry the reason for a caller that outlives the poweroff", err)
		}

		proc.mu.Lock()
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()

		failed := indexOf(record, "log:guest init failed")
		off := indexOf(record, "poweroff")
		switch {
		case failed < 0:
			t.Fatalf("the reason was never written to the console: %v", record)
		case off < 0:
			t.Fatalf("the machine never powered off: %v", record)
		case failed > off:
			t.Fatalf("the reason was written AFTER the poweroff (%v); the machine is gone by then and the console line is never read", record)
		}
	})

	t.Run("the-reason-precedes-the-whole-shutdown-not-just-the-poweroff", func(t *testing.T) {
		// An operator should not have to wait out a 30s grace budget to learn why
		// the guest is dying, so the reason is emitted before the signalling too.
		r, proc := consoleReaper(t)
		proc.spawn(11)
		r.Track("app", 11)

		reason := errors.New("serve the guest agent: vsock listen failed")
		_ = r.Fail(context.Background(), 0, reason)

		proc.mu.Lock()
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()

		failed := indexOf(record, "log:guest init failed")
		term := indexOf(record, "term:")
		off := indexOf(record, "poweroff")
		if failed < 0 || off < 0 {
			t.Fatalf("record = %v, want both a reason and a poweroff", record)
		}
		if term >= 0 && failed > term {
			t.Errorf("record = %v; the reason must precede the shutdown signalling, not trail it", record)
		}
		if failed > off {
			t.Errorf("record = %v; the reason must precede the poweroff", record)
		}
	})

	t.Run("a-clean-stop-reports-no-failure", func(t *testing.T) {
		// The signal-driven shutdown is not a fatal path and must not claim to be
		// one: a guest that stopped because the host asked it to would otherwise
		// look like a guest that crashed.
		r, proc := consoleReaper(t)
		if err := r.Stop(context.Background(), 0); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		proc.mu.Lock()
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()
		if i := indexOf(record, "log:guest init failed"); i >= 0 {
			t.Errorf("a clean stop logged a failure: %v", record)
		}
		if indexOf(record, "poweroff") < 0 {
			t.Errorf("a clean stop did not power off: %v", record)
		}
	})

	t.Run("the-first-reason-wins-and-stop-still-runs-once", func(t *testing.T) {
		// Stop is once-only by contract; Fail must not give a second caller a way
		// to overwrite the first, more specific reason or to race a second
		// poweroff.
		r, proc := consoleReaper(t)
		first := errors.New("first cause")
		second := errors.New("second cause")
		_ = r.Fail(context.Background(), 0, first)
		if err := r.Fail(context.Background(), 0, second); errors.Is(err, second) && !errors.Is(err, first) {
			t.Errorf("the second reason replaced the first: %v", err)
		}
		proc.mu.Lock()
		offs := proc.poweroffs
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()
		if offs != 1 {
			t.Errorf("poweroffs = %d, want exactly 1", offs)
		}
		if n := strings.Count(strings.Join(record, "\n"), "log:guest init failed"); n != 1 {
			t.Errorf("the reason was logged %d times, want once: %v", n, record)
		}
	})

	t.Run("a-nil-reason-is-not-a-failure", func(t *testing.T) {
		r, proc := consoleReaper(t)
		if err := r.Fail(context.Background(), 0, nil); err != nil {
			t.Errorf("Fail(nil) = %v, want nil", err)
		}
		proc.mu.Lock()
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()
		if i := indexOf(record, "log:guest init failed"); i >= 0 {
			t.Errorf("Fail(nil) logged a failure: %v", record)
		}
	})

	t.Run("a-grace-budget-does-not-delay-the-reason", func(t *testing.T) {
		// Belt on the ordering under the one path that blocks: a live container
		// plus a real grace budget. The reason must already be on the console when
		// the wait begins.
		r, proc := consoleReaper(t)
		proc.spawn(11)
		r.Track("app", 11)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Fail(ctx, 10*time.Millisecond, errors.New("boom"))
		proc.mu.Lock()
		record := append([]string(nil), proc.log...)
		proc.mu.Unlock()
		if indexOf(record, "log:guest init failed") != 0 {
			t.Errorf("record = %v; the reason must be the FIRST thing the shutdown emits", record)
		}
	})
}
