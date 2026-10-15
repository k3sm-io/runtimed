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
	"reflect"
	"sync"
	"testing"
	"time"
)

// TestStopContainer pins the per-container half of the stop sequence the
// in-guest container restart is built on: it stops ONE container with the same
// TERM -> grace -> KILL steps the shutdown uses, it never powers the machine
// off, and it returns only once the instance's exit callback has run.
func TestStopContainer(t *testing.T) {
	t.Run("terms-only-the-named-container-and-never-powers-off", func(t *testing.T) {
		f := newFakeProc()
		rec := newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})
		for pid, name := range map[int]string{10: "app", 11: "sidecar"} {
			f.spawn(pid)
			r.Track(name, pid)
		}

		done := make(chan error, 1)
		go func() { done <- r.StopContainer(context.Background(), "app", time.Hour) }()
		if pid := <-f.termed; pid != 10 {
			t.Fatalf("SIGTERM went to pid %d, want the named container's pid 10", pid)
		}
		f.exit(10, WaitStatus{Signal: int(SignalTerm)})
		if err := <-done; err != nil {
			t.Fatalf("StopContainer: %v", err)
		}
		if got := f.snapshotLog(); !reflect.DeepEqual(got, []string{"term:10"}) {
			t.Errorf("signal log = %v, want only term:10 (no kill, no other container, no poweroff)", got)
		}
		if n := f.poweroffCount(); n != 0 {
			t.Errorf("poweroffs = %d, want 0: a container stop is not a guest stop", n)
		}
		if evs := rec.snapshot(); len(evs) != 1 || evs[0].Container != "app" {
			t.Errorf("exit events = %+v, want exactly app's", evs)
		}
	})

	t.Run("kills-after-the-grace-budget-is-spent", func(t *testing.T) {
		f := newFakeProc()
		timerCh := make(chan time.Time)
		r := startReaper(t, f, ReaperOptions{
			NewTimer: func(time.Duration) (<-chan time.Time, func() bool) { return timerCh, func() bool { return true } },
		})
		f.spawn(10)
		r.Track("app", 10)

		done := make(chan error, 1)
		go func() { done <- r.StopContainer(context.Background(), "app", time.Hour) }()
		<-f.termed
		f.mark("grace-expired")
		timerCh <- time.Now()
		if pid := <-f.killed; pid != 10 {
			t.Fatalf("SIGKILL went to pid %d, want 10", pid)
		}
		f.exit(10, WaitStatus{Signal: int(SignalKill)})
		if err := <-done; err != nil {
			t.Fatalf("StopContainer: %v", err)
		}
		if got, want := f.snapshotLog(), []string{"term:10", "grace-expired", "kill:10"}; !reflect.DeepEqual(got, want) {
			t.Errorf("signal log = %v, want %v (no SIGKILL before the budget is spent)", got, want)
		}
	})

	t.Run("returns-only-after-the-exit-callback-ran", func(t *testing.T) {
		// The restart spawns the replacement right after this returns, and the
		// predecessor's callback releases the container's retained stdio. Were
		// the callback still running, it would release the replacement's.
		f := newFakeProc()
		var mu sync.Mutex
		callbackDone := false
		release := make(chan struct{})
		r := startReaper(t, f, ReaperOptions{OnExit: func(ExitEvent) {
			<-release
			mu.Lock()
			callbackDone = true
			mu.Unlock()
		}})
		f.spawn(10)
		r.Track("app", 10)

		done := make(chan error, 1)
		go func() { done <- r.StopContainer(context.Background(), "app", time.Hour) }()
		<-f.termed
		f.exit(10, WaitStatus{ExitCode: 0})
		select {
		case err := <-done:
			t.Fatalf("StopContainer returned (%v) while the exit callback was still running", err)
		case <-time.After(50 * time.Millisecond):
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatalf("StopContainer: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if !callbackDone {
			t.Error("StopContainer returned before the exit callback completed")
		}
	})

	t.Run("an-already-exited-container-returns-at-once", func(t *testing.T) {
		f := newFakeProc()
		rec := newRecorder()
		r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})
		f.spawn(10)
		r.Track("app", 10)
		f.exit(10, WaitStatus{ExitCode: 3})
		rec.waitEvents(t, 1)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.StopContainer(ctx, "app", time.Hour); err != nil {
			t.Fatalf("StopContainer: %v", err)
		}
		if got := f.snapshotLog(); len(got) != 0 {
			t.Errorf("signal log = %v, want nothing: there was no process to signal", got)
		}
	})

	t.Run("refused-once-the-guest-is-stopping", func(t *testing.T) {
		f := newFakeProc()
		r := startReaper(t, f, ReaperOptions{})
		if err := r.Stop(context.Background(), 0); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		if err := r.StopContainer(context.Background(), "app", time.Second); !errors.Is(err, ErrStopped) {
			t.Errorf("StopContainer after Stop = %v, want ErrStopped", err)
		}
	})
}

// TestTrackSupersedesTheRecordedExit pins that a restarted container's Wait is
// about the NEW instance: the predecessor's recorded exit is dropped when the
// replacement is tracked, so the waiter blocks until the new one exits.
func TestTrackSupersedesTheRecordedExit(t *testing.T) {
	f := newFakeProc()
	rec := newRecorder()
	r := startReaper(t, f, ReaperOptions{OnExit: rec.onExit})
	f.spawn(10)
	r.Track("app", 10)
	f.exit(10, WaitStatus{ExitCode: 1})
	rec.waitEvents(t, 1)

	f.spawn(20)
	r.Track("app", 20)
	got := make(chan WaitStatus, 1)
	go func() {
		st, err := r.Wait(context.Background(), "app")
		if err != nil {
			t.Errorf("Wait: %v", err)
		}
		got <- st
	}()
	select {
	case st := <-got:
		t.Fatalf("Wait returned %+v for a running replacement; it read the predecessor's exit", st)
	case <-time.After(50 * time.Millisecond):
	}
	f.exit(20, WaitStatus{ExitCode: 7})
	if st := <-got; st.ExitCode != 7 {
		t.Errorf("Wait = %+v, want the replacement's exit code 7", st)
	}
}
