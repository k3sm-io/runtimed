//go:build darwin && cgo

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
	"fmt"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// detachedReapMinPoll and detachedReapMaxPoll bound reapDetached's WNOHANG
	// backoff. The case it exists for is a pid the daemon already SIGKILLed, which
	// dies at its next scheduling opportunity — so the first poll is short enough
	// to collect it almost immediately — while the tail case (a cancellation with
	// no kill behind it) may run for the child's whole remaining life, so the
	// interval grows to something a long-lived orphan can be polled at for hours
	// without cost. Neither bound is a deadline: the loop ends only on the reap.
	detachedReapMinPoll = 5 * time.Millisecond
	detachedReapMaxPoll = 1 * time.Second
)

// KqueueReaper is the production ExitWaiter and the SOLE reaper: it registers an
// EVFILT_PROC/NOTE_EXIT filter for the child pid on a kqueue and blocks until the
// kernel reports the exit, then wait4's the child once to collect status and
// release the zombie. Using kqueue (not os/exec.Cmd.Wait) guarantees a single
// wait4 caller — mixing the two double-reaps and loses the status.
//
// The zero value is usable.
type KqueueReaper struct{}

// WaitExit blocks until pid exits (or ctx is cancelled) and returns its exit
// code and terminating signal (0 if none), reaping the zombie exactly once.
//
// EVERY return path reaps, including the ones that return early. A return before
// the wait4 below — ctx cancellation, or a kqueue/kevent setup failure — would
// otherwise ABANDON a child this daemon spawned: nothing else in the daemon ever
// wait4s a pod pid (kqueue is the sole reaper), so the moment that child dies it
// becomes an OS zombie holding a process-table slot for the life of the daemon.
// The cancellation arm is not hypothetical: it is the ordinary DeletePod
// teardown, where GracefulStop's exit-observation bound expires and pkg/runtime
// cancels the pod-lifetime supervision context for a group it had just
// SIGKILLed. So a return without a reap hands the pid to reapDetached instead.
//
// The handoff changes nothing this call REPORTS. The caller still receives
// ctx.Err() on cancellation, Process.reap still records it as the container's
// exit error, and GracefulStop's observed == false contract — "the reaper did
// not report the exit within the bound, so the status that follows is not
// trustworthy" — reads exactly as documented. Collecting the corpse and
// reporting the death are different jobs; only the first one is now unconditional.
func (KqueueReaper) WaitExit(ctx context.Context, pid int) (int, int, error) {
	// reaped is set only where this call has PROVED the child is collected: a
	// successful wait4, or an ECHILD saying there is nothing left to collect.
	// Every other exit — including a panic — hands off.
	reaped := false
	defer func() {
		if !reaped {
			go reapDetached(pid)
		}
	}()

	kq, err := unix.Kqueue()
	if err != nil {
		return 0, 0, fmt.Errorf("kqueue: %w", err)
	}
	defer unix.Close(kq)

	// Register interest in the child's exit.
	ev := unix.Kevent_t{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		// ESRCH: the child already exited before we registered. Fall through to
		// the wait4 below, which collects the already-pending zombie.
		if !errors.Is(err, unix.ESRCH) {
			return 0, 0, fmt.Errorf("kevent register pid %d: %w", pid, err)
		}
	} else {
		// Block for the exit event with NO timeout. Cancellation is delivered
		// through the same kqueue: an EVFILT_USER event registered here and
		// NOTE_TRIGGERed by a goroutine the moment ctx is done, so the wait is
		// fully event-driven — no poll, no wakeups while nothing happens
		// (this loop used to wake every 250 ms per supervised process to look
		// at ctx.Err(); runtimed#125).
		if err := waitExitOrCancel(ctx, kq, pid); err != nil {
			return 0, 0, err
		}
	}

	// Reap exactly once.
	var ws unix.WaitStatus
	for {
		wpid, err := unix.Wait4(pid, &ws, 0, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ECHILD) {
				// Already reaped elsewhere (should not happen — kqueue is the sole
				// reaper); report unknown status rather than failing the pod op.
				reaped = true
				return 0, 0, nil
			}
			return 0, 0, fmt.Errorf("wait4 pid %d: %w", pid, err)
		}
		if wpid == pid {
			reaped = true
			break
		}
	}

	if ws.Signaled() {
		return 128 + int(ws.Signal()), int(ws.Signal()), nil
	}
	return ws.ExitStatus(), 0, nil
}

// cancelIdent is the EVFILT_USER ident WaitExit registers for its cancellation
// wakeup. Idents are scoped per (kqueue, filter), so any value is free of the
// EVFILT_PROC registration on the same kqueue, whose ident is the pid.
const cancelIdent = 1

// waitExitOrCancel blocks on kq until the child's NOTE_EXIT fires (nil) or ctx is
// done (ctx.Err()). The kqueue carries the EVFILT_PROC registration already;
// this adds an EVFILT_USER event and a goroutine that NOTE_TRIGGERs it on
// ctx.Done().
//
// LIFETIME of the trigger goroutine: it ends when this function returns, for any
// reason, and it is JOINED before the return — so it can never fire a trigger
// into a kqueue the caller has since closed, whose descriptor number the kernel
// may already have handed to something else.
//
// When both events are ready in one kevent return, the exit wins: the child is
// dead, and the real status it will be reaped with is strictly more information
// than the cancellation. That is also the old poll loop's behaviour whenever
// NOTE_EXIT arrived inside a poll window.
func waitExitOrCancel(ctx context.Context, kq int, pid int) error {
	user := unix.Kevent_t{
		Ident:  cancelIdent,
		Filter: unix.EVFILT_USER,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{user}, nil, nil); err != nil {
		return fmt.Errorf("kevent register cancel wakeup for pid %d: %w", pid, err)
	}

	stop := make(chan struct{})
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		select {
		case <-ctx.Done():
		case <-stop:
			return
		}
		trigger := unix.Kevent_t{
			Ident:  cancelIdent,
			Filter: unix.EVFILT_USER,
			Fflags: unix.NOTE_TRIGGER,
		}
		// A failure here is not reported: the only consequence would be the
		// caller not waking on cancellation, and there is nobody to tell — the
		// caller is the one blocked. It cannot happen on a kqueue that is still
		// open with the ident registered above, which the join below guarantees.
		_, _ = unix.Kevent(kq, []unix.Kevent_t{trigger}, nil, nil)
	}()
	defer func() {
		close(stop)
		<-gone
	}()

	out := make([]unix.Kevent_t, 2)
	for {
		n, err := unix.Kevent(kq, nil, out, nil)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("kevent wait pid %d: %w", pid, err)
		}
		cancelled := false
		for _, ev := range out[:n] {
			switch ev.Filter {
			case unix.EVFILT_PROC:
				return nil // NOTE_EXIT fired; the exit wins over a cancellation
			case unix.EVFILT_USER:
				cancelled = true
			}
		}
		if cancelled {
			if err := ctx.Err(); err != nil {
				return err
			}
			// A trigger with no cancellation behind it cannot happen (the
			// goroutine only fires after ctx.Done()); keep waiting rather than
			// invent a cancellation.
		}
	}
}

// reapDetached polls wait4(WNOHANG) until pid is collected. It is the handoff
// target for a WaitExit that returned before reaping — see there for why one is
// needed at all.
//
// LIFETIME: pid-scoped and self-terminating. It holds NOTHING but the int pid —
// no Process, no pod context, no file descriptor, no lock — so it can neither
// keep a torn-down pod's resources alive nor be preempted by the very
// cancellation that created it (taking a ctx here would reintroduce the abandoned
// zombie one level down). It returns as soon as the child is collected, or as
// soon as ECHILD proves there is nothing left to collect. Its worst case is
// therefore the child's own remaining lifetime, which is the correct bound: a
// parent owes its child a wait4 for exactly as long as the child lives. The cost
// of that worst case is one goroutine and a timer, not an OS thread — the poll
// is WNOHANG, so it never blocks in the kernel, which is why this is a poll and
// not a second kqueue registration.
//
// The collected status is DISCARDED, deliberately. WaitExit has already returned
// the status the container will report (an error, on every path that reaches
// here) and the pod it belonged to is being torn down; publishing a second,
// later status would overwrite an honest "the daemon was cancelled mid-kill" with
// one no live pod is waiting for. This goroutine exists to release a kernel
// process-table slot, and does only that.
func reapDetached(pid int) {
	// A pid <= 0 is a wait4 WILDCARD (any child / any child in a process group),
	// never an identified child of ours — reaping one would steal another
	// supervisor's exit status. It cannot arise from a started Process (Start
	// records the spawner's pid), so treat it as a programming error to drop.
	if pid <= 0 {
		slog.Warn("detached reap asked for a non-pid; dropping", "pid", pid)
		return
	}
	delay := detachedReapMinPoll
	for {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG, nil)
		switch {
		case err == nil && wpid == pid:
			return // collected: the process-table slot is released
		case err == nil:
			// wpid == 0: still alive. Keep waiting — see LIFETIME above.
		case errors.Is(err, unix.EINTR):
			// Interrupted before it could look; retry without backing off.
			continue
		case errors.Is(err, unix.ECHILD):
			return // already reaped, or never ours: nothing left to collect
		default:
			slog.Warn("detached reap gave up on a child", "pid", pid, "err", err)
			return
		}
		time.Sleep(delay)
		if delay *= 2; delay > detachedReapMaxPoll {
			delay = detachedReapMaxPoll
		}
	}
}

// SignalGroup sends sig to the process GROUP led by pgid (the pod's process
// group), used by DeletePod to tear down a whole pod. A nil error is returned if
// the group is already gone (ESRCH).
func SignalGroup(pgid int, sig os.Signal) error {
	s, ok := sig.(unix.Signal)
	if !ok {
		return fmt.Errorf("supervisor: unsupported signal %v", sig)
	}
	// Negative pid signals the process group.
	if err := unix.Kill(-pgid, s); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("kill process group %d: %w", pgid, err)
	}
	return nil
}
