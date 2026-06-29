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
	"os"

	"golang.org/x/sys/unix"
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
func (KqueueReaper) WaitExit(ctx context.Context, pid int) (int, int, error) {
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
		// Block for the exit event, honoring ctx via a short poll timeout so a
		// cancelled context unblocks the reaper without leaking the goroutine.
		out := make([]unix.Kevent_t, 1)
		timeout := unix.Timespec{Sec: 0, Nsec: 250_000_000} // 250ms poll
		for {
			if err := ctx.Err(); err != nil {
				return 0, 0, err
			}
			n, err := unix.Kevent(kq, nil, out, &timeout)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return 0, 0, fmt.Errorf("kevent wait pid %d: %w", pid, err)
			}
			if n > 0 {
				break // NOTE_EXIT fired
			}
			// n == 0: timeout — re-check ctx and loop.
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
				return 0, 0, nil
			}
			return 0, 0, fmt.Errorf("wait4 pid %d: %w", pid, err)
		}
		if wpid == pid {
			break
		}
	}

	if ws.Signaled() {
		return 128 + int(ws.Signal()), int(ws.Signal()), nil
	}
	return ws.ExitStatus(), 0, nil
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
