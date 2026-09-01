//go:build linux

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

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/guestinit"
)

// linuxProc implements guestinit.Proc against the Linux kernel. It is the only
// implementation, and it is deliberately three thin syscall wrappers: every
// decision about when to reap, when to signal and when to power off lives in
// guestinit.Reaper, where a darwin test can reach it.
type linuxProc struct{}

// Wait4 reaps one exited child without blocking. Non-terminal statuses (a
// stopped or continued child) are skipped rather than reported, because the
// reaper's contract is about exits: reporting a stop as a reap would retire a
// pid that is still running.
func (linuxProc) Wait4() (int, guestinit.WaitStatus, error) {
	for {
		var ws unix.WaitStatus
		pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		switch {
		case errors.Is(err, unix.ECHILD):
			return 0, guestinit.WaitStatus{}, guestinit.ErrNoChildren
		case errors.Is(err, unix.EINTR):
			return 0, guestinit.WaitStatus{}, guestinit.ErrInterrupted
		case err != nil:
			return 0, guestinit.WaitStatus{}, fmt.Errorf("wait4: %w", err)
		case pid <= 0:
			return 0, guestinit.WaitStatus{}, nil
		}
		switch {
		case ws.Exited():
			return pid, guestinit.WaitStatus{ExitCode: ws.ExitStatus()}, nil
		case ws.Signaled():
			return pid, guestinit.WaitStatus{Signal: int(ws.Signal())}, nil
		}
	}
}

// Kill sends sig to pid. ESRCH is not an error: the process the stop sequence
// wanted gone is gone, which is the outcome it asked for.
func (linuxProc) Kill(pid int, sig guestinit.Signal) error {
	err := unix.Kill(pid, unix.Signal(sig))
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

// Poweroff syncs and powers the machine off, in that order. The sync is not
// optional: the pod's overlay uppers are RAM and go with the machine, but a
// writable virtiofs share is a host directory and, for a PVC, storage that
// outlives the pod.
func (linuxProc) Poweroff() error {
	unix.Sync()
	return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}
