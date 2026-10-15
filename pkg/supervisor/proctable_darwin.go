//go:build darwin

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
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// sZomb is XNU's p_stat for a process that has exited and awaits its reap.
const sZomb = 5

// ReadProcTable is the production ProcTable: one sysctl kern.proc.all for
// every process's pid, parent, group, start time and state, plus getsid(2) per
// process for its session (kinfo_proc carries no usable session id). On the
// lab Macs a whole read costs well under a millisecond.
func ReadProcTable() ([]ProcEntry, bool) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, false
	}
	out := make([]ProcEntry, 0, len(kps))
	for i := range kps {
		pid := int(kps[i].Proc.P_pid)
		sid, err := unix.Getsid(pid)
		if err != nil {
			sid = 0 // gone between the two reads; its session matches nothing
		}
		tv := kps[i].Proc.P_starttime
		out = append(out, ProcEntry{
			Pid:           pid,
			Ppid:          int(kps[i].Eproc.Ppid),
			Pgid:          int(kps[i].Eproc.Pgid),
			Sid:           sid,
			StartUnixNano: tv.Nano(),
			Zombie:        kps[i].Proc.P_stat == sZomb,
			Comm:          unix.ByteSliceToString(kps[i].Proc.P_comm[:]),
		})
	}
	return out, true
}

// ProcSessionID reports pid's session id via getsid(2); ok is false when the
// process does not exist or cannot be asked.
func ProcSessionID(pid int) (sid int, ok bool) {
	sid, err := unix.Getsid(pid)
	return sid, err == nil
}

// KillPID sends sig to the single process pid. A nil error is returned when
// the process is already gone (ESRCH).
func KillPID(pid int, sig unix.Signal) error {
	if pid <= 1 {
		return fmt.Errorf("supervisor: refusing to signal pid %d", pid)
	}
	if err := unix.Kill(pid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("kill process %d: %w", pid, err)
	}
	return nil
}
