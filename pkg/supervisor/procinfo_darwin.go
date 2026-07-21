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
	"golang.org/x/sys/unix"
)

// ProcMember is one live member of a process group as reported by
// ProcGroupMembers: its pid and its kernel-reported start time (unix
// nanoseconds). It is the kern.proc.pgrp-result owner — the startup pod reap's
// exact-instance identity check reads BOTH fields (the leader pid == pgid only
// while the leader lives, and the start time is the immutable fork timestamp).
type ProcMember struct {
	// Pid is the member's process id.
	Pid int
	// StartUnixNano is the member's kernel start time in unix nanoseconds,
	// derived IDENTICALLY to ProcStartTimeNano (P_starttime.Nano()) so an
	// equality comparison between the two paths is bit-exact.
	StartUnixNano int64
}

// ProcStartTimeNano reports pid's kernel process start time in unix
// nanoseconds via sysctl kern.proc.pid (kinfo_proc.p_starttime). ok is false
// when the process does not exist or the sysctl fails.
//
// Start time is the identity anchor recorded for a spawned pod's process group
// leader: it is assigned by the kernel at spawn and survives execve (the
// sandbox exec-shim execs the pod binary, so the executable path does NOT
// survive), so it stays valid for the leader's whole life. ProcGroupMembers
// derives its members' StartUnixNano with the IDENTICAL expression, so the
// reap's exact-equality identity check is a bit-exact comparison.
func ProcStartTimeNano(pid int) (startUnixNano int64, ok bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, false
	}
	tv := kp.Proc.P_starttime
	return tv.Nano(), true
}

// ProcGroupMembers reports the live members (pid + start time) of process GROUP
// pgid, via sysctl kern.proc.pgrp. ok is false only when the group cannot be
// inspected (a real sysctl failure); an existing but EMPTY group (every member
// gone) returns an empty slice with ok true.
//
// The startup pod reap inspects the GROUP, not just the leader pid: a pod
// process commonly forks grandchildren (shell → daemon), and after a daemon
// death the orphaned leader reparents to launchd and is reaped while its
// grandchildren keep holding ports in the same group. Probing the group lets
// the reap SEE those survivors, but the kill decision is driven by the exact
// leader member (Pid == pgid): the reaper kills only when that member's start
// time matches the recorded leader start, so a recycled pgid (whose leader has
// a different start, or whose leader is gone) is never signalled. Each member's
// StartUnixNano uses the SAME P_starttime.Nano() derivation as
// ProcStartTimeNano so the equality check is bit-exact.
func ProcGroupMembers(pgid int) (members []ProcMember, ok bool) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return nil, false
	}
	members = make([]ProcMember, 0, len(kps))
	for i := range kps {
		tv := kps[i].Proc.P_starttime
		members = append(members, ProcMember{
			Pid:           int(kps[i].Proc.P_pid),
			StartUnixNano: tv.Nano(),
		})
	}
	return members, true
}
