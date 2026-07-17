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

// ProcStartTimeNano reports pid's kernel process start time in unix
// nanoseconds via sysctl kern.proc.pid (kinfo_proc.p_starttime). ok is false
// when the process does not exist or the sysctl fails.
//
// Start time is the identity anchor recorded for a spawned pod's process group
// leader: it is assigned by the kernel at spawn and survives execve (the
// sandbox exec-shim execs the pod binary, so the executable path does NOT
// survive), so it stays valid for the leader's whole life.
func ProcStartTimeNano(pid int) (startUnixNano int64, ok bool) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, false
	}
	tv := kp.Proc.P_starttime
	return tv.Nano(), true
}

// ProcGroupStartsNano reports the kernel start times (unix nanoseconds) of the
// live members of process GROUP pgid, via sysctl kern.proc.pgrp. ok is false
// only when the group cannot be inspected (a real sysctl failure); an existing
// but EMPTY group (every member gone) returns an empty slice with ok true.
//
// The startup pod reap inspects the GROUP, not just the leader pid: a pod
// process commonly forks grandchildren (shell → daemon), and after a daemon
// death the orphaned leader reparents to launchd and is reaped while its
// grandchildren keep holding ports in the same group. Probing only the leader
// would miss them. The kernel reserves a pgid while ANY member of that group
// is alive, so a non-empty result cannot be a group that recycled the pgid out
// from under us — it is our original group's survivors.
func ProcGroupStartsNano(pgid int) (memberStartsNano []int64, ok bool) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return nil, false
	}
	starts := make([]int64, 0, len(kps))
	for i := range kps {
		tv := kps[i].Proc.P_starttime
		starts = append(starts, tv.Nano())
	}
	return starts, true
}
