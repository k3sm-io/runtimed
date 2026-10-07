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

/*
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <libproc.h>
#include <sys/proc_info.h>

// k3sm_pbi_flags reads pid's pbi_flags through the PUBLIC proc_pidinfo
// (<libproc.h>) PROC_PIDTBSDINFO flavor. The short-info flavor names its field
// pbsi_flags; this one is pbi_flags. Returns 0 or an errno.
static int k3sm_pbi_flags(pid_t pid, uint32_t *out) {
	struct proc_bsdinfo bi;
	memset(&bi, 0, sizeof(bi));
	errno = 0;
	int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, sizeof(bi));
	if (n != (int)sizeof(bi)) return errno ? errno : EIO;
	*out = bi.pbi_flags;
	return 0;
}
*/
import "C"

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// pcontrolFlags returns pid's pbi_flags word, whose PROC_FLAG_PC_* bits are the
// process's resource-starvation policy.
func pcontrolFlags(pid int) (uint32, error) {
	var flags C.uint32_t
	if rc := C.k3sm_pbi_flags(C.pid_t(pid), &flags); rc != 0 {
		return 0, fmt.Errorf("proc_pidinfo(%d, PROC_PIDTBSDINFO): %w", pid, unix.Errno(rc))
	}
	return uint32(flags), nil
}

// pcontrolIsKill reports whether flags carry the kill policy. The policy is a
// two-bit field, not a flag: PROC_FLAG_PC_KILL equals PROC_FLAG_PC_MASK (both
// the THROTTLE and SUSP bits), so a bare flags&PC_KILL would accept either
// lesser policy. Only the full-mask compare is correct.
func pcontrolIsKill(flags uint32) bool {
	return flags&uint32(C.PROC_FLAG_PC_MASK) == uint32(C.PROC_FLAG_PC_KILL)
}

// VerifyPressureKill proves on this host that PosixSpawner{PressureKill: true}
// produces a pcontrol-KILL child: it spawns /bin/sleep through it, reads the
// policy back while the child lives, then SIGKILLs and reaps it. It returns nil
// only when the read-back shows the kill policy. The daemon runs it once at
// startup and spawns pods unmarked (and reports why) when it fails.
func VerifyPressureKill(ctx context.Context) error {
	pid, err := PosixSpawner{PressureKill: true}.Spawn(ctx, SpawnSpec{
		Path: "/bin/sleep",
		Argv: []string{"/bin/sleep", "30"},
		Env:  []string{},
	})
	if err != nil {
		return fmt.Errorf("pressure-kill self-check: spawn probe: %w", err)
	}
	flags, readErr := pcontrolFlags(pid)
	// The probe has served its purpose whatever the read said. KqueueReaper
	// reaps on every return path, so a cancelled ctx cannot leave a zombie.
	_ = unix.Kill(pid, unix.SIGKILL)
	_, _, _ = KqueueReaper{}.WaitExit(ctx, pid)
	if readErr != nil {
		return fmt.Errorf("pressure-kill self-check: %w", readErr)
	}
	if !pcontrolIsKill(flags) {
		return fmt.Errorf("pressure-kill self-check: pbi_flags 0x%x: %w", flags, ErrPressureKillNotMarked)
	}
	return nil
}
