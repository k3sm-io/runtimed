//go:build darwin && cgo

/*
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
*/

package sandbox

/*
#include <stdlib.h>
#include <unistd.h>

// sandbox_check is private libsandbox SPI (variadic, not in the public
// <sandbox.h>), canaried with the other Seatbelt symbols in internal/spicanary.
// It is linked rather than resolved through dlsym because it is variadic: on
// arm64 Darwin a variadic argument is passed on the stack, so calling it through
// a non-variadic function pointer would hand it garbage.
extern int sandbox_check(pid_t pid, const char *operation, int type, ...);

// SANDBOX_FILTER_PATH selects a path argument; SANDBOX_CHECK_NO_REPORT keeps a
// denied query out of the system log (the query is runtimed's, not the target's).
#define K3SM_SANDBOX_FILTER_PATH 1
#define K3SM_SANDBOX_CHECK_NO_REPORT 0x40000000

// k3sm_pid_sandboxed reports 1 when pid runs under a Seatbelt policy, 0 when it
// does not, -1 on error (the process is gone, or the query was refused).
static int k3sm_pid_sandboxed(pid_t pid) {
	return sandbox_check(pid, NULL, 0);
}

// k3sm_pid_policy_denies_write asks pid's own policy whether it would allow a
// file-write-data on path: 0 allowed, 1 denied, -1 error.
static int k3sm_pid_policy_denies_write(pid_t pid, const char *path) {
	return sandbox_check(pid, "file-write-data",
		K3SM_SANDBOX_FILTER_PATH | K3SM_SANDBOX_CHECK_NO_REPORT, path);
}
*/
import "C"

import (
	"unsafe"
)

// ProbeWritePolicy asks the Seatbelt policy that pid runs under whether it
// allows a file-write-data on path. It reports whether pid is sandboxed at all,
// whether its policy allows the write, and ok=false when either query failed
// (the process exited, or libsandbox refused). Nothing is written: the answer is
// libsandbox's evaluation of pid's policy, and the query is not logged.
//
// The policy is the one thing a process cannot drop or change: setsid, a new
// process group and reparenting to launchd all leave it in place, and every
// descendant inherits it (measured on macOS 27 for a POSIX_SPAWN_SETSID child
// whose parent exited, ppid 1). Measured caveats a caller must design around:
// path must exist (a path that does not exist answers "denied" whatever the
// policy says), and an unsandboxed process answers "allowed" for every path.
func ProbeWritePolicy(pid int, path string) (sandboxed, allowed, ok bool) {
	if pid <= 0 || path == "" {
		return false, false, false
	}
	switch C.k3sm_pid_sandboxed(C.pid_t(pid)) {
	case 0:
		return false, false, true
	case 1:
	default:
		return false, false, false
	}
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))
	switch C.k3sm_pid_policy_denies_write(C.pid_t(pid), cs) {
	case 0:
		return true, true, true
	case 1:
		return true, false, true
	default:
		return true, false, false
	}
}
