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
#include <sys/types.h>

// csops is the code-signing-operations syscall wrapper libsystem_kernel
// exports. PRIVATE SPI: its only declaration is in the kernel's
// <sys/codesign.h>, which the public SDK does not ship, so it is declared here
// and canaried in internal/spicanary (a removed export fails the build, not
// the detection at runtime). CS_OPS_STATUS (0) copies the process's csflags.
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

static int k3sm_cs_status(int pid, uint32_t *flags) {
	errno = 0;
	if (csops((pid_t)pid, 0, flags, sizeof(*flags)) != 0) {
		return errno ? errno : EINVAL;
	}
	return 0;
}

// CS_OPS_CDHASH (5) copies the process's code-directory hash. The kernel
// requires the buffer to be exactly CS_CDHASH_LEN (20) bytes.
static int k3sm_cs_cdhash(int pid, uint8_t *out) {
	errno = 0;
	if (csops((pid_t)pid, 5, out, 20) != 0) {
		return errno ? errno : EINVAL;
	}
	return 0;
}
*/
import "C"

import (
	"encoding/hex"
	"unsafe"

	"golang.org/x/sys/unix"
)

// cdHashLen is CS_CDHASH_LEN, the size of the code-directory hash csops copies.
const cdHashLen = 20

// CodeSignStatus returns pid's kernel code-signing flags (csops
// CS_OPS_STATUS). It fails with the errno, notably ESRCH once the process is
// gone. The caller owns the pid-reuse question: see Process.ObserveExec for
// the ordering that answers it.
func CodeSignStatus(pid int) (uint32, error) {
	var flags C.uint32_t
	if rc := C.k3sm_cs_status(C.int(pid), &flags); rc != 0 {
		return 0, unix.Errno(rc)
	}
	return uint32(flags), nil
}

// CodeDirectoryHash returns pid's code-directory hash (csops CS_OPS_CDHASH) as
// lower-case hex: the kernel's identity for the exact signed binary the process
// is running. Every darwin/arm64 executable carries one (the linker ad-hoc signs
// what nobody else signs), so an error here means the process is gone or the SPI
// changed, not that the binary is unsigned. Same PRIVATE SPI and canary as
// CodeSignStatus.
func CodeDirectoryHash(pid int) (string, error) {
	var buf [cdHashLen]byte
	if rc := C.k3sm_cs_cdhash(C.int(pid), (*C.uint8_t)(unsafe.Pointer(&buf[0]))); rc != 0 {
		return "", unix.Errno(rc)
	}
	return hex.EncodeToString(buf[:]), nil
}
