//go:build darwin && cgo

package supervisor

/*
#include <libproc.h>
#include <sys/resource.h>
#include <errno.h>
#include <stdint.h>

// k3sm_phys_footprint reads ri_phys_footprint (bytes) for pid via
// proc_pid_rusage(RUSAGE_INFO_V2).
//
// proc_pid_rusage is PUBLIC (<libproc.h>, since 10.9) and is canaried in
// internal/spicanary so its disappearance fails the BUILD, not pods at runtime.
// The load-bearing semantic detail: ri_phys_footprint is the kernel's
// phys_footprint ledger for the task — resident + compressed + wired +
// IOKit-mapped memory — NOT RSS. It is the same accounting jetsam/memorystatus
// compares against a task's memory limit, so it is the correct number to gate an
// OOM kill on (and to report as the kubectl-top working set).
//
// RUSAGE_INFO_V2 (stable since 10.9/10.10) is the minimal flavor that carries
// ri_phys_footprint; later flavors only add fields, so V2 stays forward-safe.
//
// Returns 0 and writes *out on success, or the positive errno on failure
// (proc_pid_rusage returns -1 and sets errno — notably ESRCH for an exited pid).
static int k3sm_phys_footprint(int pid, uint64_t *out) {
	struct rusage_info_v2 ri;
	errno = 0;
	int rc = proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ri);
	if (rc != 0) {
		return errno ? errno : EINVAL;
	}
	*out = (uint64_t)ri.ri_phys_footprint;
	return 0;
}
*/
import "C"

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// PhysFootprinter is the production Footprinter: it reads ri_phys_footprint via
// proc_pid_rusage(RUSAGE_INFO_V2). The zero value is usable.
//
// ri_phys_footprint is NOT RSS — see the Footprinter and MemorySampler docs and
// docs/resources.md: it is the kernel's phys_footprint ledger (resident +
// compressed + wired + IOKit-mapped), the figure jetsam compares against a task's
// memory limit, so the OOM threshold and the kubectl-top working set are both in
// these units. This SPI is isolated here behind the Footprinter interface and
// re-verified by the internal/spicanary symbol-canary.
type PhysFootprinter struct{}

// Footprint returns pid's ri_phys_footprint in bytes. A failed sample (e.g. the
// pid already exited → ESRCH) is returned as a wrapped errno so the caller can
// skip it.
func (PhysFootprinter) Footprint(pid int) (uint64, error) {
	var out C.uint64_t
	rc := C.k3sm_phys_footprint(C.int(pid), &out)
	if rc != 0 {
		return 0, fmt.Errorf("proc_pid_rusage pid %d: %w", pid, unix.Errno(int(rc)))
	}
	return uint64(out), nil
}
