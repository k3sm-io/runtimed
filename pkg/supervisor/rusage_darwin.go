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
#include <libproc.h>
#include <sys/resource.h>
#include <mach/mach_time.h>
#include <errno.h>
#include <stdint.h>

// k3sm_rusage reads one struct rusage_info_v2 for pid via
// proc_pid_rusage(RUSAGE_INFO_V2) and extracts the three fields k3sm meters:
// ri_phys_footprint (bytes) and the ri_user_time / ri_system_time CPU counters.
//
// proc_pid_rusage is PUBLIC (<libproc.h>, since 10.9) and is canaried in
// internal/spicanary so its disappearance fails the BUILD, not pods at runtime.
//
// Two load-bearing semantic details:
//
//   - ri_phys_footprint is the kernel's phys_footprint ledger for the task —
//     resident + compressed + wired + IOKit-mapped memory — NOT RSS. It is the
//     same accounting jetsam/memorystatus compares against a task's memory limit,
//     so it is the correct number to gate an OOM kill on (and to report as the
//     kubectl-top working set).
//
//   - ri_user_time / ri_system_time are in MACH ABSOLUTE TIME UNITS, NOT
//     nanoseconds. XNU's fill_task_rusage copies task_power_info's
//     total_user/total_system straight out of the task's thread timers, which
//     accumulate in absolute time units. The two are numerically identical only
//     where the mach timebase is 1/1 (x86_64); on Apple Silicon it is 125/3, so
//     an unscaled reading undercounts CPU by ~41.67x. The scaling is applied in
//     Go via MachTimebase so it can be unit-tested with a faked ratio; this
//     function returns the RAW ticks and does not convert.
//
// Returns 0 and writes the three out-params on success, or the positive errno on
// failure (proc_pid_rusage returns -1 and sets errno — notably ESRCH for an
// exited pid).
static int k3sm_rusage(int pid, uint64_t *footprint, uint64_t *user_ticks, uint64_t *sys_ticks) {
	struct rusage_info_v2 ri;
	errno = 0;
	int rc = proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&ri);
	if (rc != 0) {
		return errno ? errno : EINVAL;
	}
	*footprint = (uint64_t)ri.ri_phys_footprint;
	*user_ticks = (uint64_t)ri.ri_user_time;
	*sys_ticks = (uint64_t)ri.ri_system_time;
	return 0;
}

// k3sm_mach_timebase reads mach_timebase_info(3) — the ticks→nanoseconds ratio
// the CPU counters above must be scaled by. Returns 0 on success, else the
// kern_return_t (non-zero) verbatim.
static int k3sm_mach_timebase(uint32_t *numer, uint32_t *denom) {
	mach_timebase_info_data_t tb;
	kern_return_t kr = mach_timebase_info(&tb);
	if (kr != KERN_SUCCESS) {
		return (int)kr;
	}
	*numer = tb.numer;
	*denom = tb.denom;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// PhysFootprinter is the production Footprinter AND RUsager: it reads
// ri_phys_footprint and the ri_user_time/ri_system_time CPU counters via
// proc_pid_rusage(RUSAGE_INFO_V2). The zero value is usable.
//
// ri_phys_footprint is NOT RSS — see the Footprinter and MemorySampler docs and
// docs/resources.md: it is the kernel's phys_footprint ledger (resident +
// compressed + wired + IOKit-mapped), the figure jetsam compares against a task's
// memory limit, so the OOM threshold and the kubectl-top working set are both in
// these units. This SPI is isolated here behind the Footprinter/RUsager
// interfaces and re-verified by the internal/spicanary symbol-canary.
//
// The name is retained (rather than widened to "RUsager") because the memory
// footprint is still what the OOM sampler exists for; CPU rides along in the same
// struct at no extra syscall cost.
type PhysFootprinter struct{}

var (
	_ Footprinter = PhysFootprinter{}
	_ RUsager     = PhysFootprinter{}
)

// timebaseOnce/timebase cache the host's mach_timebase_info ratio. It is a
// hardware constant for the life of the process, so reading it once and reusing
// it keeps RUsage to exactly one syscall per sample.
var (
	timebaseOnce sync.Once
	timebase     MachTimebase
	timebaseErr  error
)

// hostTimebase returns the cached mach timebase, reading it on first use.
func hostTimebase() (MachTimebase, error) {
	timebaseOnce.Do(func() {
		var numer, denom C.uint32_t
		if rc := C.k3sm_mach_timebase(&numer, &denom); rc != 0 {
			timebaseErr = fmt.Errorf("mach_timebase_info: kern_return_t %d", int(rc))
			return
		}
		timebase = MachTimebase{Numer: uint32(numer), Denom: uint32(denom)}
		if !timebase.Valid() {
			timebaseErr = fmt.Errorf("mach_timebase_info: unusable ratio %d/%d", timebase.Numer, timebase.Denom)
		}
	})
	return timebase, timebaseErr
}

// Footprint returns pid's ri_phys_footprint in bytes. A failed sample (e.g. the
// pid already exited → ESRCH) is returned as a wrapped errno so the caller can
// skip it.
func (f PhysFootprinter) Footprint(pid int) (uint64, error) {
	var footprint, user, sys C.uint64_t
	if rc := C.k3sm_rusage(C.int(pid), &footprint, &user, &sys); rc != 0 {
		return 0, fmt.Errorf("proc_pid_rusage pid %d: %w", pid, unix.Errno(int(rc)))
	}
	return uint64(footprint), nil
}

// RUsage returns pid's memory footprint and CUMULATIVE CPU time from a single
// proc_pid_rusage(RUSAGE_INFO_V2) sample. The CPU counters are scaled from mach
// absolute time units to nanoseconds by the host timebase (see MachTimebase for
// why an unscaled reading is the classic ~41.67x Apple-Silicon undercount).
//
// A failed sample is a wrapped errno, exactly as Footprint's is. An unreadable
// mach timebase is a hard error rather than an unscaled fallback: reporting CPU
// scaled by a ratio nobody read is worse than reporting none, because the k3sm
// provider withholds a CPU-less pod from /metrics/resource but happily publishes
// a wrong number.
func (f PhysFootprinter) RUsage(pid int) (RUsage, error) {
	tb, err := hostTimebase()
	if err != nil {
		return RUsage{}, err
	}
	var footprint, user, sys C.uint64_t
	if rc := C.k3sm_rusage(C.int(pid), &footprint, &user, &sys); rc != 0 {
		return RUsage{}, fmt.Errorf("proc_pid_rusage pid %d: %w", pid, unix.Errno(int(rc)))
	}
	// Sum in ticks, convert once: the two counters share a timebase, and summing
	// first avoids two truncations.
	return RUsage{
		PhysFootprintBytes: uint64(footprint),
		CPUTimeNanos:       tb.Nanos(uint64(user) + uint64(sys)),
	}, nil
}
