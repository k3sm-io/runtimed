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
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestPhysFootprinterSelf exercises the real proc_pid_rusage cgo binding against
// this process (root-free, deterministic): a live process has a non-zero
// ri_phys_footprint. This proves the binding links and reads a sane value — the
// production memory sampler depends on it (the symbol itself is canaried in
// internal/spicanary). The OOMKilled-on-a-real-limit path is the m2.sh e2e.
func TestPhysFootprinterSelf(t *testing.T) {
	fp, err := PhysFootprinter{}.Footprint(os.Getpid())
	if err != nil {
		t.Fatalf("Footprint(self): %v", err)
	}
	if fp == 0 {
		t.Fatal("self ri_phys_footprint = 0, want > 0 (a live process has a footprint)")
	}
	t.Logf("self ri_phys_footprint = %d bytes", fp)
}

// TestPhysFootprinterDeadPidErrors confirms a sample of a non-existent pid returns
// an error (ESRCH), which the sampler treats as "skip this pid".
func TestPhysFootprinterDeadPidErrors(t *testing.T) {
	// pid 0x7FFFFFFE is effectively never live; proc_pid_rusage → ESRCH.
	if _, err := (PhysFootprinter{}).Footprint(0x7FFFFFFE); err == nil {
		t.Fatal("Footprint(non-existent pid) = nil error, want ESRCH")
	}
}

// TestPhysFootprinterRUsageSelf exercises the real proc_pid_rusage CPU path
// against this process (root-free): a live process has both a non-zero
// ri_phys_footprint and a non-zero cumulative CPU time, and the CPU counter is
// MONOTONE across samples (the property metrics-server's rate computation
// requires — it rejects a sample pair whose later cumulative value is smaller).
//
// The magnitude is also sanity-checked against an independent CPU reference:
// getrusage(RUSAGE_SELF) user plus system time, which the kernel converts to
// microseconds itself and so never passes through the user-space mach timebase
// scaling RUsage applies. The loop below burns CPU until that reference has
// advanced by at least minCPU, and the reported CPU delta must be within an order
// of magnitude of the reference delta in either direction. That is tight enough
// to catch the un-scaled mach-absolute-time reading, which would report ~1/41.67
// of the truth on Apple Silicon (or an inverted scaling, ~41.67x too much). The
// exact conversion is pinned hermetically in TestMachTimebaseNanos.
//
// The reference is CPU time, not wall time, on purpose: on a loaded host the
// burning thread is scheduled for only a fraction of a wall interval, so a wall
// comparison fails for a scheduling reason rather than a timebase error.
func TestPhysFootprinterRUsageSelf(t *testing.T) {
	const (
		minCPU   = 100 * time.Millisecond // reference CPU the burn must reach
		deadline = 10 * time.Second       // wall bound on reaching it
	)

	f := PhysFootprinter{}
	first, err := f.RUsage(os.Getpid())
	if err != nil {
		t.Fatalf("RUsage(self): %v", err)
	}
	if first.PhysFootprintBytes == 0 {
		t.Error("self ri_phys_footprint = 0, want > 0 (a live process has a footprint)")
	}
	if first.CPUTimeNanos == 0 {
		t.Error("self cumulative CPU = 0 ns, want > 0 (this process has run)")
	}

	// The reference interval sits inside the RUsage interval, so the reported
	// delta covers at least the reference delta.
	ref0 := selfCPU(t)
	start := time.Now()
	var ref time.Duration
	x := 0.0
	for {
		for i := 0; i < 100000; i++ {
			x += float64(i) * 0.5
		}
		ref = selfCPU(t) - ref0
		if ref >= minCPU {
			break
		}
		if time.Since(start) > deadline {
			t.Fatalf("burned only %v of process CPU in %v of wall time (want %v); "+
				"the host is too loaded for the magnitude check", ref, time.Since(start), minCPU)
		}
	}
	_ = x
	wall := time.Since(start)

	second, err := f.RUsage(os.Getpid())
	if err != nil {
		t.Fatalf("RUsage(self) second sample: %v", err)
	}
	if second.CPUTimeNanos < first.CPUTimeNanos {
		t.Fatalf("cumulative CPU went backwards: %d then %d", first.CPUTimeNanos, second.CPUTimeNanos)
	}
	delta := time.Duration(second.CPUTimeNanos - first.CPUTimeNanos)
	t.Logf("burned wall=%v, getrusage CPU delta=%v, reported CPU delta=%v", wall, ref, delta)
	if translated() {
		// Under Rosetta the process-visible mach timebase is 1/1 (Rosetta presents
		// mach_absolute_time in nanoseconds) while proc_pid_rusage still reports the
		// NATIVE 24 MHz counters the kernel keeps — so scaling by the visible
		// timebase undercounts by ~41.67x for a TRANSLATED reader. k3sm-runtimed is
		// a native arm64 daemon and never runs translated, but the Go toolchain on a
		// developer Mac may be x86_64, which would run this test translated and fail
		// the magnitude check for an environmental reason, not a code defect. Run the
		// gate as `GOARCH=arm64 go test` for the magnitude assertion.
		t.Skip("running under Rosetta: the visible mach timebase (1/1) does not describe " +
			"the native rusage counters; re-run with GOARCH=arm64 for the magnitude check")
	}
	// Both counters measure the same process CPU over (nearly) the same interval,
	// so they agree closely; a factor of ten either way is far outside any
	// sampling or granularity difference and far inside the ~41.67x of a missing
	// or inverted mach-tick scaling.
	if delta < ref/10 {
		t.Errorf("CPU delta %v is implausibly small against getrusage's %v — "+
			"the mach-absolute-time scaling looks to be missing", delta, ref)
	}
	if delta > ref*10 {
		t.Errorf("CPU delta %v is implausibly large against getrusage's %v — "+
			"the mach-absolute-time scaling looks to be inverted", delta, ref)
	}
}

// selfCPU returns this process's cumulative user plus system CPU time as
// getrusage(RUSAGE_SELF) reports it.
func selfCPU(t *testing.T) time.Duration {
	t.Helper()
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage(RUSAGE_SELF): %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// translated reports whether this process is running under Rosetta translation
// (sysctl.proc_translated == 1).
func translated() bool {
	v, err := unix.SysctlUint32("sysctl.proc_translated")
	return err == nil && v == 1
}

// TestPhysFootprinterRUsageDeadPidErrors confirms the CPU path fails the same way
// the memory path does for a pid that is gone (ESRCH → skip this pid).
func TestPhysFootprinterRUsageDeadPidErrors(t *testing.T) {
	if _, err := (PhysFootprinter{}).RUsage(0x7FFFFFFE); err == nil {
		t.Fatal("RUsage(non-existent pid) = nil error, want ESRCH")
	}
}

// TestHostTimebaseIsUsable asserts the host's mach_timebase_info reads and is a
// usable ratio — the precondition RUsage errors out on rather than reporting CPU
// scaled by a ratio nobody read.
func TestHostTimebaseIsUsable(t *testing.T) {
	tb, err := hostTimebase()
	if err != nil {
		t.Fatalf("hostTimebase: %v", err)
	}
	if !tb.Valid() {
		t.Fatalf("host mach timebase %d/%d is not usable", tb.Numer, tb.Denom)
	}
	t.Logf("host mach timebase = %d/%d", tb.Numer, tb.Denom)
}
