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
	"context"
	"sync"
	"time"
)

// Footprinter reports a process's physical-memory footprint in bytes — the
// ri_phys_footprint field of proc_pid_rusage. PhysFootprinter is the production
// implementation (rusage_darwin.go); unit tests inject a fake.
//
// ri_phys_footprint is NOT RSS. It is the kernel's phys_footprint ledger for the
// task — resident + compressed (swapped-but-accounted) + wired + IOKit-mapped
// memory — the SAME figure jetsam/memorystatus compares against a task's memory
// limit. So the OOM threshold the MemorySampler enforces is in phys-footprint
// units, and so is the working-set value surfaced to kubectl top. CPU is NOT
// bounded here: k3sm CPU limits are best-effort QoS (taskpolicy/setpriority),
// never CFS millicores. See docs/resources.md.
type Footprinter interface {
	// Footprint returns pid's ri_phys_footprint in bytes.
	Footprint(pid int) (bytes uint64, err error)
}

// RUsage is ONE proc_pid_rusage(RUSAGE_INFO_V2) sample: the memory footprint and
// the cumulative CPU time, read out of the SAME kernel struct by the SAME call.
// Reading both from one sample is the point — a stats snapshot whose memory and
// CPU came from two calls would straddle two instants, and the extra call would
// double the per-container syscall cost of every scrape.
type RUsage struct {
	// PhysFootprintBytes is ri_phys_footprint — identical to Footprint's value
	// (NOT RSS; see the Footprinter doc).
	PhysFootprintBytes uint64
	// CPUTimeNanos is ri_user_time + ri_system_time CONVERTED TO NANOSECONDS via
	// the host mach timebase (see MachTimebase — the raw fields are mach absolute
	// time units, not nanoseconds). It is the process's CUMULATIVE CPU time since
	// exec, i.e. a counter, and is the source of the kubelet Summary API's
	// CPUStats.usage_core_nano_seconds.
	//
	// It is USAGE accounting, never a millicore guarantee: k3sm enforces no CFS
	// quota (see docs/resources.md), so this number says what a pod consumed, not
	// what it was entitled to.
	CPUTimeNanos uint64
}

// RUsager is the richer proc_pid_rusage seam: a Footprinter that can also report
// cumulative CPU time. PhysFootprinter implements it; test fakes that only need
// the OOM/memory path may implement Footprinter alone.
//
// It is a SEPARATE (optional) interface rather than two methods on Footprinter so
// the memory sampler — which needs nothing else — keeps its 1-method consumer
// interface, and so a CPU-blind Footprinter stays a legal injection. A consumer
// type-asserts for it and reports no CPU when it is absent; the k3sm provider
// then withholds that pod from /metrics/resource entirely, because metrics-server
// has no memory-only path (see the provider's resource-metrics builder).
type RUsager interface {
	Footprinter
	// RUsage returns pid's combined memory + cumulative-CPU sample.
	RUsage(pid int) (RUsage, error)
}

// MemorySampler polls a pod's physical-memory footprint at a fixed interval and,
// when the summed footprint of its sampled PIDs first exceeds limitBytes, invokes
// onBreach EXACTLY ONCE (the runtime then SIGKILLs the pod and records OOMKilled).
// limitBytes == 0 disables the OOM check (meter-only — the kubectl top path).
//
// Concurrency: mu guards last/breached. The sampling loop is a SINGLE goroutine
// with a clear lifetime — Start launches it; it stops when ctx is cancelled (the
// runtime cancels it on pod teardown / pod termination) and closes Done, so there
// is no goroutine leak. onBreach is invoked OUTSIDE mu (the re-entrancy rule).
type MemorySampler struct {
	fp       Footprinter
	pids     func() []int
	limit    uint64
	onBreach func(footprint uint64)

	mu       sync.Mutex
	last     uint64
	breached bool

	done chan struct{}
}

// NewMemorySampler builds a sampler. fp samples per-PID footprints; pids returns
// the pod's CURRENT PID set (re-evaluated each tick, so an exited container drops
// out); limitBytes is the OOM threshold (0 = meter only); onBreach fires once on
// the first breach (nil for meter-only).
func NewMemorySampler(fp Footprinter, pids func() []int, limitBytes uint64, onBreach func(footprint uint64)) *MemorySampler {
	return &MemorySampler{
		fp:       fp,
		pids:     pids,
		limit:    limitBytes,
		onBreach: onBreach,
		done:     make(chan struct{}),
	}
}

// Start launches the sampling loop at interval, returning immediately. The loop
// runs until ctx is cancelled. Start must be called at most once.
func (s *MemorySampler) Start(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		s.loop(ctx, t.C)
	}()
}

// loop is the sampling loop, parameterized on the tick source so unit tests can
// drive ticks deterministically. It closes Done on return (the no-leak signal).
func (s *MemorySampler) loop(ctx context.Context, ticks <-chan time.Time) {
	defer close(s.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			s.sampleOnce()
		}
	}
}

// sampleOnce sums the footprints of the current PID set, records the latest value
// for the Summary API, and fires onBreach once on the first limit breach.
func (s *MemorySampler) sampleOnce() {
	var total uint64
	for _, pid := range s.pids() {
		fp, err := s.fp.Footprint(pid)
		if err != nil {
			// The pid may have exited between ticks (proc_pid_rusage → ESRCH), or
			// a sample failed; skip it rather than fail the whole pod.
			continue
		}
		total += fp
	}
	s.mu.Lock()
	s.last = total
	breach := s.limit > 0 && total > s.limit && !s.breached
	if breach {
		s.breached = true
	}
	s.mu.Unlock()
	if breach && s.onBreach != nil {
		s.onBreach(total)
	}
}

// Last returns the most recent summed footprint in bytes (0 before the first
// sample) — the working-set value the Summary API / kubectl top surfaces.
func (s *MemorySampler) Last() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// Done is closed when the sampling loop has stopped (ctx cancelled). It is the
// no-leak signal the runtime and unit tests assert on.
func (s *MemorySampler) Done() <-chan struct{} { return s.done }
