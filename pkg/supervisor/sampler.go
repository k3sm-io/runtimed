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
//
// DO NOT "SIMPLIFY" THIS TO RSS. The choice is load-bearing and it is now measured
// rather than argued: a GPU inference process holding 24 GiB of Metal buffers
// reports ri_phys_footprint 24 593 MB and ri_resident_size 31 MB — RSS is BLIND to
// the unified-memory working set, moving not at all across the entire ramp. A
// sampler metering RSS would show a pod using 31 MB while it held 24 GiB, and every
// memory limit on the node would be unenforceable. Only file-backed (mmap'd) pages
// show up in both; anything the GPU allocates shows up in footprint alone.
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

// DefaultBreachSamples is how many CONSECUTIVE over-limit samples a pod must
// produce before the sampler declares a breach.
//
// It is 3 rather than 1 because a single over-limit sample is not evidence of an
// over-limit pod. A GPU inference workload's footprint OSCILLATES: its allocator
// hands memory back and takes it again between samples, so measured transient
// peaks run ~60-130 MB above a ~2 GB steady state (~6%) while the pod is behaving
// exactly as intended. Killing on the first sample would OOMKill healthy pods on
// allocator churn — and an OOMKilled status is not a soft signal: upstream reads
// it as the pod's own fault, restarts it, and counts it against a Job's backoff.
//
// The cost is explicit and bounded: a pod that goes over its limit is killed up to
// N sample intervals later (~3 s at the default 1 Hz) than it would have been. That
// window is affordable here because nothing else is racing to act on it — on a
// 64 GiB host neither the Metal wired limit (which is a residency HINT, not a cap:
// allocation 8x past it succeeded with no eviction) nor jetsam engages anywhere in
// the range k3sm operates in. This sampler IS the killer, so it can afford to be
// sure before it fires.
const DefaultBreachSamples = 3

// MemorySampler polls a pod's physical-memory footprint at a fixed interval and,
// when the summed footprint of its sampled PIDs exceeds limitBytes for
// breachSamples CONSECUTIVE samples, invokes onBreach EXACTLY ONCE (the runtime
// then SIGKILLs the pod and records OOMKilled). limitBytes == 0 disables the OOM
// check (meter-only — the kubectl top path).
//
// PID COVERAGE — leader-PID-only, and why that is exact here. The sampler sums the
// footprints handed to it by pids(), which is the pod's live container LEADERS. A
// leader's ri_phys_footprint is blind to FORKED CHILDREN: measured against a
// deliberately forking process, a leader holding 200 MB with two 300 MB children
// reported 207 MB against a true group working set of 817 MB — a 3.9x under-count
// that grows with the worker count. That would be a pod appearing to fit its limit
// while the node ran out of memory.
//
// It is not a live risk because of a workload constraint, not a measurement
// accident: the engines k3sm's inference image can select were each measured
// single-process/multi-threaded, and the shipped mlx-serve image PINS a
// single-process engine, so the leader's footprint IS the pod's. Group sampling
// becomes REQUIRED the moment a forking engine is adopted; the mechanism for it —
// enumerating the pod's process group, which the daemon already places each
// container in — is understood and deliberately not built while nothing forks.
// Anything that changes the engine's process model must revisit this comment.
//
// Concurrency: mu guards last/breached/overRun. The sampling loop is a SINGLE
// goroutine with a clear lifetime — Start launches it; it stops when ctx is
// cancelled (the runtime cancels it on pod teardown / pod termination) and closes
// Done, so there is no goroutine leak. onBreach is invoked OUTSIDE mu (the
// re-entrancy rule).
type MemorySampler struct {
	fp       Footprinter
	pids     func() []int
	limit    uint64
	onBreach func(footprint uint64)
	// breachSamples is how many consecutive over-limit samples fire onBreach.
	breachSamples int

	mu   sync.Mutex
	last uint64
	// overRun counts the CONSECUTIVE over-limit samples seen so far; any sample at
	// or under the limit resets it to 0.
	overRun  int
	breached bool

	done chan struct{}
}

// MemorySamplerOption adjusts a MemorySampler at construction.
type MemorySamplerOption func(*MemorySampler)

// WithBreachSamples sets how many CONSECUTIVE over-limit samples declare a breach
// (see DefaultBreachSamples). n < 1 is clamped to 1 — "kill on the first sample" is
// a coherent, if aggressive, policy, while "kill on zero samples" is not.
//
// It exists for tests, which drive ticks deterministically and would otherwise have
// to encode the production constant into every expectation.
func WithBreachSamples(n int) MemorySamplerOption {
	return func(s *MemorySampler) {
		if n < 1 {
			n = 1
		}
		s.breachSamples = n
	}
}

// NewMemorySampler builds a sampler. fp samples per-PID footprints; pids returns
// the pod's CURRENT PID set (re-evaluated each tick, so an exited container drops
// out); limitBytes is the OOM threshold (0 = meter only); onBreach fires once after
// DefaultBreachSamples consecutive over-limit samples (nil for meter-only).
func NewMemorySampler(fp Footprinter, pids func() []int, limitBytes uint64, onBreach func(footprint uint64), opts ...MemorySamplerOption) *MemorySampler {
	s := &MemorySampler{
		fp:            fp,
		pids:          pids,
		limit:         limitBytes,
		onBreach:      onBreach,
		breachSamples: DefaultBreachSamples,
		done:          make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
// for the Summary API, and fires onBreach once the run of consecutive over-limit
// samples reaches breachSamples.
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
	over := s.limit > 0 && total > s.limit
	if over {
		s.overRun++
	} else {
		// A single sample back at or under the limit ends the run: the breach
		// condition is SUSTAINED over-limit, so an oscillating footprint must start
		// counting again rather than accumulate its peaks.
		s.overRun = 0
	}
	breach := over && s.overRun >= s.breachSamples && !s.breached
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
