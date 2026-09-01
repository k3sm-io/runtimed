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

package runtime

import "sync"

// cpuAccumulator turns per-PROCESS cumulative CPU readings into per-CONTAINER
// cumulative CPU that is MONOTONE for the whole life of the pod.
//
// Why it has to exist: proc_pid_rusage counts a PROCESS. A restarted container is
// a new pid whose counter starts again near zero, so the raw reading for that
// container jumps BACKWARDS at every restart. The consumer cannot tolerate that —
// metrics-server derives CPU as a RATE from two cumulative samples and rejects a
// pair whose later value is smaller than the earlier one (its
// storage.resourceUsage errors with "unexpected decrease in cumulative CPU"), so
// a single restart would poison `kubectl top` for that pod until the counter
// climbed back past its pre-restart peak. The Prometheus counter semantics of
// container_cpu_usage_seconds_total say the same thing from the wire side.
//
// The fix is the usual counter-carry: when the pid behind a container name
// changes, the last reading observed for the retired pid is folded into a
// per-container `retired` total that only ever grows, and the container's
// cumulative value is reported as retired + the current process's reading.
//
// # Honest limitation
//
// Readings are taken when a stats request arrives, not continuously, so the
// retired total carries the last value this accumulator actually SAW for the old
// pid — the CPU that process burned between the final observation and its exit is
// lost. A restart between two scrapes therefore UNDERCOUNTS by that tail. It never
// breaks monotonicity (retired only grows and the live reading is added on top),
// which is the property the consumer's correctness depends on; and at a 15 s
// metrics-server scrape interval against a ~1 Hz restart-to-scrape gap the lost
// tail is small. Closing it entirely would mean sampling a container's final
// rusage at exit, which is a change to the exit path, not to metering.
//
// The zero value is ready to use. All methods are safe for concurrent use.
type cpuAccumulator struct {
	mu sync.Mutex
	// byContainer is keyed by container NAME (stable across restarts), never by
	// pid (which is exactly what changes).
	byContainer map[string]cpuCounter
}

// cpuCounter is one container's CPU bookkeeping.
type cpuCounter struct {
	// pid is the process the `last` reading came from. A change of pid is the
	// restart signal.
	pid int
	// last is the most recent raw cumulative reading for pid, in nanoseconds.
	last uint64
	// retired is the summed final readings of every previous pid for this
	// container. It never decreases.
	retired uint64
}

// observe records a raw per-process cumulative CPU reading (nanoseconds) for the
// container name running as pid, and returns the container's pod-lifetime
// cumulative CPU.
//
// The return value is guaranteed to be >= every value previously returned for the
// same name, both across a pid change (the retired carry) and within one pid (a
// reading that somehow came back smaller is ignored rather than trusted).
func (a *cpuAccumulator) observe(name string, pid int, raw uint64) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.byContainer == nil {
		a.byContainer = make(map[string]cpuCounter)
	}
	c, seen := a.byContainer[name]
	switch {
	case !seen:
		c.pid = pid
	case c.pid != pid:
		// Restart: fold the retiring process's last observed total into the carry
		// and start the new process from zero.
		c.retired += c.last
		c.pid = pid
		c.last = 0
	}
	if raw > c.last {
		c.last = raw
	}
	a.byContainer[name] = c
	return c.retired + c.last
}

// sum returns the pod-lifetime cumulative CPU of every container this
// accumulator has observed, including ones that have since terminated. ok is
// false when nothing has been observed at all.
//
// A pod's counter must include a container that has exited: dropping it when the
// container leaves the live set would make the pod's cumulative CPU FALL, which is
// exactly what a counter may not do (and what the consumer rejects).
func (a *cpuAccumulator) sum() (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.byContainer) == 0 {
		return 0, false
	}
	var total uint64
	for _, c := range a.byContainer {
		total += c.retired + c.last
	}
	return total, true
}

// total returns the container's pod-lifetime cumulative CPU from the readings
// already observed, without taking a new one. ok is false for a container this
// accumulator has never seen — the caller must then report no CPU at all rather
// than a zero, because a zero is indistinguishable from "idle" to the consumer and
// would publish an incomplete sample instead of withholding one.
//
// This is what keeps a container that has EXITED (no pid to sample) from dragging
// its pod's cumulative CPU back down to zero.
func (a *cpuAccumulator) total(name string) (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.byContainer[name]
	if !ok {
		return 0, false
	}
	return c.retired + c.last, true
}
