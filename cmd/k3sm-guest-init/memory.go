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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
)

// applyContainerMemory writes cp's memory limits into its cgroup2 leaf before
// the container's process is forked into it. leaf is "" when no leaf could be
// made.
//
// With no limit it writes nothing and a missing leaf is the unmetered case the
// spawn already degrades to. With a limit, a missing leaf or a failed write
// fails the container's start: the host asked for a bound and this guest
// advertises memory-limits, so running the container without it would let it
// take the whole VM's memory while the pod spec says it cannot.
//
// It lives in an untagged file so the gate runs on the darwin host; the linux
// spawn is its only caller.
func applyContainerMemory(leaf string, cp guestinit.ContainerPlan) error {
	limits := guestagent.MemoryLimits{Max: cp.MemoryMaxBytes, High: cp.MemoryHighBytes}
	if !limits.Set() {
		return nil
	}
	if leaf == "" {
		return fmt.Errorf("container %s has a memory limit but no cgroup2 leaf to apply it to", cp.Name)
	}
	if err := guestagent.ApplyMemoryLimits(leaf, limits); err != nil {
		return fmt.Errorf("container %s: %w", cp.Name, err)
	}
	return nil
}

// oomWatch decides ContainerExited.oom_killed from each container leaf's
// memory.events oom_kill counter.
//
// The counter is cumulative over the leaf's life and a restart reuses the
// leaf, so the verdict is a comparison against the count taken when this
// instance started (arm), never the raw count: an instance that exited
// normally after an earlier instance was OOM-killed is not OOMKilled.
//
// A counter that cannot be read at arm or at exit yields false. OOMKilled is
// the pod's own fault upstream (a restart, a Job backoff charge), so it is set
// only on proof.
//
// mu guards base; arm runs on a starter's goroutine and killed on the reap loop.
type oomWatch struct {
	root string

	mu   sync.Mutex
	base map[string]uint64
}

func newOOMWatch(root string) *oomWatch {
	return &oomWatch{root: root, base: map[string]uint64{}}
}

// arm records the container's oom_kill count before an instance runs.
func (w *oomWatch) arm(container string) {
	n, ok := w.count(container)
	w.mu.Lock()
	defer w.mu.Unlock()
	if !ok {
		delete(w.base, container)
		return
	}
	w.base[container] = n
}

// killed reports whether the container's cgroup OOM killer ran since arm.
func (w *oomWatch) killed(container string) bool {
	w.mu.Lock()
	base, armed := w.base[container]
	w.mu.Unlock()
	if !armed {
		return false
	}
	n, ok := w.count(container)
	return ok && n > base
}

func (w *oomWatch) count(container string) (uint64, bool) {
	leaf, err := guestagent.LeafPath(w.root, container)
	if err != nil {
		return 0, false
	}
	ev, err := guestagent.ReadMemoryEvents(leaf)
	if err != nil {
		return 0, false
	}
	return ev.OOMKill, true
}

// sampleLeaf reads one container leaf's cpu.stat, memory.current, memory.stat
// and memory.events into a sample. It is cgroupSampler.Sample's body below the
// leaf-exists check, in an untagged file so the gate runs on the darwin host.
//
// Any file that is missing or does not parse fails the whole sample: a
// partially-read sample is not a sample, and reporting the half that parsed
// would put a CPU counter next to a working set of zero. That includes a
// memory.events without oom_kill (guestagent.ErrCgroupFieldAbsent).
func sampleLeaf(dir string) (guestagent.ContainerSample, error) {
	cpuStat, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read cpu.stat: %w", err)
	}
	usage, err := guestagent.CPUUsageUsec(string(cpuStat))
	if err != nil {
		return guestagent.ContainerSample{}, err
	}
	current, err := os.ReadFile(filepath.Join(dir, "memory.current"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read memory.current: %w", err)
	}
	memStat, err := os.ReadFile(filepath.Join(dir, "memory.stat"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read memory.stat: %w", err)
	}
	ws, err := guestagent.WorkingSet(string(current), string(memStat))
	if err != nil {
		return guestagent.ContainerSample{}, err
	}
	events, err := guestagent.ReadMemoryEvents(dir)
	if err != nil {
		return guestagent.ContainerSample{}, err
	}
	return guestagent.ContainerSample{CPUUsageUsec: usage, MemoryWorkingSetBytes: ws, MemoryHighEvents: events.High}, nil
}
