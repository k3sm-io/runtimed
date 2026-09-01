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

import (
	"sync"
	"testing"
)

// TestCPUAccumulatorMonotone is the counter-semantics proof: a container's
// cumulative CPU never goes backwards, in particular across a RESTART, where the
// raw per-process reading resets to near zero because the pid changed.
//
// This is the property the consumer's correctness rests on — metrics-server
// derives CPU as a rate from two cumulative samples and rejects a pair whose later
// value is smaller, so a naive pass-through of the raw per-pid counter would
// poison `kubectl top` for a restarted pod. Prometheus counter semantics for
// container_cpu_usage_seconds_total say the same from the wire side.
func TestCPUAccumulatorMonotone(t *testing.T) {
	// Each step is one observation; want is the cumulative total it must report.
	steps := []struct {
		name string
		pid  int
		raw  uint64
		want uint64
		why  string
	}{
		{"main", 100, 500, 500, "first sample of the first process"},
		{"main", 100, 900, 900, "same process, counter advanced"},
		{"main", 100, 1500, 1500, "same process, still advancing"},
		// The restart: a new pid whose raw counter starts over.
		{"main", 101, 10, 1510, "restart carries the retired process's 1500 forward"},
		{"main", 101, 300, 1800, "the new process accumulates on top of the carry"},
		{"main", 102, 0, 1800, "a second restart at zero still cannot go backwards"},
		{"main", 102, 7, 1807, "and resumes from the carry"},
		// A raw reading that came back smaller within one pid is not trusted.
		{"main", 102, 3, 1807, "a backwards reading for the same pid is ignored"},
	}
	var a cpuAccumulator
	var prev uint64
	for i, st := range steps {
		got := a.observe(st.name, st.pid, st.raw)
		if got != st.want {
			t.Errorf("step %d (%s): observe(%s, pid %d, raw %d) = %d, want %d",
				i, st.why, st.name, st.pid, st.raw, got, st.want)
		}
		if got < prev {
			t.Fatalf("step %d (%s): cumulative CPU went BACKWARDS %d → %d", i, st.why, prev, got)
		}
		prev = got
		if total, ok := a.total(st.name); !ok || total != got {
			t.Errorf("step %d: total(%s) = (%d, %v), want (%d, true)", i, st.name, total, ok, got)
		}
	}
}

// TestCPUAccumulatorPerContainer confirms the carry is keyed by container NAME, so
// two containers in one pod never contaminate each other's counters.
func TestCPUAccumulatorPerContainer(t *testing.T) {
	var a cpuAccumulator
	a.observe("app", 10, 1000)
	a.observe("sidecar", 11, 40)
	a.observe("app", 12, 5) // app restarted; sidecar did not
	if got, _ := a.total("app"); got != 1005 {
		t.Errorf("app total = %d, want 1005 (1000 retired + 5 live)", got)
	}
	if got, _ := a.total("sidecar"); got != 40 {
		t.Errorf("sidecar total = %d, want 40 (untouched by app's restart)", got)
	}
}

// TestCPUAccumulatorUnseenIsNotZero pins the distinction the metrics builder
// depends on: a container never observed reports ok=false, not a zero. A zero is
// indistinguishable from "idle" to the consumer, so returning one would publish an
// incomplete sample where the contract is to withhold the pod entirely.
func TestCPUAccumulatorUnseenIsNotZero(t *testing.T) {
	var a cpuAccumulator
	if v, ok := a.total("never-sampled"); ok {
		t.Errorf("total(unseen) = (%d, true), want ok=false", v)
	}
	// An observed container reporting a genuine zero IS reportable.
	a.observe("idle", 5, 0)
	if v, ok := a.total("idle"); !ok || v != 0 {
		t.Errorf("total(observed-idle) = (%d, %v), want (0, true)", v, ok)
	}
}

// TestCPUAccumulatorConcurrent exercises the lock under -race: the stats read path
// may be entered concurrently for the same pod.
func TestCPUAccumulatorConcurrent(t *testing.T) {
	var a cpuAccumulator
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := uint64(1); i <= 200; i++ {
				a.observe("main", 1, i)
				if _, ok := a.total("main"); !ok {
					t.Error("total(main) = ok=false after an observation")
				}
			}
		}()
	}
	wg.Wait()
	if got, _ := a.total("main"); got != 200 {
		t.Errorf("total after concurrent observation = %d, want 200 (the high-water raw)", got)
	}
}

// TestCPUAccumulatorSumIncludesRetiredContainers pins the pod-level counter's
// monotonicity: the pod total sums every container observed, including one that
// has since terminated and left the live set. Summing only live containers would
// make the pod's cumulative CPU FALL the moment a container exited, which a
// counter may not do and the consumer rejects.
func TestCPUAccumulatorSumIncludesRetiredContainers(t *testing.T) {
	var a cpuAccumulator
	if _, ok := a.sum(); ok {
		t.Error("sum() of an empty accumulator must report ok=false")
	}
	a.observe("init", 10, 300) // runs, then exits — never observed again
	a.observe("app", 11, 1000)
	if got, ok := a.sum(); !ok || got != 1300 {
		t.Fatalf("sum = (%d, %v), want (1300, true)", got, ok)
	}
	// "app" keeps running; "init" is gone. The pod total must not shrink.
	prev, _ := a.sum()
	a.observe("app", 11, 1500)
	got, _ := a.sum()
	if got < prev {
		t.Errorf("pod total fell %d → %d after a container exited", prev, got)
	}
	if got != 1800 {
		t.Errorf("pod total = %d, want 1800 (300 retired init + 1500 live app)", got)
	}
}
