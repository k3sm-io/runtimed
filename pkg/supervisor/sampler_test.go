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
	"testing"
	"time"
)

// fakeFootprinter returns canned per-pid footprints, settable between ticks.
type fakeFootprinter struct {
	mu sync.Mutex
	fp map[int]uint64
}

func newFakeFootprinter() *fakeFootprinter { return &fakeFootprinter{fp: map[int]uint64{}} }

func (f *fakeFootprinter) set(pid int, bytes uint64) {
	f.mu.Lock()
	f.fp[pid] = bytes
	f.mu.Unlock()
}

func (f *fakeFootprinter) Footprint(pid int) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fp[pid], nil
}

// TestMemorySamplerMetersWorkingSet drives the meter-only path (limit 0): the
// sampler sums the pod's per-PID footprints and exposes the latest via Last() —
// the kubectl top / Summary-API source.
func TestMemorySamplerMetersWorkingSet(t *testing.T) {
	ff := newFakeFootprinter()
	ff.set(10, 100)
	ff.set(11, 50) // a two-container pod: footprint is the sum (150)
	s := NewMemorySampler(ff, func() []int { return []int{10, 11} }, 0 /* meter only */, nil)

	ticks := make(chan time.Time)
	go s.loop(context.Background(), ticks)

	// Two ticks: when the second send returns the loop has received it, which it
	// can only do after finishing the first tick's sampleOnce (the loop is serial).
	ticks <- time.Now()
	ticks <- time.Now()

	if got := s.Last(); got != 150 {
		t.Errorf("Last() = %d, want 150 (sum of 100+50)", got)
	}
}

// TestMemorySamplerOOMBreachFiresOnce proves the OOM path: a sustained over-limit
// footprint fires onBreach exactly once after DefaultBreachSamples consecutive
// samples, Last() tracks the sample, and the loop stops (Done closes) on ctx
// cancel — the no-goroutine-leak signal.
func TestMemorySamplerOOMBreachFiresOnce(t *testing.T) {
	ff := newFakeFootprinter()
	ff.set(10, 8<<20)     // 8 MiB, over the limit
	const limit = 1 << 20 // 1 MiB

	breaches := make(chan uint64, 8)
	s := NewMemorySampler(ff, func() []int { return []int{10} }, limit, func(b uint64) { breaches <- b })

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	go s.loop(ctx, ticks)

	// The first DefaultBreachSamples-1 over-limit samples must not fire: a single
	// spike is allocator churn, not an over-limit pod.
	for i := 0; i < DefaultBreachSamples-1; i++ {
		ticks <- time.Now()
		select {
		case b := <-breaches:
			t.Fatalf("onBreach fired after %d over-limit sample(s) (footprint %d); want %d consecutive", i+1, b, DefaultBreachSamples)
		default:
		}
	}
	ticks <- time.Now() // the sample that completes the run
	select {
	case b := <-breaches:
		if b <= limit {
			t.Errorf("onBreach footprint = %d, want > limit %d", b, limit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onBreach did not fire on a memory-limit breach")
	}

	// Further ticks must not re-fire onBreach (once-only).
	ticks <- time.Now()
	ticks <- time.Now()
	select {
	case b := <-breaches:
		t.Errorf("onBreach fired more than once (got another %d)", b)
	case <-time.After(100 * time.Millisecond):
	}

	if got := s.Last(); got != 8<<20 {
		t.Errorf("Last() = %d, want %d", got, 8<<20)
	}

	// Stop → Done closes (no goroutine leak).
	cancel()
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("sampler did not stop on ctx cancel (goroutine leak)")
	}
}

// TestMemorySamplerUnderLimitNoBreach confirms a pod under its limit never fires
// onBreach.
func TestMemorySamplerUnderLimitNoBreach(t *testing.T) {
	ff := newFakeFootprinter()
	ff.set(10, 512<<10) // 512 KiB, under the 1 MiB limit

	breaches := make(chan uint64, 1)
	s := NewMemorySampler(ff, func() []int { return []int{10} }, 1<<20, func(b uint64) { breaches <- b })

	ticks := make(chan time.Time)
	go s.loop(context.Background(), ticks)
	ticks <- time.Now()
	ticks <- time.Now()

	select {
	case <-breaches:
		t.Error("onBreach fired for a pod under its memory limit")
	default:
	}
}

// TestMemorySamplerBreachRequiresConsecutiveSamples pins the sustained-breach rule
// and its reset: an oscillating footprint — which is what a GPU inference pod's
// allocator actually produces, with transient peaks a few percent above a healthy
// steady state — must not accumulate its spikes into a kill.
func TestMemorySamplerBreachRequiresConsecutiveSamples(t *testing.T) {
	ff := newFakeFootprinter()
	const limit = 1 << 20

	breaches := make(chan uint64, 4)
	s := NewMemorySampler(ff, func() []int { return []int{10} }, limit, func(b uint64) { breaches <- b },
		WithBreachSamples(3))

	ticks := make(chan time.Time)
	go s.loop(context.Background(), ticks)

	// Two over-limit samples interrupted by one under-limit sample: the run resets,
	// so no kill — even though 4 of the 5 samples below are over the limit.
	for _, fp := range []uint64{8 << 20, 8 << 20, 512 << 10, 8 << 20, 8 << 20} {
		ff.set(10, fp)
		ticks <- time.Now()
	}
	select {
	case b := <-breaches:
		t.Fatalf("onBreach fired on an oscillating footprint (got %d)", b)
	default:
	}

	// One more consecutive over-limit sample completes the run of three.
	ff.set(10, 8<<20)
	ticks <- time.Now()
	select {
	case <-breaches:
	case <-time.After(2 * time.Second):
		t.Fatal("onBreach did not fire after three consecutive over-limit samples")
	}
}

// TestWithBreachSamplesClamp pins the clamp: "kill on the first sample" is a
// coherent policy, "kill on zero samples" is not.
func TestWithBreachSamplesClamp(t *testing.T) {
	for _, n := range []int{0, -1} {
		ff := newFakeFootprinter()
		ff.set(10, 8<<20)
		breaches := make(chan uint64, 1)
		s := NewMemorySampler(ff, func() []int { return []int{10} }, 1<<20, func(b uint64) { breaches <- b },
			WithBreachSamples(n))
		ticks := make(chan time.Time)
		go s.loop(context.Background(), ticks)
		ticks <- time.Now()
		select {
		case <-breaches:
		case <-time.After(2 * time.Second):
			t.Fatalf("WithBreachSamples(%d) did not clamp to 1 (no breach on the first over-limit sample)", n)
		}
	}
}
