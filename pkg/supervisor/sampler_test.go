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
	// can only do AFTER finishing the first tick's sampleOnce (the loop is serial).
	ticks <- time.Now()
	ticks <- time.Now()

	if got := s.Last(); got != 150 {
		t.Errorf("Last() = %d, want 150 (sum of 100+50)", got)
	}
}

// TestMemorySamplerOOMBreachFiresOnce proves the OOM path: the summed footprint
// exceeding the limit fires onBreach exactly once, Last() tracks the sample, and
// the loop stops (Done closes) on ctx cancel — the no-goroutine-leak signal.
func TestMemorySamplerOOMBreachFiresOnce(t *testing.T) {
	ff := newFakeFootprinter()
	ff.set(10, 8<<20)     // 8 MiB, over the limit
	const limit = 1 << 20 // 1 MiB

	breaches := make(chan uint64, 8)
	s := NewMemorySampler(ff, func() []int { return []int{10} }, limit, func(b uint64) { breaches <- b })

	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	go s.loop(ctx, ticks)

	ticks <- time.Now() // breach
	select {
	case b := <-breaches:
		if b <= limit {
			t.Errorf("onBreach footprint = %d, want > limit %d", b, limit)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("onBreach did not fire on a memory-limit breach")
	}

	// Further ticks must NOT re-fire onBreach (once-only).
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
