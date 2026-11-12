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

package image

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLeaseExpiryBoundary pins the expiry rule at its edge: a lease whose
// expiry is exactly now is still live, and one nanosecond later it is gone,
// through both leaseHas and leasedDigests.
func TestLeaseExpiryBoundary(t *testing.T) {
	const d = "sha256:boundary"
	ttl := time.Minute
	tests := []struct {
		name   string
		offset time.Duration // clock offset from the lease's expiry instant
		live   bool
	}{
		{"before expiry", -time.Nanosecond, true},
		{"exactly at expiry", 0, true},
		{"one nanosecond after expiry", time.Nanosecond, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newGCFixture(t)
			start := f.clock
			f.cache.AcquireLease([]string{d}, ttl)
			f.clock = start.Add(ttl + tc.offset)

			if got := f.cache.leaseHas(d); got != tc.live {
				t.Errorf("leaseHas = %v, want %v", got, tc.live)
			}
			if got := f.cache.leasedDigests()[d]; got != tc.live {
				t.Errorf("leasedDigests has it = %v, want %v", got, tc.live)
			}
		})
	}
}

// TestLeaseConcurrentUse drives acquire, release and both readers on
// overlapping digests so -race can check the lease table, then asserts that
// once every lease is released nothing is leased.
func TestLeaseConcurrentUse(t *testing.T) {
	f := newGCFixture(t)
	c := f.cache
	digests := []string{"sha256:a", "sha256:b", "sha256:c"}
	const iterations = 200

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range iterations {
				l := c.AcquireLease([]string{digests[(g+i)%3], digests[(g+i+1)%3]}, time.Hour)
				_ = c.leaseHas(digests[i%3])
				l.Release()
				l.Release() // idempotent
			}
		}()
		go func() {
			defer wg.Done()
			for i := range iterations {
				_ = c.leaseHas(digests[i%3])
				_ = c.leasedDigests()
			}
		}()
	}
	wg.Wait()

	if got := c.leasedDigests(); len(got) != 0 {
		t.Errorf("leasedDigests after all releases = %v, want empty", got)
	}
	for _, d := range digests {
		if c.leaseHas(d) {
			t.Errorf("leaseHas(%q) after all releases, want false", d)
		}
	}
}

// TestLeaseOutlivesItsTTLWhileThePullRuns pins renewal: a lease kept alive by
// arriving bytes outlives its TTL, lapses one TTL after the last renewal, is
// throttled to one renewal per quarter TTL, is never revived once lapsed or
// released, and never passes a set maxEnd.
func TestLeaseOutlivesItsTTLWhileThePullRuns(t *testing.T) {
	const d = "sha256:renew"
	ttl := time.Minute
	quarter := ttl / 4

	t.Run("renewed every quarter TTL is held at three TTLs", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		for f.clock.Before(start.Add(3 * ttl)) {
			f.clock = f.clock.Add(quarter)
			l.Renew()
		}
		if !f.cache.leaseHas(d) {
			t.Fatalf("lease lapsed at three TTLs despite renewals")
		}
		last := f.clock
		f.clock = last.Add(ttl)
		if !f.cache.leaseHas(d) {
			t.Errorf("lease lapsed before one TTL after the last renewal")
		}
		f.clock = last.Add(ttl + time.Nanosecond)
		if f.cache.leaseHas(d) {
			t.Errorf("lease still held past one TTL after the last renewal")
		}
	})

	t.Run("no renewal lapses at TTL", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(ttl + time.Nanosecond)
		if f.cache.leaseHas(d) {
			t.Errorf("unrenewed lease held past its TTL")
		}
	})

	t.Run("renew inside the throttle window does not move expiry", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(quarter - time.Nanosecond)
		l.Renew()
		if got, want := l.expires, start.Add(ttl); !got.Equal(want) {
			t.Errorf("expires after throttled Renew = %v, want %v", got, want)
		}
		f.clock = start.Add(quarter)
		l.Renew()
		if got, want := l.expires, start.Add(quarter+ttl); !got.Equal(want) {
			t.Errorf("expires after Renew past the window = %v, want %v", got, want)
		}
	})

	t.Run("renew after lapse is a no-op", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(ttl + time.Nanosecond)
		l.Renew() // lapsed but not yet swept
		if f.cache.leaseHas(d) {
			t.Errorf("Renew revived a lapsed lease")
		}
		if n := leaseCount(f.cache); n != 0 {
			t.Errorf("lease table has %d entries, want 0", n)
		}
	})

	t.Run("renew after release is a no-op", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		l.Release()
		f.clock = start.Add(quarter)
		l.Renew()
		if f.cache.leaseHas(d) {
			t.Errorf("Renew revived a released lease")
		}
		if n := leaseCount(f.cache); n != 0 {
			t.Errorf("lease table has %d entries, want 0", n)
		}
	})

	t.Run("nil lease", func(t *testing.T) {
		var l *Lease
		l.Renew()
		(&Lease{}).Renew()
		if _, err := l.Reader(strings.NewReader("x")).Read(make([]byte, 1)); err != nil {
			t.Errorf("Read through a nil lease's reader: %v", err)
		}
	})

	t.Run("maxEnd caps renewal", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		maxEnd := start.Add(2 * ttl)
		l.maxEnd = maxEnd
		for f.clock.Before(start.Add(3 * ttl)) {
			f.clock = f.clock.Add(quarter)
			l.Renew()
		}
		if f.cache.leaseHas(d) {
			t.Errorf("lease held past maxEnd")
		}
		f2 := newGCFixture(t)
		l2 := f2.cache.AcquireLease([]string{d}, ttl)
		l2.maxEnd = f2.clock.Add(2 * ttl)
		start2 := f2.clock
		f2.clock = start2.Add(3 * quarter)
		l2.Renew() // expires at 1.75 TTL, under the cap
		f2.clock = start2.Add(6 * quarter)
		l2.Renew() // would be 2.5 TTL; capped at 2 TTL
		if got, want := l2.expires, l2.maxEnd; !got.Equal(want) {
			t.Errorf("expires = %v, want capped at maxEnd %v", got, want)
		}
		f2.clock = l2.maxEnd
		if !f2.cache.leaseHas(d) {
			t.Errorf("lease lapsed before maxEnd")
		}
		f2.clock = l2.maxEnd.Add(time.Nanosecond)
		if f2.cache.leaseHas(d) {
			t.Errorf("lease held past maxEnd")
		}
	})

	t.Run("reader renews on bytes, not on a zero-byte read", func(t *testing.T) {
		f := newGCFixture(t)
		start := f.clock
		l := f.cache.AcquireLease([]string{d}, ttl)
		f.clock = start.Add(quarter)
		if n, _ := l.Reader(strings.NewReader("")).Read(make([]byte, 1)); n != 0 {
			t.Fatalf("empty read returned %d bytes", n)
		}
		if got, want := l.expires, start.Add(ttl); !got.Equal(want) {
			t.Errorf("zero-byte read moved expires to %v, want %v", got, want)
		}
		if n, _ := l.Reader(strings.NewReader("abc")).Read(make([]byte, 3)); n != 3 {
			t.Fatalf("read returned %d bytes, want 3", n)
		}
		if got, want := l.expires, start.Add(quarter+ttl); !got.Equal(want) {
			t.Errorf("read of bytes left expires at %v, want %v", got, want)
		}
	})
}

// leaseCount returns the size of the lease table.
func leaseCount(c *Cache) int {
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	return len(c.leases)
}
