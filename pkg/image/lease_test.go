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
