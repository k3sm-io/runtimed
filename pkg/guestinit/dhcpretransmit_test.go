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

package guestinit

import (
	"testing"
	"time"
)

// TestDHCPRetransmitSchedule pins the schedule itself, because the schedule IS
// the behaviour: the executor that spends it is linux-only and unreachable from
// any test this repo runs, so an exact-sequence assertion here is the only place
// a wrong wait can be caught. The case that matters operationally is the first
// one — the shipped 12s budget must begin with a 250ms retry, since a flat first
// wait is exactly the cost a lost first DISCOVER used to charge every boot.
func TestDHCPRetransmitSchedule(t *testing.T) {
	const ms = time.Millisecond

	for _, tc := range []struct {
		name  string
		total time.Duration
		want  []time.Duration
	}{
		{
			name:  "the shipped twelve-second budget retransmits five times",
			total: 12 * time.Second,
			want:  []time.Duration{250 * ms, 500 * ms, 1000 * ms, 2000 * ms, 8250 * ms},
		},
		{
			name:  "a budget of exactly the fixed prefix ends on the prefix",
			total: 3750 * ms,
			want:  []time.Duration{250 * ms, 500 * ms, 1000 * ms, 2000 * ms},
		},
		{
			name:  "a budget that runs out mid-prefix truncates and absorbs the rest",
			total: 1000 * ms,
			want:  []time.Duration{250 * ms, 500 * ms, 250 * ms},
		},
		{
			name:  "a sub-prefix budget keeps the first step and absorbs the rest",
			total: 700 * ms,
			want:  []time.Duration{250 * ms, 450 * ms},
		},
		{
			name:  "a budget equal to the first step is one wait, never a zero second one",
			total: 250 * ms,
			want:  []time.Duration{250 * ms},
		},
		{
			name:  "a budget below the first step is one wait of the whole budget",
			total: 100 * ms,
			want:  []time.Duration{100 * ms},
		},
		{
			name:  "no budget sends nothing",
			total: 0,
			want:  nil,
		},
		{
			name:  "a negative budget sends nothing",
			total: -5 * time.Second,
			want:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DHCPRetransmitSchedule(tc.total)
			if len(got) != len(tc.want) {
				t.Fatalf("schedule(%s) = %v (%d waits), want %v (%d waits)",
					tc.total, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("schedule(%s)[%d] = %s, want %s (full: %v)",
						tc.total, i, got[i], tc.want[i], got)
				}
			}
		})
	}

	// The invariants, over budgets chosen to straddle every prefix boundary as
	// well as the values the caller actually passes. A schedule that sums to
	// less than the budget fails the boot early; one that sums to more pushes
	// the guest past the host's deadline on Health, which the host reports as a
	// dead pod rather than a slow one.
	t.Run("invariants", func(t *testing.T) {
		for _, total := range []time.Duration{
			1, 99 * ms, 250 * ms, 251 * ms, 749 * ms, 750 * ms, 751 * ms,
			1749 * ms, 1750 * ms, 1751 * ms, 3749 * ms, 3750 * ms, 3751 * ms,
			4 * time.Second, 12 * time.Second, 30 * time.Second, time.Hour,
		} {
			got := DHCPRetransmitSchedule(total)
			if len(got) == 0 {
				t.Errorf("schedule(%s) is empty; a positive budget must buy at least one wait", total)
				continue
			}
			if len(got) > len(dhcpRetransmitPrefix)+1 {
				t.Errorf("schedule(%s) has %d waits, want at most %d; the sequence must terminate",
					total, len(got), len(dhcpRetransmitPrefix)+1)
			}
			var sum time.Duration
			for i, w := range got {
				if w <= 0 {
					t.Errorf("schedule(%s)[%d] = %s, want a strictly positive wait", total, i, w)
				}
				sum += w
			}
			if sum != total {
				t.Errorf("schedule(%s) sums to %s, want exactly %s (%v)", total, sum, total, got)
			}
			if total > dhcpRetransmitPrefix[0] && got[0] != dhcpRetransmitPrefix[0] {
				t.Errorf("schedule(%s) starts with %s, want %s: the first retry is what a lost DISCOVER costs",
					total, got[0], dhcpRetransmitPrefix[0])
			}
		}
	})
}
