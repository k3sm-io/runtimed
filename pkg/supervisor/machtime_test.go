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
	"math"
	"testing"
)

// TestMachTimebaseNanos pins the mach-absolute-time → nanosecond conversion with
// FAKED timebases, which is the whole reason MachTimebase is a value type.
//
// The bug this guards is the classic one: proc_pid_rusage's ri_user_time /
// ri_system_time are mach absolute time units, and on x86_64 the timebase is 1/1,
// so an implementation that forgets to scale is INDISTINGUISHABLE from a correct
// one on an Intel host — and undercounts CPU by ~41.67x on Apple Silicon, whose
// timebase is 125/3. Driving the conversion from an injected ratio means this
// test fails on any host if the scaling is dropped.
func TestMachTimebaseNanos(t *testing.T) {
	const (
		appleSiliconNumer = 125 // measured on an M-series host: mach_timebase_info
		appleSiliconDenom = 3   // returns numer=125 denom=3 (a 24 MHz counter)
	)
	tests := []struct {
		name  string
		tb    MachTimebase
		ticks uint64
		want  uint64
	}{
		{
			// The measured probe: 1.001 s of busy-looped CPU on an M-series host
			// produced a raw ri_user_time+ri_system_time delta of 24 023 155. Read
			// raw that is 0.024 "seconds"; scaled it is 1.000 964 791 s.
			name:  "apple silicon 125/3 scales a measured one-second sample",
			tb:    MachTimebase{Numer: appleSiliconNumer, Denom: appleSiliconDenom},
			ticks: 24023155,
			want:  1000964791,
		},
		{
			name:  "apple silicon 125/3 exact multiple",
			tb:    MachTimebase{Numer: appleSiliconNumer, Denom: appleSiliconDenom},
			ticks: 24, // 24 * 125 / 3 = 1000 ns
			want:  1000,
		},
		{
			// The x86_64 identity ratio — the case that hides the bug.
			name:  "intel 1/1 is the identity",
			tb:    MachTimebase{Numer: 1, Denom: 1},
			ticks: 24023155,
			want:  24023155,
		},
		{
			name:  "zero ticks stay zero",
			tb:    MachTimebase{Numer: appleSiliconNumer, Denom: appleSiliconDenom},
			ticks: 0,
			want:  0,
		},
		{
			// Truncation must round DOWN, never up: the value is a monotone
			// cumulative counter, and rounding up could make a later sample of an
			// unchanged counter differ from an earlier one.
			name:  "truncates toward zero",
			tb:    MachTimebase{Numer: appleSiliconNumer, Denom: appleSiliconDenom},
			ticks: 1, // 125/3 = 41.666… → 41
			want:  41,
		},
		{
			// ticks*125 overflows uint64 long before ticks does; the 128-bit path
			// must produce the exact quotient, not a wrapped one.
			name:  "no 64-bit overflow in the intermediate product",
			tb:    MachTimebase{Numer: appleSiliconNumer, Denom: appleSiliconDenom},
			ticks: 200000000000000000,  // ticks*125 = 2.5e19 > MaxUint64
			want:  8333333333333333333, // (2e17 * 125) / 3, exact
		},
		{
			name:  "saturates instead of panicking when the quotient cannot fit",
			tb:    MachTimebase{Numer: 1000, Denom: 1},
			ticks: math.MaxUint64,
			want:  math.MaxUint64,
		},
		{
			// An unread timebase must NOT silently behave like 1/1 — that is the
			// wrong answer everywhere except x86_64.
			name:  "invalid timebase converts to zero, not the identity",
			tb:    MachTimebase{Numer: 0, Denom: 0},
			ticks: 24023155,
			want:  0,
		},
		{
			name:  "zero denominator converts to zero",
			tb:    MachTimebase{Numer: 125, Denom: 0},
			ticks: 24023155,
			want:  0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tb.Nanos(tc.ticks); got != tc.want {
				t.Errorf("MachTimebase{%d/%d}.Nanos(%d) = %d, want %d",
					tc.tb.Numer, tc.tb.Denom, tc.ticks, got, tc.want)
			}
		})
	}
}

// TestMachTimebaseNanosMonotone is the property the metrics-server consumer
// depends on: a cumulative CPU counter scaled through the timebase must never go
// backwards, because metrics-server computes CPU as a RATE over two samples and
// rejects a pair whose later cumulative value is smaller.
func TestMachTimebaseNanosMonotone(t *testing.T) {
	tb := MachTimebase{Numer: 125, Denom: 3}
	var prev uint64
	for ticks := uint64(0); ticks < 5000; ticks += 7 {
		got := tb.Nanos(ticks)
		if got < prev {
			t.Fatalf("Nanos(%d) = %d < previous %d — conversion is not monotone", ticks, got, prev)
		}
		prev = got
	}
}

// TestMachTimebaseValid pins the guard that keeps an unread ratio from being
// treated as usable.
func TestMachTimebaseValid(t *testing.T) {
	tests := []struct {
		tb   MachTimebase
		want bool
	}{
		{MachTimebase{Numer: 125, Denom: 3}, true},
		{MachTimebase{Numer: 1, Denom: 1}, true},
		{MachTimebase{}, false},
		{MachTimebase{Numer: 125}, false},
		{MachTimebase{Denom: 3}, false},
	}
	for _, tc := range tests {
		if got := tc.tb.Valid(); got != tc.want {
			t.Errorf("MachTimebase{%d/%d}.Valid() = %v, want %v", tc.tb.Numer, tc.tb.Denom, got, tc.want)
		}
	}
}
