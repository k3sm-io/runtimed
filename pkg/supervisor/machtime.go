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
	"math/bits"
)

// MachTimebase is the mach_timebase_info(3) ratio that converts MACH absolute
// TIME UNITS to nanoseconds: nanos = ticks * Numer / Denom.
//
// It is a first-class (pure, injectable) type because getting it wrong is the
// classic Apple-Silicon CPU-accounting bug, and the bug is INVISIBLE on Intel.
// proc_pid_rusage's ri_user_time / ri_system_time are not nanoseconds: XNU's
// fill_task_rusage copies task_power_info's total_user / total_system straight
// out of the task's thread timers, which accumulate in mach absolute time units
// (bsd/kern/kern_resource.c). On x86_64 the timebase is 1/1, so the raw value
// happens to equal nanoseconds and no conversion is needed; on Apple Silicon the
// timebase is 125/3 (a 24 MHz counter), so an unconverted reading UNDERCOUNTS CPU
// by ~41.67x. Measured on an M-series host: 1.001 s of busy-looped CPU produced a
// raw ri_user_time+ri_system_time delta of 24 023 155 — 0.024 "seconds" read raw,
// 1.001 seconds once scaled by 125/3.
//
// The type therefore exists to be faked: unit tests pin the conversion against a
// synthetic Apple-Silicon timebase on any host, so the scaling cannot silently
// regress to the identity that happens to be right on x86_64.
type MachTimebase struct {
	// Numer / Denom are mach_timebase_info_data_t.numer / .denom verbatim.
	Numer uint32
	Denom uint32
}

// Valid reports whether tb is a usable ratio. A zero Denom (or a zero Numer)
// means mach_timebase_info was never read, or failed; converting with it would
// silently report zero CPU forever, so callers must reject it rather than fall
// back to an identity that is only correct on x86_64.
func (tb MachTimebase) Valid() bool { return tb.Numer > 0 && tb.Denom > 0 }

// Nanos converts a mach-absolute-time tick count to nanoseconds.
//
// The arithmetic is exact and overflow-safe: ticks*Numer is computed in 128 bits
// (bits.Mul64) and divided in 128 bits (bits.Div64), because a cumulative CPU
// counter scaled by 125 overflows uint64 well before the counter itself does.
// Division truncates, which is right for a monotone cumulative counter — it can
// never make a later sample smaller than an earlier one.
//
// An invalid timebase converts to 0 (see Valid): the caller is expected to have
// rejected it already, and reporting zero is preferable to reporting a number
// scaled by a ratio nobody read.
func (tb MachTimebase) Nanos(ticks uint64) uint64 {
	if !tb.Valid() {
		return 0
	}
	if tb.Numer == tb.Denom {
		return ticks
	}
	hi, lo := bits.Mul64(ticks, uint64(tb.Numer))
	if hi >= uint64(tb.Denom) {
		// The quotient would not fit in 64 bits. Unreachable for any real CPU
		// counter (it needs ~10^11 core-years), but bits.Div64 PANICS on
		// overflow, so saturate rather than take a library panic.
		return math.MaxUint64
	}
	q, _ := bits.Div64(hi, lo, uint64(tb.Denom))
	return q
}
