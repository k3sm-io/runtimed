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
	"errors"
	"testing"
	"time"
)

// TestAwaitCarrier pins the wait's decision logic as a table over the flag
// sequence: no clock, a scripted reader, and a recorded sleeper that is the
// only witness of how long the wait took.
func TestAwaitCarrier(t *testing.T) {
	const ms = time.Millisecond
	readErr := errors.New("SIOCGIFFLAGS: no such device")

	for _, tc := range []struct {
		name       string
		flags      []bool // one entry per read; the last entry repeats
		readErrAt  int    // 1-based read that fails; 0 never
		bound      time.Duration
		step       time.Duration
		wantSleeps int
		wantErr    error
	}{
		{
			name:  "carrier already up costs no sleep",
			flags: []bool{true},
			bound: 25 * ms, step: ms,
			wantSleeps: 0,
		},
		{
			name:  "carrier arrives after two polls",
			flags: []bool{false, false, true},
			bound: 25 * ms, step: ms,
			wantSleeps: 2,
		},
		{
			name:  "carrier never arrives: sleeps exactly the bound, then gives up",
			flags: []bool{false},
			bound: 25 * ms, step: ms,
			wantSleeps: 25,
			wantErr:    ErrNoCarrier,
		},
		{
			name:  "carrier on the read after the last sleep still counts",
			flags: []bool{false, false, false, true},
			bound: 3 * ms, step: ms,
			wantSleeps: 3,
		},
		{
			name:  "a bound that is not a multiple of the step rounds down",
			flags: []bool{false},
			bound: 5 * ms, step: 2 * ms,
			wantSleeps: 2,
			wantErr:    ErrNoCarrier,
		},
		{
			name:  "no bound means one read and no sleep",
			flags: []bool{false},
			bound: 0, step: ms,
			wantSleeps: 0,
			wantErr:    ErrNoCarrier,
		},
		{
			name:  "no step means one read and no sleep",
			flags: []bool{false},
			bound: 25 * ms, step: 0,
			wantSleeps: 0,
			wantErr:    ErrNoCarrier,
		},
		{
			name:      "a reader error ends the wait with the sleeps so far",
			flags:     []bool{false, false},
			readErrAt: 3,
			bound:     25 * ms, step: ms,
			wantSleeps: 2,
			wantErr:    readErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			running := func() (bool, error) {
				reads++
				if tc.readErrAt != 0 && reads == tc.readErrAt {
					return false, readErr
				}
				i := reads - 1
				if i >= len(tc.flags) {
					i = len(tc.flags) - 1
				}
				return tc.flags[i], nil
			}
			var slept []time.Duration
			sleep := func(d time.Duration) { slept = append(slept, d) }

			err := AwaitCarrier(running, tc.bound, tc.step, sleep)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			sleeps := len(slept)
			if sleeps != tc.wantSleeps {
				t.Fatalf("sleeps = %d, want %d", sleeps, tc.wantSleeps)
			}
			var total time.Duration
			for _, d := range slept {
				if d != tc.step {
					t.Fatalf("slept %s, want every sleep to be the step %s", d, tc.step)
				}
				total += d
			}
			if total > tc.bound {
				t.Fatalf("slept %s in total, over the bound %s", total, tc.bound)
			}
			if reads != sleeps+1 {
				t.Fatalf("reads = %d, want one more than the sleeps (%d): the first read precedes any sleep and one read follows the last", reads, sleeps+1)
			}
		})
	}
}
