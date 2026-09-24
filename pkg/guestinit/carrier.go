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
	"fmt"
	"time"
)

// CarrierBound is how long the guest waits for its link to report carrier
// before sending the first DHCPDISCOVER anyway, and CarrierPoll is how often
// it asks. The observed wait on the macOS NAT attachment is 1–2 ms: the host
// attaches the device's port a moment after the guest has set the link up,
// and a solicitation sent in that gap is dropped by the guest kernel itself
// (tx_dropped, never on the wire), which is the whole reason for the wait.
//
// The bound is small on purpose: it is the price of a link that never
// reports carrier, and must stay far below the retransmission schedule's
// first wait. A link with no host behind it at all is that schedule's case,
// not this wait's, which is why running out of bound is reported and not
// fatal. The reader must be the driver's carrier bit itself, not IFF_RUNNING,
// which the kernel derives from it tens of milliseconds later.
const (
	CarrierBound = 25 * time.Millisecond
	CarrierPoll  = time.Millisecond
)

// ErrNoCarrier reports that the link had not reported carrier when the bound
// ran out. Compare with errors.Is.
var ErrNoCarrier = errors.New("guestinit: link reported no carrier within the bound")

// AwaitCarrier polls running until it reports true, sleeping step between
// polls through sleep, and gives up with ErrNoCarrier once the sleeps would
// exceed bound.
//
// Invariants, each pinned by the test through the recorded sleeper:
//
//   - The first read happens before any sleep, so a link that is already up
//     costs no wait at all.
//   - The total slept never exceeds bound: with step s and bound b it sleeps
//     at most floor(b/s) times, reading the flags once more after the last.
//   - A bound of zero or less, or a step of zero or less, means one read and
//     no sleep: a caller that cannot wait still learns the answer.
//   - A reader error ends the wait at once with that error; the caller
//     decides what a link it cannot read means.
//
// It reads no clock and owns no timer. The decision is a function of the
// flag sequence and the two durations, which is what lets it be a table test
// on a darwin host: the sysfs read of the carrier bit lives in the Linux-only
// guest init, and this is everything that init does with the answer.
func AwaitCarrier(running func() (bool, error), bound, step time.Duration, sleep func(time.Duration)) error {
	sleeps := 0
	if bound > 0 && step > 0 {
		sleeps = int(bound / step)
	}
	for {
		up, err := running()
		if err != nil {
			return fmt.Errorf("read link flags: %w", err)
		}
		if up {
			return nil
		}
		if sleeps == 0 {
			return ErrNoCarrier
		}
		sleep(step)
		sleeps--
	}
}
