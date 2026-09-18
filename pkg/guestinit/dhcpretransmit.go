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

import "time"

// dhcpRetransmitPrefix is the fixed head of the retransmission schedule: the
// waits spent before the client concludes that silence is not a lost packet but
// a segment with nothing on it. The doubling is RFC 2131 §4.1's shape, floored
// at 250ms rather than the RFC's 4s initial retransmission delay because this
// client is not a laptop joining an unknown network — it is a pod's PID 1 on a
// host-owned NAT segment whose server is a local process, so a reply that has
// not arrived in 250ms is a dropped datagram, not a slow one.
var dhcpRetransmitPrefix = []time.Duration{
	250 * time.Millisecond,
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
}

// DHCPRetransmitSchedule returns, in order, the waits one DHCPDISCOVER
// retransmission sequence spends for a total exchange budget of total.
//
// ONE SEND PER WAIT. The caller transmits a DISCOVER, waits the first duration
// for an OFFER, and on silence transmits again and waits the second — a
// retransmission, not a row of identical timeouts. That is the whole point: a
// DHCP solicitation is a UDP broadcast and is entitled to be lost, and a flat
// schedule charges the full per-attempt timeout for the very first loss, on
// every boot that suffers one. Here a lost first DISCOVER is replaced after
// 250ms.
//
// The waits are 250ms, 500ms, 1s, 2s, and then ALL of the remaining budget as
// one final wait. The front-loaded retries are where a lost packet is cheap to
// replace; the final wait absorbs the remainder so a segment with no server on
// it still fails at exactly the same wall-clock point a flat schedule failed at.
// The total is a property of the host's boot deadline, and spending less of it
// is not this function's decision to make.
//
// Invariants, each pinned by the test:
//
//   - The waits sum to exactly total, so the caller's budget is neither
//     overspent nor quietly shortened.
//   - Every wait is strictly positive, and the sequence is finite: at most one
//     more than the fixed prefix.
//   - The first wait is 250ms whenever the budget can afford it.
//   - A total too small for the whole prefix DEGRADES BY TRUNCATION: a prefix
//     step is taken only while the budget is strictly larger than it, and
//     whatever is left becomes the final wait. So 700ms is 250ms + 450ms, and
//     any budget at or below the first step is a single wait of the whole
//     budget — never a zero-length wait that would send and not listen.
//   - A total of zero or less returns no waits at all: a caller with no budget
//     must not send even once and then claim it waited.
//
// It reads no clock. The schedule is a function of the budget alone, which is
// what lets it be a table test on a darwin host rather than a timing test
// inside a VM no unit test boots.
func DHCPRetransmitSchedule(total time.Duration) []time.Duration {
	if total <= 0 {
		return nil
	}
	out := make([]time.Duration, 0, len(dhcpRetransmitPrefix)+1)
	left := total
	for _, step := range dhcpRetransmitPrefix {
		// Strictly larger, not at-least: a step equal to the whole remainder
		// would leave a final wait of zero, which is a send with no listen.
		if left <= step {
			break
		}
		out = append(out, step)
		left -= step
	}
	return append(out, left)
}
