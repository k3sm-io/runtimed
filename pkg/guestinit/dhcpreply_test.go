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
	"syscall"
	"testing"
	"time"
)

// TestAwaitReply pins the receive loop's decisions as a table over a scripted
// receiver and a stepping clock: what an interrupted read, a foreign reply, a
// NAK, a receive error and a spent budget each do to the round.
func TestAwaitReply(t *testing.T) {
	const xid = 0x6b33a1c4
	const ms = time.Millisecond
	full := map[byte][]byte{1: ip4("255.255.255.0"), 3: ip4("192.168.66.1"), 51: {0, 0, 0x0e, 0x10}}
	offer := serverReply(xid, testMAC, dhcpOffer, "192.168.66.7", full)
	ack := serverReply(xid, testMAC, dhcpAck, "192.168.66.7", full)
	nak := serverReply(xid, testMAC, dhcpNak, "", nil)
	foreign := serverReply(0x55667788, testMAC, dhcpOffer, "192.168.66.9", full)
	eio := errors.New("read: input/output error")

	type read struct {
		msg []byte
		err error
	}
	for _, tc := range []struct {
		name      string
		reads     []read // one per recv call; the last repeats
		tick      time.Duration
		budget    time.Duration
		want      func(byte) bool
		wantCalls int
		wantErr   error
		wantAddr  string
	}{
		{
			name:  "an interrupted read is read again within the same round",
			reads: []read{{err: syscall.EINTR}, {msg: offer}},
			tick:  ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 2, wantAddr: "192.168.66.7",
		},
		{
			name:  "interrupted reads stop when the budget is spent",
			reads: []read{{err: syscall.EINTR}},
			tick:  100 * ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 3, wantErr: ErrDHCP,
		},
		{
			name:  "another exchange's reply is skipped, not failed",
			reads: []read{{msg: foreign}, {msg: offer}},
			tick:  ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 2, wantAddr: "192.168.66.7",
		},
		{
			name:  "a reply of the wrong type is waited past",
			reads: []read{{msg: ack}, {msg: offer}},
			tick:  ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 2, wantAddr: "192.168.66.7",
		},
		{
			name:  "a NAK ends the round at once",
			reads: []read{{msg: nak}, {msg: offer}},
			tick:  ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 1, wantErr: ErrDHCP,
		},
		{
			name:  "a receive error other than EINTR fails the round",
			reads: []read{{err: eio}, {msg: offer}},
			tick:  ms, budget: 250 * ms, want: IsOffer,
			wantCalls: 1, wantErr: eio,
		},
		{
			name:  "a spent budget is refused before any read",
			reads: []read{{msg: offer}},
			tick:  ms, budget: 0, want: IsOffer,
			wantCalls: 0, wantErr: ErrDHCP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := time.Unix(1_700_000_000, 0)
			now := func() time.Time { return clock }
			calls := 0
			recv := func(buf []byte, remaining time.Duration) (int, error) {
				if remaining <= 0 {
					t.Fatalf("recv %d called with remaining=%s", calls+1, remaining)
				}
				r := tc.reads[min(calls, len(tc.reads)-1)]
				calls++
				clock = clock.Add(tc.tick)
				if r.err != nil {
					return 0, r.err
				}
				return copy(buf, r.msg), nil
			}
			lease, err := AwaitReply(recv, xid, testMAC, tc.want, tc.budget, now)
			if calls != tc.wantCalls {
				t.Errorf("recv called %d times, want %d", calls, tc.wantCalls)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want a lease", err)
			}
			if got := lease.Address.String(); got != tc.wantAddr {
				t.Errorf("lease address = %s, want %s", got, tc.wantAddr)
			}
		})
	}
}
