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
	"syscall"
	"time"
)

// AwaitReply reads datagrams through recv until one is a reply to this
// exchange (xid and mac) that want accepts, or budget is spent. A NAK ends the
// round at once: the server has refused, and waiting out the budget would only
// delay the retransmission. Replies to other exchanges and malformed datagrams
// are skipped, not failed.
//
// recv fills buf and reports the datagram length; remaining is the time the
// round still has, so a socket-backed recv can set its receive timeout to it.
// An EINTR from recv is read again within the same budget: SO_RCVTIMEO makes a
// read return EINTR for any handled signal regardless of SA_RESTART (signal(7)),
// and the Go runtime handles signals of its own — its preemption signal, SIGURG,
// arrives on the runtime's schedule — so the interruption happens with nothing
// spawned and no SIGCHLD in flight. The datagram, if one arrived, is still
// queued, and counting the round as unanswered would retransmit a DISCOVER whose
// OFFER is already waiting.
//
// It owns no socket and no timer: the receive and the clock are the caller's,
// which is what makes the retry a table test on a darwin host while the
// Linux-only guest init supplies the real socket.
func AwaitReply(recv func(buf []byte, remaining time.Duration) (int, error), xid uint32, mac []byte, want func(byte) bool, budget time.Duration, now func() time.Time) (Lease, error) {
	if budget <= 0 {
		return Lease{}, fmt.Errorf("%w: the exchange's budget is spent", ErrDHCP)
	}
	deadline := now().Add(budget)
	buf := make([]byte, dhcpMaxLen)
	for {
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return Lease{}, fmt.Errorf("%w: no reply within %s", ErrDHCP, budget)
		}
		n, err := recv(buf, remaining)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return Lease{}, fmt.Errorf("%w: receive: %w", ErrDHCP, err)
		}
		msgType, lease, ok, perr := ParseReply(buf[:n], xid, mac)
		if perr != nil || !ok {
			continue // not ours, or malformed: keep waiting for the real one
		}
		if IsNak(msgType) {
			return Lease{}, fmt.Errorf("%w: the server sent DHCPNAK", ErrDHCP)
		}
		if want(msgType) {
			return lease, nil
		}
	}
}
