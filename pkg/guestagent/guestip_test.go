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

package guestagent

import (
	"context"
	"sync"
	"testing"

	guestv1 "k3sm.io/apis/guest/v1"
)

// leasedStatus is the Statusr seam shaped like the guest's own guestStatus: the
// address starts empty and is set once the DHCP client holds a lease, and Status
// RE-READS it every call.
//
// The re-read is the property under test, not an implementation detail.
// guest.proto calls guest_ip "the single live-address authority" and says the
// host re-reads it rather than caching it, so an agent that captured the address
// at construction would make a lease change unobservable — which is the whole
// reason the field exists rather than the host deriving the address itself.
type leasedStatus struct {
	mu sync.Mutex
	ip string
}

func (s *leasedStatus) Status(context.Context) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{Ready: true, GuestIP: s.ip}
}

func (s *leasedStatus) setIP(ip string) {
	s.mu.Lock()
	s.ip = ip
	s.mu.Unlock()
}

// TestHealthReportsTheLeasedAddress is the gate on a vm pod having no transport
// address at all. The guest never configured its interfaces — lo DOWN, eth0 DOWN
// with no address and no routes — so guestStatus.guestIP was never set, Health
// reported an empty guest_ip, and the host's lease watcher had nothing to
// publish for the pod's whole life.
func TestHealthReportsTheLeasedAddress(t *testing.T) {
	st := &leasedStatus{}
	client := testAgent(t, "pod-1", Deps{
		Runner: &fakeRunner{names: []string{"app"}},
		Status: st,
	})
	ctx := context.Background()

	t.Run("empty-before-a-lease-is-held", func(t *testing.T) {
		resp, err := client.Health(ctx, &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		if resp.GetGuestIp() != "" {
			t.Errorf("guest_ip = %q before any lease; the host must not be handed an address the guest does not hold", resp.GetGuestIp())
		}
	})

	t.Run("reported-once-the-lease-is-held", func(t *testing.T) {
		st.setIP("192.168.66.7")
		resp, err := client.Health(ctx, &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		if resp.GetGuestIp() != "192.168.66.7" {
			t.Errorf("guest_ip = %q, want the leased address", resp.GetGuestIp())
		}
	})

	t.Run("a-new-lease-is-observable-on-the-next-call", func(t *testing.T) {
		// The re-read contract: the SAME client and the SAME server, no
		// reconnection, must report the new address.
		st.setIP("192.168.66.9")
		resp, err := client.Health(ctx, &guestv1.HealthRequest{})
		if err != nil {
			t.Fatalf("Health: %v", err)
		}
		if resp.GetGuestIp() != "192.168.66.9" {
			t.Errorf("guest_ip = %q, want the NEW lease; a cached address makes a lease change invisible to the host", resp.GetGuestIp())
		}
	})
}
