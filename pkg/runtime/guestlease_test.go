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

package runtime

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- fakes ----------------------------------------------------------------

// guestLeaseAgent is a real guest/v1 GuestAgent server answering the ONE verb
// the lease watcher rides on — Health — over the same bufconn+gRPC round trip
// startFakeGuestAgent gives every other guest route. There is no VM, no vmhost
// and no vsock anywhere in this file: only the SOCKET is replaced.
//
// It is SCRIPTABLE mid-test (set), which is what makes a renewal and a lease
// loss observable as a change in what one running watcher publishes rather than
// as two separately-constructed fixtures.
type guestLeaseAgent struct {
	guestv1.UnimplementedGuestAgentServer

	mu    sync.Mutex
	ip    string
	ready bool
	err   error
	calls int
}

func (a *guestLeaseAgent) Health(_ context.Context, _ *guestv1.HealthRequest) (*guestv1.HealthResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	return &guestv1.HealthResponse{Ready: a.ready, GuestIp: a.ip}, nil
}

func (a *guestLeaseAgent) set(ip string, err error) {
	a.mu.Lock()
	a.ip, a.err = ip, err
	a.mu.Unlock()
}

func (a *guestLeaseAgent) healthCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// leaseRuntime builds a Runtime whose guest dialer reaches agent, polling fast
// enough that a lease transition lands in milliseconds. The interval is a field
// (Runtime.guestLeasePoll) precisely so a test need not wait out the production
// five-second cadence.
func leaseRuntime(t *testing.T, agent guestv1.GuestAgentServer) *Runtime {
	t.Helper()
	dial, _ := startFakeGuestAgent(t, agent)
	rt := newTestRuntime(t, Deps{GuestDialer: dial})
	rt.guestLeasePoll = time.Millisecond
	return rt
}

// leaseOf reads a pod's published transport address the way a consumer does —
// off a rendered PodStatus, not off the struct field.
func leaseOf(t *testing.T, rt *Runtime, podID string) string {
	t.Helper()
	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: podID})
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	return gs.GetStatus().GetGuestTransportAddress()
}

// --- the validator --------------------------------------------------------

// TestGuestLeaseValidationRejectsHostileValues is the untrusted-input half of
// B237. The guest agent's guest_ip is attacker-chosen whenever the workload is
// (guest.proto §TRUST), so the table below is the full statement of what the
// host will and will not stamp onto PodStatus.guest_transport_address.
func TestGuestLeaseValidationRejectsHostileValues(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    string
		want   string
		reason string
	}{
		// The vm/NAT family: what a guest on the macOS vmnet segment leases.
		{"vmnet-lease", "192.168.64.7", "192.168.64.7", guestLeaseReasonValid},
		{"rfc1918-10", "10.0.5.9", "10.0.5.9", guestLeaseReasonValid},
		{"rfc1918-172", "172.16.3.4", "172.16.3.4", guestLeaseReasonValid},
		{"ula-v6", "fd00::2", "fd00::2", guestLeaseReasonValid},
		// A canonical rendering, not the guest's bytes.
		{"v6-uppercase-is-canonicalized", "FD00::0002", "fd00::2", guestLeaseReasonValid},

		// No lease yet is the normal pre-DHCP state, not a fault.
		{"empty", "", "", guestLeaseReasonAbsent},

		// Out of family: the whole point of the predicate.
		{"loopback-v4", "127.0.0.1", "", guestLeaseReasonOutOfFamily},
		{"loopback-v6", "::1", "", guestLeaseReasonOutOfFamily},
		{"unspecified-v4", "0.0.0.0", "", guestLeaseReasonOutOfFamily},
		{"unspecified-v6", "::", "", guestLeaseReasonOutOfFamily},
		{"multicast-v4", "224.0.0.1", "", guestLeaseReasonOutOfFamily},
		{"multicast-v6", "ff02::1", "", guestLeaseReasonOutOfFamily},
		// 169.254/16 is what a guest self-assigns when DHCP FAILED — the absence
		// of a lease — and it contains the cloud metadata address.
		{"link-local-apipa", "169.254.10.1", "", guestLeaseReasonOutOfFamily},
		{"link-local-metadata", "169.254.169.254", "", guestLeaseReasonOutOfFamily},
		{"link-local-v6", "fe80::1", "", guestLeaseReasonOutOfFamily},
		{"public-v4", "8.8.8.8", "", guestLeaseReasonOutOfFamily},
		{"public-v6", "2001:4860:4860::8888", "", guestLeaseReasonOutOfFamily},
		{"documentation-range", "192.0.2.15", "", guestLeaseReasonOutOfFamily},

		// One spelling only: "::ffff:127.0.0.1" must not smuggle a loopback past
		// a v4-shaped check downstream.
		{"v4-mapped-v6", "::ffff:192.168.64.7", "", guestLeaseReasonV4MappedV6},
		{"v4-mapped-loopback", "::ffff:127.0.0.1", "", guestLeaseReasonV4MappedV6},

		// A zone names a HOST interface; a guest does not get to name one.
		{"zoned", "fd00::2%eth0", "", guestLeaseReasonZoned},

		// One address, nothing else.
		{"with-port", "192.168.64.7:8080", "", guestLeaseReasonUnparsable},
		{"cidr", "192.168.64.0/24", "", guestLeaseReasonUnparsable},
		{"list", "192.168.64.7,192.168.64.8", "", guestLeaseReasonUnparsable},
		{"hostname", "guest.local", "", guestLeaseReasonUnparsable},
		{"leading-zero-octet", "192.168.064.7", "", guestLeaseReasonUnparsable},
		{"junk", "not an address", "", guestLeaseReasonUnparsable},
		{"newline-injection", "192.168.64.7\nnameserver 1.2.3.4", "", guestLeaseReasonUnparsable},

		// Length is checked BEFORE the parser sees the string.
		{"overlong", strings.Repeat("9", maxGuestLeaseBytes+1), "", guestLeaseReasonOverlong},
		{"overlong-address-prefix", "192.168.64.7" + strings.Repeat("0", maxGuestLeaseBytes), "", guestLeaseReasonOverlong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := parseGuestLease(tc.raw)
			if got != tc.want || reason != tc.reason {
				t.Errorf("parseGuestLease(%q) = (%q, %s), want (%q, %s)", tc.raw, got, reason, tc.want, tc.reason)
			}
		})
	}
}

// TestGuestLeaseBackoffIsBoundedAndJittered pins the poll cadence's three
// properties: consecutive failures back off, the backoff is capped so a
// permanently dead agent costs a bounded wakeup rate forever, and no wait is
// the bare interval — without the jitter a node's pods stay phase-locked for
// their whole lives and their vsock round trips arrive as one burst per tick.
func TestGuestLeaseBackoffIsBoundedAndJittered(t *testing.T) {
	const base = time.Second
	const samples = 128
	// jitterBand is the widest a wait may stray from its nominal delay.
	const jitterLo, jitterHi = 0.8, 1.2

	spread := func(fails int) (lo, hi time.Duration) {
		lo, hi = time.Duration(1<<62), 0
		for i := 0; i < samples; i++ {
			d := guestLeaseWait(base, fails)
			if d < lo {
				lo = d
			}
			if d > hi {
				hi = d
			}
		}
		return lo, hi
	}

	nominal := base
	var prevLo time.Duration
	for fails := 0; fails < 12; fails++ {
		lo, hi := spread(fails)
		wantLo := time.Duration(jitterLo * float64(nominal))
		wantHi := time.Duration(jitterHi * float64(nominal))
		if lo < wantLo || hi > wantHi {
			t.Errorf("guestLeaseWait(%v, %d) spread [%v, %v], want within [%v, %v]", base, fails, lo, hi, wantLo, wantHi)
		}
		if lo == hi {
			t.Errorf("guestLeaseWait(%v, %d) never varied (%v): the jitter is not applied", base, fails, lo)
		}
		if nominal < guestLeasePollMaxBackoff && lo <= prevLo {
			t.Errorf("guestLeaseWait(%v, %d) floor %v did not grow past %v", base, fails, lo, prevLo)
		}
		prevLo = lo
		if nominal *= 2; nominal > guestLeasePollMaxBackoff {
			nominal = guestLeasePollMaxBackoff
		}
	}
	// However long the agent stays dead, the wait never leaves the cap's band.
	lo, hi := spread(1_000)
	if lo < time.Duration(jitterLo*float64(guestLeasePollMaxBackoff)) || hi > time.Duration(jitterHi*float64(guestLeasePollMaxBackoff)) {
		t.Errorf("saturated backoff spread [%v, %v], want within the %v cap's band", lo, hi, guestLeasePollMaxBackoff)
	}
}

// --- the watcher ----------------------------------------------------------

// TestGuestLeaseWatcherPublishesTheLiveTransportAddress is the B237 producer
// gate. It asserts the properties a consumer depends on, not merely that a poll
// happened: a first lease reaches PodStatus, a renewal REPLACES it, a lost or
// refused lease EMPTIES it rather than leaving a stale address standing, every
// transition rides the ONE status stream, the watcher stops when the pod does,
// and a host-process pod never gets one at all.
func TestGuestLeaseWatcherPublishesTheLiveTransportAddress(t *testing.T) {
	t.Run("first-lease-stamps-the-field", func(t *testing.T) {
		agent := &guestLeaseAgent{}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		waitFor(t, 2*time.Second, "the guest agent to be polled", func() bool {
			return agent.healthCalls() > 0
		})
		if got := leaseOf(t, rt, "pod-vm"); got != "" {
			t.Fatalf("guest_transport_address = %q before any lease, want empty", got)
		}

		agent.set("192.168.64.7", nil)
		waitFor(t, 2*time.Second, "the first lease to be published", func() bool {
			return leaseOf(t, rt, "pod-vm") == "192.168.64.7"
		})
	})

	t.Run("renewal-replaces-the-address", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		waitFor(t, 2*time.Second, "the first lease", func() bool {
			return leaseOf(t, rt, "pod-vm") == "192.168.64.7"
		})

		agent.set("192.168.64.9", nil)
		waitFor(t, 2*time.Second, "the renewed lease", func() bool {
			return leaseOf(t, rt, "pod-vm") == "192.168.64.9"
		})
	})

	// The stale-address rule, stated three ways. A lease we can no longer
	// confirm may already have been reassigned on the shared NAT segment, so the
	// field goes empty — "no route right now" — rather than aiming a consumer's
	// dial at somebody else's guest.
	for _, tc := range []struct {
		name string
		then func(a *guestLeaseAgent)
	}{
		{"lease-loss-empties-the-field", func(a *guestLeaseAgent) { a.set("", nil) }},
		{"agent-failure-empties-the-field", func(a *guestLeaseAgent) {
			a.set("", status.Error(codes.Unavailable, "guest is gone"))
		}},
		{"hostile-value-empties-the-field", func(a *guestLeaseAgent) { a.set("127.0.0.1", nil) }},
		{"overlong-value-empties-the-field", func(a *guestLeaseAgent) {
			a.set(strings.Repeat("9", maxGuestLeaseBytes+1), nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := &guestLeaseAgent{ip: "192.168.64.7"}
			rt := leaseRuntime(t, agent)
			p := addVMPod(t, rt, "pod-vm", "main")

			rt.armGuestLeaseWatcher(p)
			waitFor(t, 2*time.Second, "the first lease", func() bool {
				return leaseOf(t, rt, "pod-vm") == "192.168.64.7"
			})

			tc.then(agent)
			waitFor(t, 2*time.Second, "the address to be withdrawn", func() bool {
				return leaseOf(t, rt, "pod-vm") == ""
			})
		})
	}

	// An unreachable SOCKET is the case a live agent cannot script: the dial
	// itself fails, so no Health RPC is ever made.
	t.Run("undialable-socket-never-stamps-a-field", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{GuestDialer: func(context.Context, string) (net.Conn, error) {
			return nil, errors.New("no such socket")
		}})
		rt.guestLeasePoll = time.Millisecond
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		time.Sleep(50 * time.Millisecond)
		if got := leaseOf(t, rt, "pod-vm"); got != "" {
			t.Errorf("guest_transport_address = %q with an undialable agent, want empty", got)
		}
	})

	// The field rides the pod's ONE status path: a consumer learns the address
	// from the same PodStatus stream it learns everything else from.
	t.Run("a-change-is-published-to-status-subscribers", func(t *testing.T) {
		agent := &guestLeaseAgent{}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		ch, cancel := rt.broker.subscribe("pod-vm")
		defer cancel()

		rt.armGuestLeaseWatcher(p)
		agent.set("192.168.64.7", nil)

		deadline := time.After(2 * time.Second)
		for {
			select {
			case ev := <-ch:
				if ev.GetType() != runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED {
					t.Fatalf("event type = %v, want MODIFIED", ev.GetType())
				}
				if got := ev.GetStatus().GetGuestTransportAddress(); got != "192.168.64.7" {
					t.Fatalf("published guest_transport_address = %q, want 192.168.64.7", got)
				}
				// The published identity is untouched: the transport address is
				// NOT folded into pod_ip (runtime.proto's two-address model).
				if ip := ev.GetStatus().GetPodIp(); ip == "192.168.64.7" {
					t.Fatalf("the transport address leaked into pod_ip (%q)", ip)
				}
				return
			case <-deadline:
				t.Fatal("timed out waiting for a MODIFIED status event carrying the lease")
			}
		}
	})

	// A steady lease is not republished: the publish is on CHANGE, so a hostile
	// agent restating the same address cannot drive the status stream.
	t.Run("an-unchanged-lease-is-not-republished", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		waitFor(t, 2*time.Second, "the first lease", func() bool {
			return leaseOf(t, rt, "pod-vm") == "192.168.64.7"
		})

		ch, cancel := rt.broker.subscribe("pod-vm")
		defer cancel()
		before := agent.healthCalls()
		waitFor(t, 2*time.Second, "several further polls", func() bool {
			return agent.healthCalls() > before+5
		})
		select {
		case ev := <-ch:
			t.Fatalf("an unchanged lease published a status event (%v)", ev.GetType())
		default:
		}
	})
}

// TestGuestLeaseWatcherLifetime is the leak proof: the watcher is one bounded
// goroutine per vm pod, it stops when the pod's supervision context ends, and
// nothing arms one for a pod that has no guest.
func TestGuestLeaseWatcherLifetime(t *testing.T) {
	t.Run("stops-on-pod-delete", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		waitFor(t, 2*time.Second, "the first lease", func() bool {
			return leaseOf(t, rt, "pod-vm") == "192.168.64.7"
		})

		p.mu.Lock()
		stopped := p.guestLeaseStopped
		p.mu.Unlock()
		if stopped == nil {
			t.Fatal("no watcher was armed for a vm pod")
		}
		select {
		case <-stopped:
			t.Fatal("the watcher stopped while the pod was still live")
		default:
		}

		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-vm"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("the guest-lease watcher outlived its pod: DeletePod did not stop it")
		}
	})

	t.Run("stops-on-supervision-cancel", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		waitFor(t, 2*time.Second, "the watcher to poll", func() bool { return agent.healthCalls() > 0 })

		p.mu.Lock()
		stopped := p.guestLeaseStopped
		p.mu.Unlock()
		p.cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("the watcher ignored its pod-lifetime cancel")
		}
	})

	t.Run("arming-twice-starts-one-watcher", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")

		rt.armGuestLeaseWatcher(p)
		p.mu.Lock()
		first := p.guestLeaseStopped
		p.mu.Unlock()
		rt.armGuestLeaseWatcher(p)
		p.mu.Lock()
		second := p.guestLeaseStopped
		p.mu.Unlock()
		if first != second {
			t.Fatal("a second arm replaced the latch: two watchers now run for one pod")
		}
	})

	t.Run("an-unregistered-pod-is-refused", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		rt := leaseRuntime(t, agent)
		p := addVMPod(t, rt, "pod-vm", "main")
		rt.mu.Lock()
		delete(rt.pods, "pod-vm")
		rt.mu.Unlock()

		rt.armGuestLeaseWatcher(p)
		p.mu.Lock()
		armed := p.guestLeaseStopped != nil
		p.mu.Unlock()
		if armed {
			t.Fatal("armed a watcher for a pod the daemon has already forgotten")
		}
	})

	// The inertness proof, at the real arming point: a host-process pod goes
	// through CreatePod, which calls armGuestLeaseWatcher for every pod.
	t.Run("host-process-pods-never-start-a-watcher", func(t *testing.T) {
		agent := &guestLeaseAgent{ip: "192.168.64.7"}
		dial, dialed := startFakeGuestAgent(t, agent)
		sp := &fakeSpawner{}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, GuestDialer: dial})
		rt.guestLeasePoll = time.Millisecond

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-1")})
		if err != nil || resp.GetError() != nil {
			t.Fatalf("CreatePod: %v / %v", err, resp.GetError())
		}
		if got := resp.GetStatus().GetGuestTransportAddress(); got != "" {
			t.Errorf("host-process pod reported guest_transport_address %q, want empty", got)
		}

		p, ok := rt.lookupPod("pod-1")
		if !ok {
			t.Fatal("pod-1 not registered")
		}
		time.Sleep(50 * time.Millisecond)
		p.mu.Lock()
		armed := p.guestLeaseStopped != nil
		p.mu.Unlock()
		if armed {
			t.Error("a host-process pod was given a guest-lease watcher")
		}
		if calls := agent.healthCalls(); calls != 0 {
			t.Errorf("a host-process pod polled a guest agent %d times", calls)
		}
		if d := dialed(); len(d) != 0 {
			t.Errorf("a host-process pod dialled a guest agent socket: %v", d)
		}
		if got := leaseOf(t, rt, "pod-1"); got != "" {
			t.Errorf("host-process pod status carried guest_transport_address %q", got)
		}

		w.release(1001)
	})
}
