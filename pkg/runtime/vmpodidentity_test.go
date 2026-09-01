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
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestVMPodPublishesItsIdentitySeparatelyFromItsTransportAddress is the gate on
// a vm pod being unroutable, and on the two addresses staying two.
//
// createVMPod built its pod{} literal without podIP — the field is assigned in
// exactly one place, inside the host-process spine — so PodStatus.pod_ips was
// empty for every vm pod, status.podIP was empty, and a Service selecting one got
// an EndpointSlice with no addresses.
//
// The second half of the assertion matters as much as the first. runtime.proto
// is explicit that a vm pod has two addresses and that they are NOT
// interchangeable: pod_ip / pod_ips are the published identity (the podCIDR /32
// that reaches EndpointSlice, DNS and the downward API), while
// guest_transport_address is the guest's DHCP lease on the node's NAT segment and
// carries a MUST NOT against publishing it anywhere user-visible. A future change
// that collapses one into the other fails here.
func TestVMPodPublishesItsIdentitySeparatelyFromItsTransportAddress(t *testing.T) {
	const (
		podID = "pod-vm-identity"
		// Deliberately DIFFERENT shapes: a podCIDR /32 and a vmnet NAT address.
		// Equal values would let a collapse pass unnoticed.
		identity = "100.64.0.8"
		lease    = "192.168.66.7"
	)

	vmb := &fakeVMBackend{available: true, bootOK: true}
	rt := newTestRuntime(t, Deps{
		VMBackend: vmb,
		Network: &guestNetworkerNetwork{
			cfg: sandbox.GuestNetworkConfig{PodIP: netip.MustParseAddr(identity)},
			ok:  true,
		},
		Resolver: fakeResolver{},
	})

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: vmPodBox(rt, podID, 5)})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	t.Run("the-published-identity-is-the-allocated-pod-ip", func(t *testing.T) {
		st := resp.GetStatus()
		if got := st.GetPodIps(); !reflect.DeepEqual(got, []string{identity}) {
			t.Errorf("pod_ips = %v, want [%s]; an empty list is an EndpointSlice with no addresses", got, identity)
		}
		if got := st.GetPodIp(); got != identity {
			t.Errorf("pod_ip = %q, want %q — this is what status.podIP and the downward API publish", got, identity)
		}
	})

	t.Run("the-transport-address-is-reported-separately-and-does-not-displace-it", func(t *testing.T) {
		rt.mu.Lock()
		p := rt.pods[podID]
		rt.mu.Unlock()
		if p == nil {
			t.Fatal("the pod is not registered")
		}
		// Before any lease poll the transport address is empty while the identity
		// is already published: the two are independent, and one is not derived
		// from the other.
		before := rt.podStatus(p)
		if got := before.GetGuestTransportAddress(); got != "" {
			t.Errorf("guest_transport_address = %q before any lease, want empty", got)
		}
		if got := before.GetPodIp(); got != identity {
			t.Errorf("pod_ip = %q with no lease yet, want the identity %q", got, identity)
		}

		// Quiesce the pod's own lease watcher before writing the field it owns.
		// This pod was created through the real CreatePod, so the watcher is armed
		// and polling a guest agent that does not exist; each failed poll CLEARS
		// the transport address (deliberately — a stale address is worse than
		// none), which would race the write below. Cancelling and waiting for the
		// goroutine to exit makes the assertion about podStatus's rendering rather
		// than about who wrote last.
		p.cancel()
		p.mu.Lock()
		stopped := p.guestLeaseStopped
		p.mu.Unlock()
		if stopped != nil {
			<-stopped
		}

		// Now the guest reports its lease, through the production writer.
		rt.setGuestLease(p, lease)

		after := rt.podStatus(p)
		if got := after.GetGuestTransportAddress(); got != lease {
			t.Errorf("guest_transport_address = %q, want the guest's lease %q", got, lease)
		}
		if got := after.GetPodIp(); got != identity {
			t.Errorf("pod_ip = %q after the lease arrived, want the identity %q — the lease must never displace it", got, identity)
		}
		if got := after.GetPodIps(); !reflect.DeepEqual(got, []string{identity}) {
			t.Errorf("pod_ips = %v, want [%s]; the NAT lease must not reach EndpointSlice", got, identity)
		}
		if after.GetPodIp() == after.GetGuestTransportAddress() {
			t.Error("the identity and the transport address are the same value; runtime.proto requires them to be distinct")
		}
	})
}

// TestVMPodWithNoIdentityIsRefused pins the zero-value policy: the GuestNetworker
// seam is a vm pod's ONLY source of a published identity, so a pod it cannot
// answer for is refused at CreatePod rather than started unroutable.
//
// The DNS half of the same config degrades instead — a guest with no resolver
// boots and the miss is logged (TestCreateVMPodFallsBackWhenGuestNetworkerAbsent
// covers that) — because a pod that cannot resolve names is still a pod, whereas
// one with no address is not one Kubernetes can express.
func TestVMPodWithNoIdentityIsRefused(t *testing.T) {
	cases := []struct {
		name string
		net  func() supervisor.PodNetwork
	}{
		{
			name: "the-producer-has-no-config-for-this-pod",
			net: func() supervisor.PodNetwork {
				return &guestNetworkerNetwork{cfg: distinctiveGuestNetwork(), ok: false}
			},
		},
		{
			name: "the-producer-answers-with-no-pod-ip",
			net: func() supervisor.PodNetwork {
				// ok=true and a config that carries DNS but no identity: the
				// comma-ok is not the discriminator here, the field is.
				cfg := distinctiveGuestNetwork()
				cfg.PodIP = netip.Addr{}
				return &guestNetworkerNetwork{cfg: cfg, ok: true}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vmb := &fakeVMBackend{available: true, bootOK: true}
			rt := newTestRuntime(t, Deps{VMBackend: vmb, Network: tc.net(), Resolver: fakeResolver{}})

			_, reason, err := rt.createPod(context.Background(), vmPodBox(rt, "pod-vm-noip", 5))
			if err == nil {
				t.Fatal("a vm pod with no published identity must be refused")
			}
			if reason != runtimev1.FailureReason_FAILURE_REASON_INTERNAL {
				t.Errorf("reason = %v, want INTERNAL", reason)
			}
			if !strings.Contains(err.Error(), "no pod IP") {
				t.Errorf("err = %v; the refusal must name what is missing", err)
			}
			if n, _ := vmb.created(); n != 0 {
				t.Errorf("CreateVM called %d times; a pod with no identity must be refused before the machine is built", n)
			}
		})
	}
}
