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
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// guestNetworkerNetwork is a recordingNetwork that additionally implements the
// optional GuestNetworker seam — the shape the k3sm provider's network adapter
// takes in production. It returns a caller-supplied config with a caller-supplied
// comma-ok, and records every podID it was consulted for, so a test can assert
// BOTH that the vm route consults it and that the host-process route never does.
type guestNetworkerNetwork struct {
	recordingNetwork
	cfg sandbox.GuestNetworkConfig
	ok  bool

	gmu   sync.Mutex
	calls []string
}

func (n *guestNetworkerNetwork) GuestNetwork(podID string) (sandbox.GuestNetworkConfig, bool) {
	n.gmu.Lock()
	n.calls = append(n.calls, podID)
	n.gmu.Unlock()
	return n.cfg, n.ok
}

func (n *guestNetworkerNetwork) guestNetworkCalls() []string {
	n.gmu.Lock()
	defer n.gmu.Unlock()
	return append([]string{}, n.calls...)
}

// Compile-time proof the fake really satisfies the seam under test: without it a
// renamed method would make every assertion below pass through the ABSENT branch,
// which is the one way this file could go quietly vacuous.
var _ GuestNetworker = (*guestNetworkerNetwork)(nil)

// lockedBuffer is a concurrency-safe sink for the runtime's slog output. The
// daemon logs from background goroutines (samplers, reapers), so an unguarded
// bytes.Buffer is a -race failure waiting on scheduling luck.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newGuestNetworkRuntime builds a vm-capable Runtime over pn, with WARN-and-above
// log output captured. vmPodConfig supplies the Config.Root/image-cache alignment
// every vm-routed pod needs (see its doc); the logger is layered on top because
// the absent-producer contract is HALF a log assertion.
func newGuestNetworkRuntime(t *testing.T, pn supervisor.PodNetwork) (*Runtime, *fakeVMBackend, *lockedBuffer) {
	t.Helper()
	vmb := &fakeVMBackend{available: true}
	cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Network: pn})
	logs := &lockedBuffer{}
	cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return newTestRuntimeCfg(t, cfg, d), vmb, logs
}

// vmBackedBox is a vm-RuntimeClass PodBox for pod id podID.
func vmBackedBox(rt *Runtime, podID string) *runtimev1.PodBox {
	box := hostBinBox(rt, podID)
	box.SandboxProfile.Backend = runtimev1.SandboxBackend_SANDBOX_BACKEND_VM
	return box
}

// distinctiveGuestNetwork is a guest network config whose every field is
// recognizably NOT a zero value and NOT any default the runtime could invent —
// two nameservers, a three-entry search list, two options, and NAT addresses in
// ranges no other fixture in this package uses. That is what makes "these exact
// values reached the backend" a real assertion rather than a coincidence.
func distinctiveGuestNetwork() sandbox.GuestNetworkConfig {
	return sandbox.GuestNetworkConfig{
		Nameservers: []string{"10.43.0.10", "10.43.0.11"},
		Searches: []string{
			"team-a.svc.cluster.local",
			"svc.cluster.local",
			"cluster.local",
		},
		Options: []string{"ndots:5", "edns0"},
		ResolvConf: "nameserver 10.43.0.10\n" +
			"nameserver 10.43.0.11\n" +
			"search team-a.svc.cluster.local svc.cluster.local cluster.local\n" +
			"options ndots:5 edns0\n",
		PodIP:     netip.MustParseAddr("10.42.7.31"),
		Gateway:   netip.MustParseAddr("192.168.77.1"),
		NATSubnet: netip.MustParsePrefix("192.168.77.0/24"),
		DNSVIP:    netip.MustParseAddr("10.43.0.10"),
	}
}

// TestCreateVMPodUsesGuestNetworkerWhenPresent is the M11.2-d8 acceptance
// (present half): when Deps.Network additionally implements GuestNetworker, the
// config that producer returns for the pod is what the vm backend RECEIVES in
// VMSpec.Network — structured DNS fields, rendered resolv.conf, and NAT advisory
// fields alike.
//
// The assertion is against the fakeVMBackend recorder's captured VMSpec, i.e.
// what crossed the seam, never against the producer fake's own input: a test that
// re-reads its fixture proves only that Go can copy a struct. It also pins the
// two collateral facts the seam must not break — the producer is consulted for
// THIS pod id, and the vm route still binds no lo0 alias (a NAT-attached guest
// gets no host /32).
func TestCreateVMPodUsesGuestNetworkerWhenPresent(t *testing.T) {
	want := distinctiveGuestNetwork()
	pn := &guestNetworkerNetwork{cfg: want, ok: true}
	rt, vmb, _ := newGuestNetworkRuntime(t, pn)

	// The lab-gated CreateVM stub fails the pod after recording the spec —
	// expected, and orthogonal to what is asserted here.
	if _, _, err := rt.createPod(context.Background(), vmBackedBox(rt, "pod-guestnet-present")); err == nil {
		t.Fatal("vm createPod should surface the lab-gated boot error")
	}

	n, spec := vmb.created()
	if n != 1 {
		t.Fatalf("CreateVM called %d times, want 1 (the config must reach the backend)", n)
	}
	if !reflect.DeepEqual(spec.Network, want) {
		t.Fatalf("VMSpec.Network as RECEIVED by the backend =\n  %+v\nwant\n  %+v", spec.Network, want)
	}
	// Field-by-field on the newly structured half, so a future DeepEqual over a
	// widened struct cannot mask a dropped list: the guest renders resolv.conf
	// from these, so a lost search entry is a silent DNS outage.
	if got := spec.Network.Nameservers; !reflect.DeepEqual(got, want.Nameservers) {
		t.Errorf("Nameservers = %v, want %v", got, want.Nameservers)
	}
	if got := spec.Network.Searches; !reflect.DeepEqual(got, want.Searches) {
		t.Errorf("Searches = %v, want %v", got, want.Searches)
	}
	if got := spec.Network.Options; !reflect.DeepEqual(got, want.Options) {
		t.Errorf("Options = %v, want %v", got, want.Options)
	}

	if got := pn.guestNetworkCalls(); len(got) != 1 || got[0] != "pod-guestnet-present" {
		t.Errorf("GuestNetwork consulted with %v, want [pod-guestnet-present]", got)
	}
	if got := pn.setupCount(); got != 0 {
		t.Errorf("vm route allocated %d lo0 aliases; must be 0 (the guest is NAT-attached)", got)
	}
}

// TestCreateVMPodFallsBackWhenGuestNetworkerAbsent is the M11.2-d8 acceptance
// (absent half): with no config available the vm backend receives the INERT ZERO
// value — never a partial or invented one — and the miss is LOGGED.
//
// The log is the point of the row, not decoration. A vm pod with no
// /etc/resolv.conf boots, reports healthy, passes readiness, and fails only at
// the first in-app DNS lookup, at which point it is indistinguishable from an
// application bug; the node-side warning is the only thing that names the real
// cause. The two rows are the two distinct ways the config can be missing.
func TestCreateVMPodFallsBackWhenGuestNetworkerAbsent(t *testing.T) {
	cases := []struct {
		name string
		// newNet builds the Deps.Network for the row and returns the optional
		// producer fake (nil when the row's network implements no seam at all).
		newNet     func() (supervisor.PodNetwork, *guestNetworkerNetwork)
		podID      string
		wantReason string
	}{
		{
			name: "network-does-not-implement-the-seam",
			newNet: func() (supervisor.PodNetwork, *guestNetworkerNetwork) {
				return &recordingNetwork{}, nil
			},
			podID:      "pod-guestnet-absent",
			wantReason: "no GuestNetworker producer is wired",
		},
		{
			// The producer HAS a config and still answers ok=false: the comma-ok
			// is the authority, so that config must not leak into the VMSpec.
			name: "producer-reports-no-config-for-this-pod",
			newNet: func() (supervisor.PodNetwork, *guestNetworkerNetwork) {
				pn := &guestNetworkerNetwork{cfg: distinctiveGuestNetwork(), ok: false}
				return pn, pn
			},
			podID:      "pod-guestnet-notok",
			wantReason: "the GuestNetworker producer reported no config for this pod",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pn, producer := tc.newNet()
			rt, vmb, logs := newGuestNetworkRuntime(t, pn)

			if _, _, err := rt.createPod(context.Background(), vmBackedBox(rt, tc.podID)); err == nil {
				t.Fatal("vm createPod should surface the lab-gated boot error")
			}

			n, spec := vmb.created()
			if n != 1 {
				t.Fatalf("CreateVM called %d times, want 1", n)
			}
			if !reflect.DeepEqual(spec.Network, sandbox.GuestNetworkConfig{}) {
				t.Errorf("VMSpec.Network = %+v, want the inert zero value", spec.Network)
			}

			out := logs.String()
			if !strings.Contains(out, "vm pod has no guest network config") {
				t.Errorf("the missing guest network config was not logged; log output = %q", out)
			}
			if !strings.Contains(out, tc.wantReason) {
				t.Errorf("log does not name the reason %q; log output = %q", tc.wantReason, out)
			}
			if !strings.Contains(out, tc.podID) {
				t.Errorf("log does not name the pod %q; log output = %q", tc.podID, out)
			}

			if producer != nil {
				if got := producer.guestNetworkCalls(); len(got) != 1 || got[0] != tc.podID {
					t.Errorf("GuestNetwork consulted with %v, want [%s]", got, tc.podID)
				}
			}
		})
	}
}
