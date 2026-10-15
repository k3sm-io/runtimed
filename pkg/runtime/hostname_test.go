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
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TestCreateVMPodCarriesHostname pins that PodBox.hostname reaches the vm
// backend as VMSpec.Hostname, and that the sandbox.VMSpec trust-boundary check
// refuses an out-of-contract value with SANDBOX_SETUP before any CreateVM call.
// The fake backend fails every boot after recording the spec, so a carried
// hostname is asserted on what crossed the seam, never on the fixture.
func TestCreateVMPodCarriesHostname(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		refused  bool
		wantErr  string
	}{
		{name: "fqdn-is-carried", hostname: "web-0.web.ns.svc.cluster.local"},
		{name: "empty-stays-empty", hostname: ""},
		{name: "65-bytes-refused", hostname: strings.Repeat("a", 65), refused: true, wantErr: "65 bytes"},
		{name: "uppercase-refused", hostname: "Web-0", refused: true, wantErr: "byte 0x57"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pn := &guestNetworkerNetwork{cfg: distinctiveGuestNetwork(), ok: true}
			rt, vmb, _ := newGuestNetworkRuntime(t, pn)
			box := vmBackedBox(rt, "pod-hostname-"+tc.name)
			box.Hostname = tc.hostname

			_, reason, err := rt.createPod(context.Background(), box)
			if err == nil {
				t.Fatal("vm createPod should fail: the fake backend boots nothing")
			}
			if reason != runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP {
				t.Errorf("reason = %v, want SANDBOX_SETUP", reason)
			}
			n, spec := vmb.created()
			if tc.refused {
				if n != 0 {
					t.Fatalf("CreateVM called %d times, want 0: an invalid hostname must not reach a backend", n)
				}
				if !errors.Is(err, sandbox.ErrInvalidVMSpec) {
					t.Errorf("err = %v, want it to wrap sandbox.ErrInvalidVMSpec", err)
				}
				if !strings.Contains(err.Error(), "Hostname") || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %v, want it to name the Hostname field and %s", err, tc.wantErr)
				}
				return
			}
			if n != 1 {
				t.Fatalf("CreateVM called %d times, want 1", n)
			}
			if spec.Hostname != tc.hostname {
				t.Errorf("VMSpec.Hostname as RECEIVED by the backend = %q, want %q", spec.Hostname, tc.hostname)
			}
		})
	}
}
