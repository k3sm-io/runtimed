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

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const egressDataVol = "/var/lib/k3sm/pods/pod-egress1/rootfs"

// TestGenerateEgressGolden is acceptance M8.2-a1's egress half: the profile an
// allow_internet_egress pod runs under is pinned byte-for-byte against
// testdata/pod-egress.golden.sb — the DOCUMENTED-CEILING form.
//
// The golden's job is to make the ceiling visible and hard to move. What a reader
// must be able to see in it: the grant is unfiltered, it names its own ceiling in
// its comments, and it contains no per-IP filter, no deny-list of node/loopback
// addresses, and nothing that would let anyone read the egress flag as network
// isolation. Run with -update to regenerate.
func TestGenerateEgressGolden(t *testing.T) {
	got, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:      egressDataVol,
		AllowInternetEgress: true,
	}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	goldenPath := filepath.Join("testdata", "pod-egress.golden.sb")
	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("generated egress SBPL differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestEgressImpliesNetwork pins the implies-pairing at the byte level: at the
// Seatbelt layer allow_internet_egress and allow_network are INDISTINGUISHABLE.
// Three profiles — egress only, network only, both — must render identically.
//
// This is the honest statement of the ceiling, expressed as a test rather than
// only as prose: if someone later makes the egress branch emit something else,
// this goes red and they have to justify a filter macOS cannot compile. The
// enforcement difference the flag names is an ADMISSION contract, carried in the
// API and (in future) by a packet filter; it is not, and must never be claimed as,
// a Seatbelt difference.
func TestEgressImpliesNetwork(t *testing.T) {
	render := func(t *testing.T, sp *runtimev1.SandboxProfile) string {
		t.Helper()
		sp.DataVolumePath = egressDataVol
		out, err := Generate(sp, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return out
	}

	network := render(t, &runtimev1.SandboxProfile{AllowNetwork: true})
	egress := render(t, &runtimev1.SandboxProfile{AllowInternetEgress: true})
	both := render(t, &runtimev1.SandboxProfile{AllowNetwork: true, AllowInternetEgress: true})

	if egress != network {
		t.Errorf("allow_internet_egress rendered a different profile than allow_network:\n--- egress ---\n%s\n--- network ---\n%s", egress, network)
	}
	if both != network {
		t.Errorf("allow_network+allow_internet_egress rendered a different profile than allow_network alone:\n%s", both)
	}
	if !strings.Contains(egress, networkStanza) {
		t.Errorf("the egress profile does not carry the generated network stanza:\n%s", egress)
	}
}

// TestEgressRetiredRules pins what the egress branch must NOT emit. The
// range-based deny set, the tier-3 re-allows, and the kine-loopback deny were
// retired from this milestone (m8-plan Resolution 21): per-IP filters do not
// compile on macOS 26, so emitting one would not tighten anything — it would make
// every networked pod fail at sandbox_apply while LOOKING like enforcement.
// Network-layer enforcement is the networking datapath's future work.
func TestEgressRetiredRules(t *testing.T) {
	out, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:      egressDataVol,
		AllowInternetEgress: true,
	}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := ruleLines(out)
	for _, banned := range []string{
		"remote ip",  // any per-IP filter, the form that does not compile
		"127.0.0.1",  // the retired kine-loopback deny
		"100.64.0.0", // the retired sibling-pod range deny
		"2379",       // the retired datastore-port deny
	} {
		if strings.Contains(rules, banned) {
			t.Errorf("egress profile carries retired rule fragment %q", banned)
		}
	}
}

// TestValidateNetworkScope is acceptance M8.2-a1's adversarial half: the re-scoped
// check accepts exactly the generated stanza under a request for it, and refuses
// every other shape — including profiles that are perfectly well-formed SBPL and
// would pass the fail-closed Validate.
func TestValidateNetworkScope(t *testing.T) {
	const head = "(version 1)\n(deny default)\n(import \"system.sb\")\n"
	sp := func(network, egress bool) *runtimev1.SandboxProfile {
		return &runtimev1.SandboxProfile{
			DataVolumePath:      egressDataVol,
			AllowNetwork:        network,
			AllowInternetEgress: egress,
		}
	}

	cases := []struct {
		name    string
		sp      *runtimev1.SandboxProfile
		profile string
		want    error
	}{
		{
			name:    "no request, no network rules",
			sp:      sp(false, false),
			profile: head,
		},
		{
			name:    "network requested, generated stanza",
			sp:      sp(true, false),
			profile: head + networkStanza,
		},
		{
			name:    "egress requested, generated stanza",
			sp:      sp(false, true),
			profile: head + networkStanza,
		},
		{
			name:    "unrequested network allow",
			sp:      sp(false, false),
			profile: head + "(allow network-outbound)\n",
			want:    ErrNetworkRulesUnrequested,
		},
		{
			// The exact regression the retired design would have caused: a
			// "tightened" per-IP filter that libsandbox refuses to compile.
			name:    "per-IP filtered outbound instead of the stanza",
			sp:      sp(true, false),
			profile: head + "(allow network-outbound (remote ip \"10.43.0.10:53\"))\n",
			want:    ErrNetworkStanzaMismatch,
		},
		{
			name:    "wildcard network allow instead of the stanza",
			sp:      sp(true, false),
			profile: head + "(allow network*)\n",
			want:    ErrNetworkStanzaMismatch,
		},
		{
			// Whitespace/dialect variant: DETECTION is loose so this is still seen
			// as a network grant, and ACCEPTANCE is strict so it is still refused.
			name:    "reformatted stanza",
			sp:      sp(true, false),
			profile: head + "(allow  network-outbound)\n(allow network-bind)\n(allow network-inbound)\n",
			want:    ErrNetworkStanzaMismatch,
		},
		{
			name:    "stanza plus an extra hand-added allow",
			sp:      sp(true, false),
			profile: head + networkStanza + "(allow network-outbound (remote ip \"*:*\"))\n",
			want:    ErrNetworkStanzaMismatch,
		},
		{
			name:    "network requested but no grant emitted",
			sp:      sp(true, false),
			profile: head,
			want:    ErrNetworkStanzaMismatch,
		},
		{
			name:    "egress requested but no grant emitted (pairing broken)",
			sp:      sp(false, true),
			profile: head,
			want:    ErrEgressPairingViolated,
		},
		{
			// A commented-out grant is not a grant: the check reads rules, not prose.
			name:    "network allow only inside a comment",
			sp:      sp(false, false),
			profile: head + ";; (allow network-outbound)\n",
		},
		{
			// The AF_UNIX helper-socket DENY block's continuation lines must never
			// be mistaken for a grant — it is a deny, and it is what keeps a pod off
			// the privileged netd socket.
			name:    "af_unix deny block is not a grant",
			sp:      sp(false, false),
			profile: head + "(deny network-outbound\n  (remote unix-socket (literal \"/var/lib/k3sm/run/netd.sock\"))\n  )\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNetworkScope(tc.sp, tc.profile)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateNetworkScope = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ValidateNetworkScope = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestGenerateSelfChecksNetworkScope proves the generator runs the check on its
// OWN output: every profile Generate returns satisfies ValidateNetworkScope, in
// both the requested and unrequested directions.
func TestGenerateSelfChecksNetworkScope(t *testing.T) {
	for _, tc := range []struct{ network, egress bool }{
		{false, false}, {true, false}, {false, true}, {true, true},
	} {
		sp := &runtimev1.SandboxProfile{
			DataVolumePath:      egressDataVol,
			AllowNetwork:        tc.network,
			AllowInternetEgress: tc.egress,
		}
		out, err := Generate(sp, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate(network=%v egress=%v): %v", tc.network, tc.egress, err)
		}
		if err := ValidateNetworkScope(sp, out); err != nil {
			t.Fatalf("generated profile (network=%v egress=%v) failed its own scope check: %v", tc.network, tc.egress, err)
		}
		if err := Validate(out); err != nil {
			t.Fatalf("generated profile (network=%v egress=%v) failed Validate: %v", tc.network, tc.egress, err)
		}
	}
}
