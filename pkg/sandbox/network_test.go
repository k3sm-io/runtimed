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
	"regexp"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const egressDataVol = "/var/lib/k3sm/pods/pod-egress1/rootfs"

// TestGenerateEgressGolden is acceptance M8.2-a1's egress half: the profile an
// allow_internet_egress pod runs under is pinned byte-for-byte against
// testdata/pod-egress.golden.sb — the DOCUMENTED-ceiling form.
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

// TestEgressRetiredRules pins what the egress branch must not emit. What stays
// retired and banned is the PER-IP shape: a network filter naming an address.
// Those do not compile on macOS 26, so emitting one would not tighten anything —
// it would make every networked pod fail at sandbox_apply while LOOKING like
// enforcement. The range-based deny set and the tier-3 re-allows went with them.
// Network-layer enforcement is the networking datapath's future work.
//
// The one sanctioned narrowing is the host-less, PORT-only
// (deny network-outbound (remote ip "localhost:<port>")) the caller asks for by
// data through denied_local_ports — never a hard-coded address or port number in
// this package. So the ban here is on `remote ip "` followed by a digit (an
// address literal) and on the specific address fragments that were retired; the
// `localhost:` form is asserted PRESENT in the ports sub-test, and only there.
func TestEgressRetiredRules(t *testing.T) {
	// perIPFilter matches a network filter whose host is an address literal
	// rather than `localhost`/`*` — the shape that does not compile.
	perIPFilter := regexp.MustCompile(`remote ip "[0-9]`)
	bannedFragments := []string{
		"127.0.0.1",  // the retired loopback-address deny
		"100.64.0.0", // the retired sibling-pod range deny
	}

	t.Run("no ports", func(t *testing.T) {
		out, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:      egressDataVol,
			AllowInternetEgress: true,
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		rules := ruleLines(out)
		if perIPFilter.MatchString(rules) {
			t.Errorf("egress profile carries a per-IP network filter (does not compile on macOS 26):\n%s", rules)
		}
		for _, banned := range bannedFragments {
			if strings.Contains(rules, banned) {
				t.Errorf("egress profile carries retired rule fragment %q", banned)
			}
		}
		// Nothing asked for a port deny, so none may appear.
		if strings.Contains(rules, `remote ip "localhost:`) {
			t.Errorf("egress profile carries a port deny nobody requested:\n%s", rules)
		}
	})

	t.Run("with denied ports", func(t *testing.T) {
		out, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:      egressDataVol,
			AllowInternetEgress: true,
			DeniedLocalPorts:    []uint32{12379},
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		rules := ruleLines(out)
		if !strings.Contains(rules, `(deny network-outbound (remote ip "localhost:12379"))`) {
			t.Errorf("the sanctioned localhost port deny is missing:\n%s", rules)
		}
		if perIPFilter.MatchString(rules) {
			t.Errorf("the port deny rendered as a per-IP filter (does not compile on macOS 26):\n%s", rules)
		}
		for _, banned := range bannedFragments {
			if strings.Contains(rules, banned) {
				t.Errorf("egress profile carries retired rule fragment %q", banned)
			}
		}
	})
}

// TestGenerateDeniesKinePort pins the denied_local_ports translation: which
// profiles carry a loopback port deny, where it sits, and what an invalid entry
// does.
//
// Every port here is a test datum. The generator does not know — and must never
// encode — what listens on a given port: the caller names the ports, so a
// non-default 12379 exercises the same path a control plane's real listener
// would, and nothing in this package may hard-code either number.
func TestGenerateDeniesKinePort(t *testing.T) {
	gen := func(t *testing.T, sp *runtimev1.SandboxProfile) string {
		t.Helper()
		sp.DataVolumePath = egressDataVol
		out, err := Generate(sp, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return out
	}
	denyLine := func(port int) string {
		return `(deny network-outbound (remote ip "localhost:` + strconv.Itoa(port) + `"))`
	}

	t.Run("allow_network emits the deny after the network stanza", func(t *testing.T) {
		out := gen(t, &runtimev1.SandboxProfile{
			AllowNetwork:     true,
			DeniedLocalPorts: []uint32{12379, 10257},
		})
		for _, port := range []int{12379, 10257} {
			line := denyLine(port)
			at := strings.Index(out, line)
			if at < 0 {
				t.Fatalf("missing deny for port %d:\n%s", port, out)
			}
			stanzaAt := strings.Index(out, networkStanza)
			if stanzaAt < 0 {
				t.Fatalf("network stanza missing from a networked profile:\n%s", out)
			}
			// SBPL is last-match-wins: a deny emitted BEFORE the unfiltered
			// (allow network-outbound) would be overridden by it and enforce
			// nothing, which is the whole failure mode this asserts against.
			if at < stanzaAt+len(networkStanza) {
				t.Errorf("deny for port %d is emitted before/inside the network stanza (last-match-wins would clobber it)", port)
			}
		}
		// Deduped+sorted: ascending, regardless of input order.
		if a, b := strings.Index(out, denyLine(10257)), strings.Index(out, denyLine(12379)); a > b {
			t.Errorf("port denies are not in ascending order (%d > %d)", a, b)
		}
	})

	t.Run("allow_internet_egress emits the same deny", func(t *testing.T) {
		out := gen(t, &runtimev1.SandboxProfile{
			AllowInternetEgress: true,
			DeniedLocalPorts:    []uint32{12379},
		})
		if !strings.Contains(out, denyLine(12379)) {
			t.Errorf("an egress-only pod carries no port deny:\n%s", out)
		}
	})

	t.Run("no network request emits nothing", func(t *testing.T) {
		withPorts := gen(t, &runtimev1.SandboxProfile{DeniedLocalPorts: []uint32{12379}})
		without := gen(t, &runtimev1.SandboxProfile{})
		if strings.Contains(withPorts, `remote ip "localhost:`) {
			t.Errorf("a pod that requested no network carries a port deny:\n%s", withPorts)
		}
		// (deny default) already covers the dial, so the field must not perturb
		// a single byte of the profile.
		if withPorts != without {
			t.Errorf("denied_local_ports changed an unnetworked profile:\n--- with ---\n%s\n--- without ---\n%s", withPorts, without)
		}
	})

	t.Run("empty list is byte-identical", func(t *testing.T) {
		for _, tc := range []struct{ network, egress bool }{
			{false, false}, {true, false}, {false, true}, {true, true},
		} {
			withEmpty := gen(t, &runtimev1.SandboxProfile{
				AllowNetwork:        tc.network,
				AllowInternetEgress: tc.egress,
				DeniedLocalPorts:    []uint32{},
			})
			without := gen(t, &runtimev1.SandboxProfile{
				AllowNetwork:        tc.network,
				AllowInternetEgress: tc.egress,
			})
			if withEmpty != without {
				t.Errorf("an empty denied_local_ports changed the profile (network=%v egress=%v):\n--- with ---\n%s\n--- without ---\n%s", tc.network, tc.egress, withEmpty, without)
			}
		}
	})

	t.Run("a duplicate port emits once", func(t *testing.T) {
		out := gen(t, &runtimev1.SandboxProfile{
			AllowNetwork:     true,
			DeniedLocalPorts: []uint32{12379, 12379},
		})
		if n := strings.Count(out, denyLine(12379)); n != 1 {
			t.Errorf("duplicate port rendered %d deny lines, want 1:\n%s", n, out)
		}
	})

	t.Run("out-of-range ports are refused", func(t *testing.T) {
		for _, ports := range [][]uint32{{0}, {70000}, {12379, 0}, {65536}} {
			_, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:   egressDataVol,
				AllowNetwork:     true,
				DeniedLocalPorts: ports,
			}, GenerateOptions{})
			if !errors.Is(err, ErrInvalidDeniedPort) {
				t.Errorf("Generate(ports=%v) = %v, want ErrInvalidDeniedPort", ports, err)
			}
		}
		// Refused even for a pod that would emit nothing: a malformed entry is
		// the caller's bug regardless of the network flags.
		_, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath:   egressDataVol,
			DeniedLocalPorts: []uint32{0},
		}, GenerateOptions{})
		if !errors.Is(err, ErrInvalidDeniedPort) {
			t.Errorf("Generate(no network, ports=[0]) = %v, want ErrInvalidDeniedPort", err)
		}
		// The boundaries themselves are valid.
		for _, port := range []uint32{1, 65535} {
			if _, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:   egressDataVol,
				AllowNetwork:     true,
				DeniedLocalPorts: []uint32{port},
			}, GenerateOptions{}); err != nil {
				t.Errorf("Generate(ports=[%d]) = %v, want nil", port, err)
			}
		}
	})

	t.Run("the generated profile still passes both checks", func(t *testing.T) {
		sp := &runtimev1.SandboxProfile{
			DataVolumePath:   egressDataVol,
			AllowNetwork:     true,
			DeniedLocalPorts: []uint32{12379},
		}
		out := gen(t, sp)
		if err := ValidateNetworkScope(sp, out); err != nil {
			t.Errorf("a profile with port denies failed its own scope check: %v", err)
		}
		if err := Validate(out); err != nil {
			t.Errorf("a profile with port denies failed Validate: %v", err)
		}
	})
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
		{
			// The sanctioned narrowing: denied_local_ports lines sit AFTER the
			// stanza for a pod that asked for network. They are denies, so they are
			// neither a second grant nor a mismatch — the profile is accepted, and
			// the pod keeps the network it requested minus those ports.
			name:    "stanza plus the localhost port denies",
			sp:      sp(true, false),
			profile: head + networkStanza + "(deny network-outbound (remote ip \"localhost:12379\"))\n",
		},
		{
			// Same lines WITHOUT a network request: inert, not a violation. Only
			// (allow …) directives can hand a pod authority it did not ask for, and
			// under (deny default) this denies what is already denied. Accepting it
			// is the reading consistent with the af_unix case above — a check that
			// refused profiles for subtracting authority would be fail-closed in
			// name only.
			name:    "port denies without a network request are inert",
			sp:      sp(false, false),
			profile: head + "(deny network-outbound (remote ip \"localhost:12379\"))\n",
		},
		{
			// Documented LIMIT, pinned so nobody reads more assurance into this
			// check than it gives: detection counts (allow …) directives only, so a
			// per-IP shape spelled as a DENY passes here — even though libsandbox
			// refuses to compile it just as it refuses the allow form (probed
			// 2026-09-17: "host must be * or localhost in network address"). The
			// backstop for that shape is TestGeneratedProfileAppliesOnDarwin, which
			// feeds the generated profile to real libsandbox; this validator's job
			// is unrequested or uncompilable GRANTS.
			name:    "per-IP deny beside the stanza is not caught here",
			sp:      sp(true, false),
			profile: head + networkStanza + "(deny network-outbound (remote ip \"127.0.0.1:2379\"))\n",
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
// own output: every profile Generate returns satisfies ValidateNetworkScope, in
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
