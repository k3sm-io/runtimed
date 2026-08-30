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
	"fmt"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// networkStanza is the ONE network grant this generator can emit — every
// networked pod gets these bytes and no others.
//
// ============================================================================
// macOS 26 SBPL GRAMMAR CEILING — per-IP network scoping DOES NOT COMPILE.
//
// PROBE-VERIFIED on macOS 26.5.1 through the real k3sm-execshim/libsandbox
// path: Seatbelt network-address filters accept ONLY `localhost` or `*` as
// the host. (remote ip "10.43.0.10:53"), (local ip "<PodIP>:*"), and every
// tcp4/ip4/tcp dialect variant FAIL to compile with "host must be * or
// localhost in network address" — so the pre-M10.1 VIP-scoped outbound
// allows and PodIP-scoped bind allow made EVERY AllowNetwork pod fail at
// sandbox_apply (networked pods could not spawn at all).
//
// What the grammar DOES support: per-PORT scoping compiles and enforces
// precisely ((local ip "*:8899") allowed :8899 and denied :8898), and
// localhost-host filters compile. Whether `localhost` matches lo0-ALIASED
// per-pod addresses is UNKNOWN without a root-gated lab probe, so
// port-scoped and localhost-scoped TIGHTENINGS are a named follow-up —
// not emitted here.
//
// Honest consequence: for a networked pod, networking allowed means
// networking ALLOWED — unfiltered outbound + bind under the profile's
// (deny default). The isolation story for a networked pod stays fs/exec
// confinement plus the vm RuntimeClass for untrusted tenancy; NEVER claim
// network isolation from Seatbelt. Posture.ResolverVIP/APIServerVIP and
// GenerateOptions.PodIP are plumbing-only (DNS env/status) — they render
// no SBPL.
// ============================================================================
//
// network-inbound authorizes listen()/accept(). A bare (allow network-bind)
// passes bind() but a TCP server's listen() is gated by the SEPARATE
// network-inbound operation, so without it EVERY listening pod (a Service
// target, a readiness/liveness HTTP server) fails listen() with EPERM under
// (deny default). Regression from M10.1 dropping the PodIP-scoped bind (which
// implied inbound) for a bare bind; probe-verified through the real
// execshim/libsandbox path on macOS 26.5.1 (both :8080 and :8081).
//
// It is a const rather than a run of WriteString calls because ValidateNetworkScope
// compares a rendered profile against it byte-for-byte: the emitted stanza and the
// checked stanza must be the SAME artifact, or the check would be pinning a copy
// that can drift from what pods actually run under.
const networkStanza = ";; network: ALLOWED — unfiltered outbound+bind+inbound under (deny default).\n" +
	";; macOS 26 Seatbelt accepts only localhost/* hosts in network filters;\n" +
	";; per-IP scoping (VIP egress, per-pod-IP bind) does NOT compile.\n" +
	"(allow network-outbound)\n" +
	"(allow network-bind)\n" +
	"(allow network-inbound)\n" +
	";; mach-lookup the DNS resolver path (mDNSResponder) needs.\n" +
	"(allow mach-lookup\n" +
	"  (global-name \"com.apple.dnssd.service\")\n" +
	"  (global-name \"com.apple.mDNSResponder\"))\n"

// ErrNetworkRulesUnrequested reports a profile that carries a network ALLOW while
// neither allow_network nor allow_internet_egress was requested. It is the
// "network forms appear only under the booleans" half of the re-scoped check: a
// pod that never asked for networking must not be handed any, so such a profile is
// refused rather than applied.
var ErrNetworkRulesUnrequested = errors.New("sbpl: profile grants network access that the sandbox profile did not request")

// ErrNetworkStanzaMismatch reports a profile whose network grant is not the exact
// stanza this generator emits — a hand-edited, reordered, or per-IP-filtered
// variant.
//
// It is fail-closed against BOTH directions of drift, and the second one is the
// reason it exists as its own sentinel. A WIDER stanza would grant a networked pod
// more than the ceiling admits. A NARROWER, "tightened" one — a (remote ip …)
// filter someone reinstates believing macOS can express it — does not compile at
// sandbox_apply, so every networked pod on the node would fail to spawn. Naming
// the mismatch at generation time turns that into one clear error instead of a
// node-wide outage reported one pod at a time.
var ErrNetworkStanzaMismatch = errors.New("sbpl: profile network stanza is not the generated one")

// ErrEgressPairingViolated reports a rendered profile that requested
// allow_internet_egress but carries no network grant — the implies-pairing broken.
// allow_internet_egress IMPLIES allow_network (m8-plan Resolution 21), so a
// generated profile that dropped the grant would leave a workload that declared it
// needs the internet with no network at all.
var ErrEgressPairingViolated = errors.New("sbpl: allow_internet_egress did not yield a network grant")

// networkRequested reports whether sp asks for network access by either route.
//
// allow_internet_egress IMPLIES allow_network: the implication is honoured HERE,
// in translation, rather than by rejecting a profile that sets only the egress
// flag. That choice is deliberate — the two flags do not describe two enforcement
// tiers on macOS, they describe an ADMISSION intent ("this workload may reach the
// internet") that this layer cannot narrow, so a pod carrying only the egress flag
// is a pod that needs networking and gets exactly the stanza allow_network gets.
//
// What the pair is FOR, since Seatbelt cannot enforce the difference: the flag is
// the API/admission contract a cluster operator can see and refuse (the annotation
// + the admission policy that reads it). Network-LAYER enforcement (a packet
// filter) is future work owned by the networking datapath, and until it exists
// runtimed must not claim it — see the ceiling comment on networkStanza.
func networkRequested(sp *runtimev1.SandboxProfile) bool {
	return sp.GetAllowNetwork() || sp.GetAllowInternetEgress()
}

// ValidateNetworkScope checks a RENDERED profile's network grant against what sp
// requested. It is the re-scoped network check (m8-plan Resolution 21) — scoped to
// what macOS 26 can actually express, which is the shape of the grant, never a
// per-IP filter it would reject at compile time:
//
//  1. a network ALLOW appears only when allow_network ∨ allow_internet_egress;
//  2. the implies-pairing holds — allow_internet_egress yields a network grant;
//  3. the grant is byte-for-byte the stanza this generator emits.
//
// Generate calls it on its own output, so a future edit that widens, narrows, or
// reorders the stanza fails at generation rather than at sandbox_apply. It is
// EXPORTED because it also serves a caller holding a profile it did not generate.
//
// It is deliberately SEPARATE from Validate, which takes only a profile string and
// is what a Backend runs before applying one: the properties here are relational —
// they can only be decided against the SandboxProfile that asked for the grant —
// so folding them into Validate would mean a check that silently cannot see half
// its own inputs.
//
// Detection is LOOSE and acceptance is STRICT, which is what makes it fail closed:
// any (allow …) line mentioning a network operation counts as a network grant
// (even a whitespace or dialect variant a naive equality test would miss), and
// only the exact stanza is then accepted.
func ValidateNetworkScope(sp *runtimev1.SandboxProfile, profile string) error {
	hasStanza := strings.Contains(profile, networkStanza)
	hasAnyAllow := hasNetworkAllow(profile)
	// Read the two booleans DIRECTLY rather than through networkRequested: that
	// helper is the TRANSLATE-side decision, and a check that shares its predicate
	// with the code it checks can only ever confirm that code agrees with itself.
	// Spelling the disjunction here means a translate-side edit that grants network
	// to a pod which asked for neither is caught by this validator.
	requested := sp.GetAllowNetwork() || sp.GetAllowInternetEgress()

	if !requested {
		if hasAnyAllow {
			return fmt.Errorf("%w: neither allow_network nor allow_internet_egress is set", ErrNetworkRulesUnrequested)
		}
		return nil
	}
	if !hasAnyAllow {
		if sp.GetAllowInternetEgress() {
			return fmt.Errorf("%w: the profile carries no network allow", ErrEgressPairingViolated)
		}
		return fmt.Errorf("%w: allow_network is set but the profile carries no network allow", ErrNetworkStanzaMismatch)
	}
	if !hasStanza {
		return fmt.Errorf("%w: the network allow is not the generated stanza", ErrNetworkStanzaMismatch)
	}
	// The stanza is present; make sure it is the ONLY network allow, so an extra
	// hand-added (allow network-outbound (remote ip …)) beside it is still caught.
	if extra := countNetworkAllowLines(profile) - countNetworkAllowLines(networkStanza); extra != 0 {
		return fmt.Errorf("%w: %d network allow line(s) beyond the generated stanza", ErrNetworkStanzaMismatch, extra)
	}
	return nil
}

// networkOperations are the SBPL operations that grant network access. The list is
// the closed set the generator can emit plus the wildcard form a hand-written
// profile might use; it drives DETECTION only (see ValidateNetworkScope), so an
// entry here can only ever make the check stricter.
var networkOperations = []string{"network-outbound", "network-bind", "network-inbound", "network*"}

// hasNetworkAllow reports whether profile has any (allow …) directive naming a
// network operation, ignoring comments. Continuation lines are attributed to the
// directive they belong to, so the AF_UNIX (deny network-outbound …) block's
// (remote unix-socket …) lines are never mistaken for a grant.
func hasNetworkAllow(profile string) bool {
	return countNetworkAllowLines(profile) > 0
}

// countNetworkAllowLines counts the network-granting ALLOW directive lines in
// profile, ignoring comment lines.
func countNetworkAllowLines(profile string) int {
	n := 0
	for _, line := range strings.Split(profile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.HasPrefix(line, "(allow") {
			continue
		}
		for _, op := range networkOperations {
			if strings.Contains(line, op) {
				n++
				break
			}
		}
	}
	return n
}
