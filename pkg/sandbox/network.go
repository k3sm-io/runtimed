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
	"regexp"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// networkStanza is the one network grant this generator can emit — every
// networked pod gets these bytes and no others.
//
// ============================================================================
// macOS 26 SBPL GRAMMAR ceiling — per-IP network scoping does not COMPILE.
//
// PROBE-verified on macOS 26.5.1 through the real k3sm-execshim/libsandbox
// path: Seatbelt network-address filters accept only `localhost` or `*` as
// the host. (remote ip "10.43.0.10:53"), (local ip "<PodIP>:*"), and every
// tcp4/ip4/tcp dialect variant fail to compile with "host must be * or
// localhost in network address" — so an earlier VIP-scoped outbound
// allows and PodIP-scoped bind allow made every AllowNetwork pod fail at
// sandbox_apply (networked pods could not spawn at all).
//
// What the grammar does support: per-PORT scoping compiles and enforces
// precisely ((local ip "*:8899") allowed :8899 and denied :8898), and
// localhost-host filters compile. RESOLVED (a lab probe run 2026-08-31,
// through the real execshim/libsandbox path): a port- or localhost-scoped
// tightening is foreclosed, not merely deferred. Scoping network-bind alone
// is inert — this stanza's separate, unscoped (allow network-inbound) still
// authorizes the bind, so any tightening has to scope both operations to
// change anything. And once both are scoped, `localhost` matches every
// address the host owns — the lo0-aliased per-pod address, the LAN address,
// and the wildcard alike (the LAN half measured 2026-09-17 by
// TestLocalPortDenyBlocksLANConnect, which dials the host's own non-loopback
// IPv4 address and is refused with EPERM) — so a localhost-scoped filter
// provides no per-pod isolation even then. Nothing narrower than the stanza
// below is expressible as an ALLOW.
//
// The ONE sanctioned narrowing, and it is a DENY: a
// (deny network-outbound (remote ip "localhost:<port>")) compiles and enforces
// — proven 2026-09-17 by the sandbox-exec connect test in
// sbpl_apply_check_test.go, which under one profile is refused on the denied
// port and connects on an undenied one. It is carried by
// SandboxProfile.denied_local_ports, threaded as data (the generator does not
// know what listens there), emitted after this stanza so last-match-wins keeps
// it denied. Its reach is exactly the grammar's: PORT-only, and `localhost`
// matches every address the host owns — measured, not inferred: the loopback
// test covers 127.0.0.1 and ::1, and TestLocalPortDenyBlocksLANConnect
// (integration-tagged) covers the host's LAN address, where the same deny is
// enforced with EPERM. So a Service that reused the port number is unreachable
// from a confined pod too. It is a same-host defence-in-depth
// layer over a shared-uid pod process — NOT per-pod isolation, and it narrows
// nothing about where else a networked pod may dial.
//
// Honest consequence: for a networked pod, networking allowed means
// networking ALLOWED — unfiltered outbound + bind under the profile's
// (deny default), minus whatever ports the caller named. The isolation story
// for a networked pod stays fs/exec confinement plus the vm RuntimeClass for
// untrusted tenancy; never claim network isolation from Seatbelt.
// Posture.ResolverVIP/APIServerVIP and GenerateOptions.PodIP are plumbing-only
// (DNS env/status) — they render no SBPL.
// ============================================================================
//
// network-inbound authorizes listen()/accept(). A bare (allow network-bind)
// passes bind() but a TCP server's listen() is gated by the separate
// network-inbound operation, so without it every listening pod (a Service
// target, a readiness/liveness HTTP server) fails listen() with EPERM under
// (deny default). Regression from per-pod-IP dropping the PodIP-scoped bind (which
// implied inbound) for a bare bind; probe-verified through the real
// execshim/libsandbox path on macOS 26.5.1 (both :8080 and :8081).
//
// It is a const rather than a run of WriteString calls because ValidateNetworkScope
// compares a rendered profile against it byte-for-byte: the emitted stanza and the
// checked stanza must be the same artifact, or the check would be pinning a copy
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

// ErrNetworkRulesUnrequested reports a profile that carries a network allow while
// neither allow_network nor allow_internet_egress was requested. It is the
// "network forms appear only under the booleans" half of the re-scoped check: a
// pod that never asked for networking must not be handed any, so such a profile is
// refused rather than applied.
var ErrNetworkRulesUnrequested = errors.New("sbpl: profile grants network access that the sandbox profile did not request")

// ErrNetworkStanzaMismatch reports a profile whose network grant is not the exact
// stanza this generator emits — a hand-edited, reordered, or per-IP-filtered
// variant.
//
// It is fail-closed against both directions of drift, and the second one is the
// reason it exists as its own sentinel. A WIDER stanza would grant a networked pod
// more than the ceiling admits. A narrower, "tightened" one — a (remote ip …)
// filter someone reinstates believing macOS can express it — does not compile at
// sandbox_apply, so every networked pod on the node would fail to spawn. Naming
// the mismatch at generation time turns that into one clear error instead of a
// node-wide outage reported one pod at a time.
var ErrNetworkStanzaMismatch = errors.New("sbpl: profile network stanza is not the generated one")

// ErrEgressPairingViolated reports a rendered profile that requested
// allow_internet_egress but carries no network grant — the implies-pairing broken.
// allow_internet_egress IMPLIES allow_network, so a
// generated profile that dropped the grant would leave a workload that declared it
// needs the internet with no network at all.
var ErrEgressPairingViolated = errors.New("sbpl: allow_internet_egress did not yield a network grant")

// networkRequested reports whether sp asks for network access by either route.
//
// allow_internet_egress IMPLIES allow_network: the implication is honoured here,
// in translation, rather than by rejecting a profile that sets only the egress
// flag. That choice is deliberate — the two flags do not describe two enforcement
// tiers on macOS, they describe an ADMISSION intent ("this workload may reach the
// internet") that this layer cannot narrow, so a pod carrying only the egress flag
// is a pod that needs networking and gets exactly the stanza allow_network gets.
//
// What the pair is for, since Seatbelt cannot enforce the difference: the flag is
// the API/admission contract a cluster operator can see and refuse (the annotation
// + the admission policy that reads it). Network-LAYER enforcement (a packet
// filter) is future work owned by the networking datapath, and until it exists
// runtimed must not claim it — see the ceiling comment on networkStanza.
func networkRequested(sp *runtimev1.SandboxProfile) bool {
	return sp.GetAllowNetwork() || sp.GetAllowInternetEgress()
}

// ValidateNetworkScope checks a RENDERED profile's network grant against what sp
// requested. It is the re-scoped network check — scoped to
// what macOS 26 can actually express, which is the shape of the grant, never a
// per-IP filter it would reject at compile time:
//
//  1. a network allow appears only when allow_network ∨ allow_internet_egress;
//  2. the implies-pairing holds — allow_internet_egress yields a network grant;
//  3. the grant is byte-for-byte the stanza this generator emits;
//  4. every network-address filter in the profile — (remote ip …) or (local ip …),
//     on an allow OR a deny — names `localhost` or `*` as its host, never an
//     address literal or a hostname. Port-only forms like (local ip "*:8899") are
//     the valid narrowing and stay valid.
//
// Generate calls it on its own output, so a future edit that widens, narrows, or
// reorders the stanza fails at generation rather than at sandbox_apply. It is
// EXPORTED because it also serves a caller holding a profile it did not generate.
//
// It is deliberately separate from Validate, which takes only a profile string and
// is what a Backend runs before applying one: the properties here are relational —
// they can only be decided against the SandboxProfile that asked for the grant —
// so folding them into Validate would mean a check that silently cannot see half
// its own inputs.
//
// Detection is LOOSE and acceptance is strict, which is what makes it fail closed:
// any (allow …) line mentioning a network operation counts as a network grant
// (even a whitespace or dialect variant a naive equality test would miss), and
// only the exact stanza is then accepted.
//
// Rule 4 is the one property decided over DENY lines as well as allows, and it is
// decided FIRST and UNCONDITIONALLY — before the request booleans are even read —
// because an uncompilable host token is wrong in every profile, including one that
// asked for no network at all. Rules 1-3 stay allow-only: only an (allow …) can
// hand a pod authority it did not request, so the denied_local_ports lines and the
// AF_UNIX helper-socket block are neither a grant nor a mismatch, and a profile
// that only ever subtracts authority is not refused for doing so.
//
// Where rule 4 comes from: macOS 26 Seatbelt accepts only `localhost` or `*` as
// the host in a network-address filter (probed 2026-09-17 —
// "host must be * or localhost in network address"), and it refuses the deny form
// exactly as it refuses the allow form. A
// (deny network-outbound (remote ip "127.0.0.1:2379")) therefore does not tighten
// anything; it makes the whole profile fail to compile at sandbox_apply, so every
// pod carrying it dies at spawn. That is the same failure class, with the same
// remediation — write the host as localhost or * — as a per-IP allow, which is
// why it returns the same ErrNetworkStanzaMismatch rather than a new sentinel.
//
// Generate is this function's only caller today, and Generate emits no per-IP
// filter in any branch, so on generated output rule 4 can only ever fire on a
// future generator edit. The EXPORTED form exists for a caller holding a profile
// it did not generate, and that caller is the whole point of the rule: such a
// profile can carry any shape at all, and nothing else in the package would look
// at its deny lines. (An earlier version of this comment named the live-libsandbox
// compile test as the backstop for the deny shape. It is not one: that test feeds
// Generate's own output to sandbox-exec, so it can only ever see profiles this
// package wrote, and it never sees a foreign one.)
func ValidateNetworkScope(sp *runtimev1.SandboxProfile, profile string) error {
	// Rule 4, unconditionally: an address literal in ANY network filter, allow or
	// deny, requested or not, is a profile that will not compile.
	if err := validateNetworkFilterHosts(profile); err != nil {
		return err
	}
	hasStanza := strings.Contains(profile, networkStanza)
	hasAnyAllow := hasNetworkAllow(profile)
	// Read the two booleans directly rather than through networkRequested: that
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
	// The stanza is present; make sure it is the only network allow, so an extra
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

// networkAddressFilter matches one SBPL network-address filter — (remote ip "…")
// or (local ip "…") — and captures the quoted host:port it scopes to. The other
// filter kinds a network directive can carry (remote unix-socket, local tcp on
// older dialects) are not address filters and are not matched.
var networkAddressFilter = regexp.MustCompile(`\((?:remote|local)\s+ip\s+"([^"]*)"\)`)

// validateNetworkFilterHosts enforces rule 4 of ValidateNetworkScope: every
// network-address filter under a network directive names `localhost` or `*` as
// its host. Anything else — an IPv4 literal, an IPv6 literal, a hostname — makes
// libsandbox refuse the whole profile at sandbox_apply, so it is reported as
// ErrNetworkStanzaMismatch wrapped with the offending line.
//
// The host is the part before the LAST colon, so a port-only "*:8899" splits to
// host "*", "localhost:12379" to "localhost", and a bare "localhost" carrying no
// colon at all is kept whole. Splitting on the last colon rather than the first is
// what keeps an IPv6 literal from being read as a host of "fe80" or "": "fe80::1"
// splits to "fe80:" and "::1" to ":", and both are rejected, which is the verdict
// they need — neither compiles.
//
// Continuation lines are attributed to the directive that opened them, the same
// way countNetworkAllowLines does it, so a filter indented under a multi-line
// (deny network-outbound …) block is checked rather than skipped.
func validateNetworkFilterHosts(profile string) error {
	inNetworkDirective := false
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "(allow") || strings.HasPrefix(line, "(deny") {
			inNetworkDirective = namesNetworkOperation(line)
		}
		if !inNetworkDirective {
			continue
		}
		for _, m := range networkAddressFilter.FindAllStringSubmatch(line, -1) {
			host := m[1]
			if i := strings.LastIndex(host, ":"); i >= 0 {
				host = host[:i]
			}
			if host == "localhost" || host == "*" {
				continue
			}
			return fmt.Errorf("%w: network filter host %q is neither localhost nor * (macOS Seatbelt will not compile it): %s",
				ErrNetworkStanzaMismatch, host, line)
		}
	}
	return nil
}

// namesNetworkOperation reports whether a directive line names one of the network
// operations. It is the shared predicate behind the allow count and the filter-host
// check, so the two agree on what "a network directive" is.
func namesNetworkOperation(line string) bool {
	for _, op := range networkOperations {
		if strings.Contains(line, op) {
			return true
		}
	}
	return false
}

// countNetworkAllowLines counts the network-granting allow directive lines in
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
		if namesNetworkOperation(line) {
			n++
		}
	}
	return n
}
