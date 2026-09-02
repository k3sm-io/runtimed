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

// APIVersion is the guest/v1 contract version this agent speaks, reported in
// HealthResponse.api_version.
//
// It is the constant the handshake was waiting for. guest.proto specifies the
// field and states the rule — a host that dials an agent speaking a different
// api_version must fail the pod with that stated reason rather than proceed and
// discover the mismatch as malformed streams — but neither end defined a value, so
// the skew the docs call "unsupported but legible" was in fact illegible.
//
// The value is the proto package name, because that IS the contract's identity: an
// agent speaking k3sm.guest.v1 and a host speaking k3sm.guest.v1 agree on every
// message on the wire. Compat is LOCKSTEP via the in-code initramfs sha256 pin —
// the supported configuration is exactly the daemon paired with the initramfs its
// own pin names — so this constant is not a negotiation mechanism. It is a
// tripwire for the one reachable way to get an unsupported pairing: the dev-lab
// --guest-artifacts-dir override.
//
// BUMP IT only for A WIRE-INCOMPATIBLE change, and never for an additive one:
// guest.proto is additive-only forever, and HealthResponse.capabilities exists
// precisely so a new feature can be negotiated without a version bump. A bump that
// was not needed fails every pod on a correct pairing.
const APIVersion = "k3sm.guest.v1"

// The capability tokens this agent advertises in HealthResponse.capabilities.
//
// They exist because APIVersion must NOT be bumped for an additive change
// (see above), and yet a host still has to be able to tell a guest that can
// serve a verb from one that cannot. The `--guest-artifacts-dir` dev-lab
// override is the one reachable way to pair a daemon with an initramfs older
// than itself, and a host that sent an unsupported request into such a guest
// got a bare `Unimplemented: method Attach not implemented` — technically the
// truth, and useless to the operator, who cannot tell it from a bug.
//
// A token is ADD-ONLY and its spelling is WIRE. Never rename one: an old guest
// keeps advertising the old spelling forever, and a host that stopped
// recognizing it would refuse a guest that is in fact capable.
const (
	// CapabilityTTYExec reports that the agent can allocate a pseudo-terminal
	// for `kubectl exec -it` (the #112 exec-pty slice). An agent without it
	// refuses a tty exec outright.
	CapabilityTTYExec = "tty-exec"

	// CapabilityAttach reports that the agent serves the Attach RPC — that it
	// retains each container's stdio endpoints and can bridge a client to them.
	// An agent without it has no such endpoints to bridge to, so the verb is
	// missing rather than merely unimplemented.
	CapabilityAttach = "attach"
)

// Capabilities is the token set this build advertises, in a STABLE order so a
// Health response is byte-identical between polls (a set that reordered itself
// would make every poll look like a change to a consumer that compares).
//
// It is a function rather than a package var so no caller can append to the
// shipped slice and change what every future Health call reports.
func Capabilities() []string {
	return []string{CapabilityTTYExec, CapabilityAttach}
}
