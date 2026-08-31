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
// IT IS THE CONSTANT THE HANDSHAKE WAS WAITING FOR. guest.proto specifies the
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
// BUMP IT ONLY FOR A WIRE-INCOMPATIBLE CHANGE, and never for an additive one:
// guest.proto is additive-only forever, and HealthResponse.capabilities exists
// precisely so a new feature can be negotiated WITHOUT a version bump. A bump that
// was not needed fails every pod on a correct pairing.
const APIVersion = "k3sm.guest.v1"
