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

import (
	"slices"
	"testing"
)

// TestCapabilitiesAdvertiseGuestFieldTokens is the same-build pin for the three
// tokens guest/v1 names beside its newest fields: the agent built with the
// guest code that honours them advertises them, under their wire spellings.
// The host's side of the vocabulary (it must KNOW each token, or it discards
// it) is pinned in pkg/runtime by TestKnownGuestCapabilityCoversAgentTokens.
func TestCapabilitiesAdvertiseGuestFieldTokens(t *testing.T) {
	want := map[string]string{
		"guest-private-mounts": CapabilityGuestPrivateMounts,
		"sidecar-init":         CapabilitySidecarInit,
		"image-user":           CapabilityImageUser,
	}
	got := Capabilities()
	for wire, constant := range want {
		if constant != wire {
			t.Errorf("token constant = %q, want the wire spelling %q", constant, wire)
		}
		if !slices.Contains(got, wire) {
			t.Errorf("Capabilities() = %v, missing %q", got, wire)
		}
	}
}
