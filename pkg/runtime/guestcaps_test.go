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
	"testing"

	"k3sm.io/runtimed/pkg/guestagent"
)

// TestKnownGuestCapabilityCoversAgentTokens pins the host half of the
// capability vocabulary: every token the same build's agent advertises is one
// the host retains. A token missing from knownGuestCapability is discarded on
// every Health poll, so a host check for it would read a capable guest as an
// old one.
func TestKnownGuestCapabilityCoversAgentTokens(t *testing.T) {
	for _, tok := range guestagent.Capabilities() {
		if !knownGuestCapability(tok) {
			t.Errorf("the agent advertises %q but the host does not know it", tok)
		}
	}
	for _, tok := range []string{
		guestagent.CapabilityGuestPrivateMounts, guestagent.CapabilitySidecarInit, guestagent.CapabilityImageUser,
	} {
		if !knownGuestCapability(tok) {
			t.Errorf("knownGuestCapability(%q) = false", tok)
		}
	}
}
