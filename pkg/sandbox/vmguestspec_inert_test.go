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

import "testing"

// TestGuestSpecSetsNoUnpinnedGuestFields pins that this host's composer sets
// none of GuestContainer.sidecar, GuestContainer.image_user or
// GuestMount.guest_private. A guest that predates a field refuses a spec that
// sets it, so a host may set one only together with a pinned initramfs that
// knows it; until that pin lands, every composed spec must leave all three at
// their zero value (and so absent from guest-spec.json). The change that
// re-pins the initramfs and adds the producers replaces this test.
func TestGuestSpecSetsNoUnpinnedGuestFields(t *testing.T) {
	t.Parallel()
	gs, err := buildGuestSpec(guestSpecFixture())
	if err != nil {
		t.Fatalf("buildGuestSpec: %v", err)
	}
	if len(gs.GetContainers()) == 0 || len(gs.GetMounts()) == 0 {
		t.Fatal("the fixture composed no containers or no mounts; the pin would be vacuous")
	}
	for _, c := range gs.GetContainers() {
		if c.GetSidecar() || c.GetImageUser() != "" {
			t.Errorf("container %q sets sidecar=%v image_user=%q", c.GetName(), c.GetSidecar(), c.GetImageUser())
		}
	}
	for _, m := range gs.GetMounts() {
		if m.GetGuestPrivate() {
			t.Errorf("mount %q sets guest_private", m.GetTarget())
		}
	}
}
