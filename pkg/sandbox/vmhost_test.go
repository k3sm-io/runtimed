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

// TestGuestRosettaShareWithheld is B229's pkg/sandbox half: the node's
// guest-Rosetta advertisement is gated on what the k3sm-vmhost helper BUILDS, and
// this build's helper attaches no Rosetta share.
//
// It asserts a constant on purpose. There is no host fact to observe here — the
// question is what this repo's source does — so the test's job is to make flipping
// the advertisement a deliberate, reviewed edit rather than an accident of some
// unrelated refactor.
func TestGuestRosettaShareWithheld(t *testing.T) {
	if VMHostRosettaShareSupported {
		t.Fatal("VMHostRosettaShareSupported is true, but k3sm-vmhost attaches no Rosetta share: " +
			"a node would advertise guest-Rosetta, pkg/image would add linux/amd64 as a pull " +
			"candidate for every vm pod, and every amd64 image would be pulled and then fail to exec")
	}
	if NewVMBackend().GuestRosettaShareSupported() {
		t.Error("VMBackend.GuestRosettaShareSupported() = true; want false while the helper attaches no share")
	}
}
