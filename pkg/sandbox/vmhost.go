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

// VMHostRosettaShareSupported reports whether the k3sm-vmhost helper attaches a
// Rosetta directory share to the guests it builds. It is FALSE in this build,
// and the falsehood is the POINT (B229).
//
// A node advertises guest-Rosetta as VMBackendAvailable AND RosettaGuestAvailable
// (see pkg/runtime's ConditionRosettaGuestAvailable), and the image-pull platform
// policy turns that capability into "linux/amd64 is a legal pull candidate for a
// vm pod". Apple's +[VZLinuxRosettaDirectoryShare availability] can perfectly
// well say Installed on this Mac while the helper attaches no share — and then
// every amd64 image would be pulled and then fail to execute, because nothing in
// the guest can translate it. Gating the advertisement on THIS constant makes the
// demotion structural: the capability comes back only when the helper is changed
// to attach the share and this constant is flipped in the same commit.
//
// It is deliberately a compile-time constant, not a probe: there is no host fact
// to observe. What is being reported is what the helper BUILDS, which is decided
// by this repo's source and nothing else.
//
// SINGLE-HOME CAVEAT. The helper's own copy of this fact is
// k3sm.io/runtimed/pkg/vmhost.RosettaShareSupported, and this package cannot
// import that one: pkg/vmhost imports github.com/Code-Hex/vz, and pkg/sandbox is
// imported by pkg/runtime, so the import would drag the Virtualization-linking
// module into the daemon binary — the exact coupling the helper split exists to
// prevent. The two constants are bound by a TEST instead
// (pkg/vmhost.TestRosettaShareCapabilityIsSingleValued), which may import both.
const VMHostRosettaShareSupported = false
