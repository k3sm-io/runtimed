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
	"os/exec"
	"path/filepath"
)

// VMHostName is the basename of the per-pod VM host helper (one process per vm
// pod) that actually builds and boots the Linux guest. The runtime ships it
// beside its own binary, exactly as it ships ExecShimName.
//
// The SPLIT IS THE SECURITY DESIGN, not packaging tidiness: this helper is the
// ONLY k3sm binary signed with com.apple.security.virtualization, so the daemon
// — which parses images, talks to the apiserver's provider and serves a gRPC
// socket — carries no virtualization authority at all. Whatever the daemon can
// be made to do, it cannot create a VZVirtualMachine.
const VMHostName = "k3sm-vmhost"

// ErrVMHostNotFound reports that the k3sm-vmhost helper could not be located.
var ErrVMHostNotFound = errors.New("sandbox: k3sm-vmhost helper not found")

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

// FindVMHost locates the k3sm-vmhost helper: first beside the current
// executable, then on PATH. It returns ErrVMHostNotFound if neither resolves.
//
// It is a STRUCTURAL MIRROR of FindExecShim — same two candidates, same order,
// same sentinel shape — because the two helpers have the same deployment story
// (installed next to the daemon, resolvable on PATH in a dev tree) and a reader
// who has understood one should not have to re-derive the other.
func FindVMHost() (string, error) {
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), VMHostName)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	if p, err := exec.LookPath(VMHostName); err == nil {
		return p, nil
	}
	return "", ErrVMHostNotFound
}

// ProcessVirtualizationEntitled reports whether THIS process's static code
// signature carries com.apple.security.virtualization. Off the darwin+cgo lane
// it is false.
//
// It exists for the k3sm-vmhost helper's own startup PREFLIGHT: constructing a
// VZVirtualMachine without the entitlement raises an uncaught NSException →
// SIGABRT, so the helper checks first and exits with a legible message instead of
// dying with a crash report. The daemon does NOT gate on it — the daemon is
// deliberately unentitled (see VMHostName), and VMBackend.Available() asks about
// the HELPER's signature instead.
func ProcessVirtualizationEntitled() bool { return vzEntitled() }
