//go:build darwin && cgo

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

/*
#cgo darwin LDFLAGS: -framework Virtualization -framework Foundation -framework CoreFoundation -framework Security
#include "vm_darwin.h"
*/
import "C"

// vzSupported reports +[VZVirtualMachine isSupported] via the Obj-C shim
// (vm_darwin.m) — a SAFE probe that never constructs a VM. See VMBackend.
func vzSupported() bool {
	return C.k3sm_vz_supported() != 0
}

// vzEntitled reports whether this process's static code-signing information
// carries com.apple.security.virtualization == true, read via Security.framework
// in the Obj-C shim. The vm backend gates on it because instantiating a
// VZVirtualMachine WITHOUT the entitlement raises an uncaught NSException →
// SIGABRT, so the probe must determine entitlement presence without ever touching
// Virtualization.framework's VM-construction path.
func vzEntitled() bool {
	return C.k3sm_vz_has_entitlement() != 0
}

// vzRosettaAvailability reports the host's Rosetta-for-Linux (GUEST translation)
// availability via the Obj-C shim's +[VZLinuxRosettaDirectoryShare availability]
// class-property read — a SAFE, ENTITLEMENT-FREE probe that constructs no object
// and never attempts an install (B103). The raw 3-valued enum is preserved, plus
// the shim's QUERY_FAILED sentinel; see GuestRosettaState and ProbeGuestRosetta.
//
// The shim's own arch guard makes the non-arm64 compile lane return NOT_SUPPORTED,
// so this wrapper is arch-agnostic.
func vzRosettaAvailability() GuestRosettaState {
	switch C.k3sm_vz_rosetta_availability() {
	case C.K3SM_VZ_ROSETTA_INSTALLED:
		return GuestRosettaInstalled
	case C.K3SM_VZ_ROSETTA_NOT_INSTALLED:
		return GuestRosettaNotInstalled
	case C.K3SM_VZ_ROSETTA_NOT_SUPPORTED:
		return GuestRosettaNotSupported
	default:
		return GuestRosettaQueryFailed
	}
}
