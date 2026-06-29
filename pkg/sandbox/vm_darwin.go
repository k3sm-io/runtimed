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
