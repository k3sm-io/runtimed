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
#cgo darwin LDFLAGS: -framework Metal -framework Foundation
#include "metal_darwin.h"
*/
import "C"

// probeMetal runs the functional Metal probe through the Obj-C shim
// (metal_darwin.m): compile a kernel, dispatch it, verify the results, and report
// whether the device is the VZ paravirtual one.
//
// Metal.framework is a PUBLIC framework, so — exactly like Virtualization.framework
// for the vm backend — this is not a symbol-canary case; do not add Metal symbols to
// internal/spicanary.
//
// The probe is synchronous and unbounded by a timeout of its own, which is safe for
// its one production caller (Runtime construction, once per daemon lifetime): every
// leg is a local GPU driver call with no network, no fork, and no lock this process
// holds. It is deliberately not run per pod.
func probeMetal() MetalStatus {
	var facts C.k3sm_metal_facts
	C.k3sm_metal_probe(&facts)
	return MetalStatus{
		Functional:                    facts.functional != 0,
		Paravirtual:                   facts.paravirtual != 0,
		DeviceName:                    C.GoString(&facts.device_name[0]),
		RecommendedMaxWorkingSetBytes: uint64(facts.recommended_max_working_set),
		Reason:                        metalReasonToken(facts.reason),
	}
}

// metalReasonToken maps the shim's reason enum to the exported machine token. An
// unrecognized value — a reason added to the shim without a token here — reports
// UnsupportedBuild rather than being folded into a known outcome, so a mapping gap
// is visible instead of mislabelled.
func metalReasonToken(reason C.int) string {
	switch reason {
	case C.K3SM_METAL_OK:
		return MetalReasonOK
	case C.K3SM_METAL_NO_DEVICE:
		return MetalReasonNoDevice
	case C.K3SM_METAL_PARAVIRTUAL:
		return MetalReasonParavirtual
	case C.K3SM_METAL_COMPILE_FAILED:
		return MetalReasonCompileFailed
	case C.K3SM_METAL_DISPATCH_FAILED:
		return MetalReasonDispatchFailed
	case C.K3SM_METAL_WRONG_RESULT:
		return MetalReasonWrongResult
	default:
		return MetalReasonUnsupportedBuild
	}
}
