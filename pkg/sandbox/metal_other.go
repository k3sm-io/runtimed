//go:build !(darwin && cgo)

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

// probeMetal is the off-PLATFORM functional Metal probe: on any lane that is not
// darwin+cgo the Metal shim is not compiled in, so the probe cannot answer and
// reports UnsupportedBuild — "this build cannot ask" is a different fact from "this
// host has no GPU", and the Reason token keeps them apart the way the vm backend's
// GuestRosettaQueryFailed does. Either way the verdict fails closed: not functional,
// so the node advertises no GPU.
func probeMetal() MetalStatus {
	return MetalStatus{Reason: MetalReasonUnsupportedBuild}
}
