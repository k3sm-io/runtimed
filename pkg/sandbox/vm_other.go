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

// vzSupported / vzEntitled are the OFF-PLATFORM vm-backend probes: on any build
// lane that is NOT darwin+cgo — notably CGO_ENABLED=0 (which excludes the
// Virtualization.framework cgo shim, vm_darwin.go) and every non-darwin OS — they
// report false, so VMBackend.Available() is false and the pure-Go build lane stays
// unbroken. The vm backend can only run a guest on a Virtualization.framework-
// capable, entitled darwin host built with cgo.
func vzSupported() bool { return false }

func vzEntitled() bool { return false }
