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

package main

import "runtime"

// The host-derived machine-size bounds FromSpec clamps a spec into.
//
// They are read from the HOST rather than pinned, because the answer differs per
// Mac and a pinned ceiling would either refuse legitimate pods on a big machine or
// accept impossible ones on a small one. Clamping rather than rejecting an
// over-large request is the deliberate choice FromSpec documents: a pod asking for
// more vCPUs than this Mac has is a scheduling mismatch the node should still run,
// degraded, rather than a pod that can never start anywhere.

// minVCPUs / maxVCPUs / defaultVCPUs bound the guest's CPU count.
//
// maxVCPUs is the host's logical CPU count: Virtualization.framework's own maximum
// is at most that, and over-committing a micro-VM past the host's core count buys
// a guest nothing but scheduler contention. defaultVCPUs is deliberately small —
// a pod that did not ask for CPUs is not asking for the machine.
func minVCPUs() uint { return 1 }

func maxVCPUs() uint {
	n := runtime.NumCPU()
	if n < 1 {
		return 1
	}
	return uint(n)
}

func defaultVCPUs() uint {
	if maxVCPUs() < 2 {
		return 1
	}
	return 2
}

// minMemoryBytes / maxMemoryBytes / defaultMemoryBytes bound the guest's RAM.
//
// The minimum is the floor a Linux guest with a virtiofs root and an overlay upper
// will actually boot in; below it the guest OOMs during init and the pod fails for
// a reason that looks like the workload's fault. The maximum is left to the
// framework's own validation (0 = unbounded here): the host's physical memory is
// not the right ceiling either, since the VM is not resident, and
// VZVirtualMachineConfiguration.Validate refuses what the framework will not take.
func minMemoryBytes() uint64     { return 128 << 20 }
func maxMemoryBytes() uint64     { return 0 }
func defaultMemoryBytes() uint64 { return 512 << 20 }
