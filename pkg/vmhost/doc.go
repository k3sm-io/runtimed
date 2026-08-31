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

// Package vmhost builds and runs ONE vm-backend pod's Linux micro-VM. It is the
// library half of cmd/k3sm-vmhost, the per-pod helper process that is the only
// k3sm binary carrying com.apple.security.virtualization.
//
// # Dumb by design
//
// Every policy decision — which platform, which shares, how much memory, which
// image — has already been made by the time this package sees anything. A
// guestv1.VMHostSpec is a machine description, and this package is a translator:
// it validates the description, turns it into a machine, boots it, proxies one
// socket, and stops it. It decides nothing, and in particular it never inspects
// what the guest sends: the agent proxy relays bytes and does not speak gRPC.
//
// # The one-way translation, and why it is one-way
//
//	guestv1.VMHostSpec --FromSpec--> MachineConfig --realize--> *vz.VirtualMachineConfiguration
//
// MachineConfig is a pure Go value with no pointers into Objective-C and no
// dependency on the Virtualization framework, so ALL the validation — path
// containment, share-tag legality, pairwise-disjoint share roots, vcpu/memory
// clamping, read-only enforcement — lives in FromSpec and is table-testable on
// any OS, including a Linux CI lane and a Mac with no entitlement. realize is a
// mechanical field-for-field construction with no decisions left in it, and is
// the ONLY thing behind the darwin+cgo build tag.
//
// The direction matters: nothing converts a *vz.VirtualMachineConfiguration back
// into a MachineConfig, so there is no path by which framework state can become
// an input to a decision this package makes.
//
// # The import boundary
//
// github.com/Code-Hex/vz is reachable ONLY from this package (in vz_darwin.go)
// and from cmd/k3sm-vmhost. Nothing in pkg/runtime, pkg/sandbox, pkg/image,
// pkg/mount or pkg/supervisor may reach it, so the shipped k3sm daemon links no
// Virtualization framework at all. That boundary is what makes the entitlement
// split real rather than a packaging convention, and it is asserted mechanically
// rather than trusted (see TestVZIsNotReachableFromTheDaemon).
//
// # Not here
//
// This package does not pull, unpack or verify images; does not allocate
// addresses; does not talk to the apiserver; and does not decide what the pod
// contains. It also does not START anything on its own: cmd/k3sm-vmhost owns the
// process lifetime, and the runtime spine that spawns that helper is a separate
// deliverable — pkg/sandbox's CreateVM still returns ErrVMBootNotImplemented, so
// nothing in production reaches this package yet.
package vmhost
