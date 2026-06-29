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

// Package spicanary is the home of runtimed's CI symbol-canary: a test that asserts the
// private/deprecated Darwin SPI k3sm depends on still resolves on the current macOS, so an
// OS update that removes a symbol fails CI loudly instead of at runtime (DESIGN §8 risk #1).
//
// M1 landed the libsandbox half (the M1 Seatbelt exec-shim links it); M2.1 grows the canary
// to the userspace-resource SPI the M2.5 memory subsystem links. The covered set:
//
//   - libsandbox:  sandbox_compile_string / sandbox_apply / sandbox_free_error   (Seatbelt)      — M1
//   - libSystem:   proc_pid_rusage                                               (ri_phys_footprint sampler) — M2.1, PUBLIC but load-bearing
//   - libSystem:   memorystatus_control                                          (jetsam probe)  — M2.1, PRIVATE/deprecated SPI
//   - libc:        clonefile / clonefileat                                       (APFS CoW)      — covered via golang.org/x/sys/unix.Clonefile
//
// Both M2 resource symbols resolve from libSystem (no extra -l flag); proc_pid_rusage is a
// public <libproc.h> export but is canaried because the whole M2.5 OOMKilled + Summary path
// depends on it staying linkable, and memorystatus_control has NO public header at all.
// Note Virtualization.framework (the M5 vm backend) is a PUBLIC framework and is explicitly
// NOT a canary case — do not add VZ symbols here.
//
// canary_darwin.go (cgo) takes the address of each symbol so the package fails to LINK if one
// vanishes; TestSymbolsResolve (libsandbox) and TestResourceSymbolsResolve (M2 resource SPI)
// run from the standard go-test gate, the workspace hack/ci.sh, and the macOS CI on every OS
// beta. The canary sits beside the swappable sandbox.Backend so the "engine is replaceable"
// mitigation stays concrete.
package spicanary
