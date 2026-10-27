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
// The libsandbox half landed with the Seatbelt exec-shim; the canary later grew to cover
// the userspace-resource SPI the memory subsystem links. The covered set:
//
//   - libsandbox:  sandbox_compile_string / sandbox_apply / sandbox_free_error /
//     sandbox_free_profile / sandbox_check                                       (Seatbelt)
//   - SBPL grammar: the per-pod POSIX semaphore grant (sandbox.PosixSemStanza)    must compile
//   - libSystem:   proc_pid_rusage                                               (ri_phys_footprint sampler), PUBLIC but load-bearing
//   - libSystem:   memorystatus_control                                          (jetsam probe), PRIVATE/deprecated SPI
//   - libSystem:   posix_spawnattr_setpcontrol_np                                (pod pressure-kill mark), PRIVATE SPI
//   - libSystem:   csops                                                         (restricted-process detection), PRIVATE SPI
//   - libsystem_kernel: open$NOCANCEL / openat$NOCANCEL                           (path shim interposer targets), non-public exports, checked by name through dlsym
//   - libc:        clonefile / clonefileat                                       (APFS CoW)      — covered via golang.org/x/sys/unix.Clonefile
//
// The resource symbols resolve from libSystem (no extra -l flag); proc_pid_rusage is a
// public <libproc.h> export but is canaried because the whole OOMKilled + Summary path
// depends on it staying linkable, and memorystatus_control and
// posix_spawnattr_setpcontrol_np have NO public SDK declaration at all.
// Note Virtualization.framework (the vm sandbox backend) is a PUBLIC framework and is explicitly
// not a canary case — do not add VZ symbols here.
//
// The grammar case differs from the symbol cases in what a failure costs: the runtime
// compiles the semaphore stanza itself before emitting it, so a macOS that rejects the
// spelling leaves pods with their semaphores denied rather than failing every pod.
// TestPosixSemStanzaCompiles makes that silent downgrade loud in CI.
//
// canary_darwin.go (cgo) takes the address of each symbol so the package fails to LINK if one
// vanishes; TestSymbolsResolve (libsandbox), TestResourceSymbolsResolve (the resource SPI) and
// TestCodeSignSymbolsResolve (csops) run in the standard go-test gate (hack/ci.sh), so
// running the tests on a new macOS release is what catches a removed symbol.
// TestResourceSymbolsWantList additionally names each resource symbol through dlsym, so a
// missing one is reported by name, and TestPathShimNocancelSymbolsWantList names the path
// shim's two NOCANCEL targets the same way. The canary sits
// beside the swappable sandbox.Backend so the "engine is replaceable" mitigation stays concrete.
package spicanary
