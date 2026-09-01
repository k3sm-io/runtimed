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

// Package sandbox generates per-pod default-deny Seatbelt (SBPL) profiles and
// applies them to native pod processes.
//
// The model (k3sm/docs/DESIGN.md §5a) runs pods as native Darwin processes at
// their real host paths — NO chroot, which SIP makes impossible — confined by a
// Seatbelt profile. The validated proof is prototypes/seatbelt-hostpath/pod.sb:
// a Foundation-linked arm64 binary launches, links the dyld shared cache, sees
// /System, is denied /Users, and writes only its pod dir. This package is the
// productionized, tightened generator plus the application backend.
//
// Two pieces:
//
//   - Generate turns a SandboxProfile (from the apis PodBox) into an SBPL string.
//     It is pure Go and exhaustively unit-tested against golden files. The
//     generated profile always begins (deny default) and (import "system.sb")
//     (the dyld/mach baseline — without it every binary aborts with SIGABRT
//     during dynamic-linker init) and tightens the prototype: it denies
//     /private/var/db (except the documented dyld-only read exception), denies
//     other pods' dirs, and scopes file-write* to the pod data volume only.
//
//   - Backend is the swappable application seam. The M1 implementation is a
//     non-PLATFORM exec-shim: a tiny ad-hoc-signed helper (cmd/k3sm-execshim)
//     that compiles+applies the profile via libsandbox in-process, then
//     execve(pod, argv, envp) preserving envp. It deliberately does not use
//     Apple's /usr/bin/sandbox-exec, which is a platform binary that strips
//     DYLD_* from the environment and would break the DNS shim (Wave-0
//     confirmed this live). The backend is OS-version-gated and FAILS closed:
//     if unavailable it refuses to start the pod rather than running unconfined.
//
// The cgo libsandbox SPI (sandbox_compile_string / sandbox_apply) is private and
// deprecated; it is isolated in execshim_darwin.go behind this package and a
// CI symbol-canary (internal/spicanary), per the standards.
package sandbox
