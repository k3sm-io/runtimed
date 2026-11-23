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
//   - Backend is the swappable application seam. The host-process implementation
//     is a non-PLATFORM exec-shim: a tiny ad-hoc-signed helper (cmd/k3sm-execshim)
//     that compiles+applies the profile via libsandbox in-process, then
//     execve(pod, argv, envp) with envp built from the launch payload it read
//     on an inherited descriptor (the shim's own environ is empty, so a
//     pod-set DYLD_INSERT_LIBRARIES reaches the pod, never the unconfined
//     shim). It deliberately does not use
//     Apple's /usr/bin/sandbox-exec, which is a platform binary that strips
//     DYLD_* from the environment and would break the DNS shim (verified on
//     hardware). The backend is OS-version-gated and FAILS closed:
//     if unavailable it refuses to start the pod rather than running unconfined.
//
// Volume mount paths and binaries that do not load the path-rebase shim: a
// volume mounted at an absolute container path such as HOME=/home/agent is a
// symlink in the pod's data volume, reached through the path-rebase shim
// (shim/). git, xcrun and every other platform or library-validated binary
// never load that shim (dyld scrubs DYLD_* from them, or library validation
// refuses the dylib), so they resolve /home/agent on the host, where the PVC
// is not. The profile grants file-read-metadata on the host /home link node
// alone, so such a lookup answers ENOENT rather than EPERM and git runs
// without a global config, but it does not see a .gitconfig kept on the PVC.
// Point GIT_CONFIG_GLOBAL at the file's rootfs path (<data volume>/home/agent/
// .gitconfig), or give the pod a HOME that is not a mount symlink. The
// runtime sets xcrun_db to a file in the pod's own temp dir for the same
// class of binary: xcrun ignores DIRHELPER_USER_DIR_SUFFIX and would
// otherwise try the shared, denied /var/folders tree.
//
// The cgo libsandbox SPI is private and deprecated. sandbox_compile_string /
// sandbox_apply are called by the exec-shim (internal/execshim/execshim_darwin.go);
// this package only compiles, never applies, through the same SPI resolved by
// dlsym in posixsem_darwin.go (the semaphore grammar probe). A CI symbol-canary
// (internal/spicanary) links every symbol, per the standards.
package sandbox
