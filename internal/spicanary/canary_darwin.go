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

package spicanary

/*
#cgo LDFLAGS: -lsandbox
#include <dlfcn.h>
#include <spawn.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

// Private/deprecated libsandbox SPI the Seatbelt backend links (not in the public
// <sandbox.h>). Taking the address of each symbol below forces the linker to
// resolve it; if a macOS update removes one the package fails to LINK, so CI goes
// red loudly instead of pods failing to confine at runtime (DESIGN §8 risk #1).
extern void *sandbox_compile_string(const char *data, void *params, char **error);
extern int   sandbox_apply(void *profile);
extern void  sandbox_free_error(char *error);

// k3sm_sandbox_symbols returns a non-zero value built from the symbol addresses,
// so the references cannot be optimized away.
static uintptr_t k3sm_sandbox_symbols(void) {
	uintptr_t s = 0;
	s ^= (uintptr_t)&sandbox_compile_string;
	s ^= (uintptr_t)&sandbox_apply;
	s ^= (uintptr_t)&sandbox_free_error;
	return s;
}

// The userspace-resource SPI the supervisor's memory subsystem links — all
// resolve from libSystem (no extra -l flag). They are canaried here, with the
// Seatbelt symbols, so an OS update that drops one fails the BUILD rather than
// surfacing as silent OOM-accounting / jetsam-probe / pressure-kill-mark loss
// at runtime:
//
//   - proc_pid_rusage   : PUBLIC (<libproc.h>, since 10.9) — the ri_phys_footprint
//                         memory sampler reads it; canaried because the whole
//                         OOMKilled + Summary path depends on it staying linkable.
//   - memorystatus_control : PRIVATE/deprecated jetsam SPI — NO public header
//                         declaration exists (only SYS_memorystatus_control in
//                         <sys/syscall.h>); declared here so the symbol is the
//                         load-bearing link check.
extern int proc_pid_rusage(int pid, int flavor, void *buffer);
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

//   - posix_spawnattr_setpcontrol_np : PRIVATE spawn SPI (XNU spawn_private.h,
//                         no SDK prototype) — pkg/supervisor (spawn) and
//                         internal/execshim (the pod exec) mark every pod
//                         process pcontrol-KILL with it. Same declaration as
//                         both call sites.
extern int posix_spawnattr_setpcontrol_np(posix_spawnattr_t *, const int);

// k3sm_resource_symbols returns a non-zero value built from the resource-SPI
// symbol addresses so the references cannot be optimized away.
static uintptr_t k3sm_resource_symbols(void) {
	uintptr_t s = 0;
	s ^= (uintptr_t)&proc_pid_rusage;
	s ^= (uintptr_t)&memorystatus_control;
	s ^= (uintptr_t)&posix_spawnattr_setpcontrol_np;
	return s;
}

// The code-signing SPI the runtime's restricted-process detection calls
// (pkg/supervisor CodeSignStatus). csops has NO public header declaration
// (the kernel's <sys/codesign.h> is not in the SDK), exactly like
// memorystatus_control, so it is declared here and its address is the
// load-bearing link check: an OS update that drops the export fails the BUILD
// instead of silently turning the detection into a permanent fail-open.
extern int csops(int pid, unsigned int ops, void *useraddr, size_t usersize);

static uintptr_t k3sm_codesign_symbols(void) {
	return (uintptr_t)&csops;
}

// k3sm_dlsym_resolves reports whether name resolves in the process's global
// symbol scope at run time — the per-name half of the canary, so a test can
// name each symbol it depends on instead of trusting an aggregate.
static int k3sm_dlsym_resolves(const char *name) {
	return dlsym(RTLD_DEFAULT, name) != NULL;
}
*/
import "C"

import "unsafe"

// sandboxSymbolsResolve reports whether the libsandbox SPI symbols linked. It is
// always true on a healthy build (the value is non-zero because it is built from
// real symbol addresses); the LOAD-BEARING check is that this file LINKS at all.
func sandboxSymbolsResolve() bool {
	return uintptr(C.k3sm_sandbox_symbols()) != 0
}

// resourceSymbolsResolve reports whether the userspace-resource SPI symbols
// (proc_pid_rusage, memorystatus_control, posix_spawnattr_setpcontrol_np)
// linked. As with the sandbox set, the
// real guard is that this file LINKS at all — a removed export fails the build.
func resourceSymbolsResolve() bool {
	return uintptr(C.k3sm_resource_symbols()) != 0
}

// symbolResolves reports whether the named symbol resolves at run time through
// dlsym(RTLD_DEFAULT). Unlike the link-time aggregates above it answers for one
// name, so a want-list test is red for exactly the symbol that went missing.
func symbolResolves(name string) bool {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	return C.k3sm_dlsym_resolves(cName) != 0
}

// codesignSymbolsResolve reports whether the code-signing SPI (csops) linked.
// As with the other sets, the real guard is that this file LINKS at all.
func codesignSymbolsResolve() bool {
	return uintptr(C.k3sm_codesign_symbols()) != 0
}
