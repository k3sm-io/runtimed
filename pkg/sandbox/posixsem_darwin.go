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
#include <dlfcn.h>
#include <stdlib.h>

// k3sm_sbpl_compiles compiles profile with libsandbox and frees the result,
// returning 1 when it compiled. Nothing is applied. The SPI is PRIVATE
// (sandbox_compile_string / sandbox_free_profile / sandbox_free_error have no
// public header) and is resolved through dlsym rather than linked, so a macOS
// that drops a symbol answers "does not compile" instead of failing the binary
// to load; internal/spicanary links the same symbols, so CI still goes red.
static int k3sm_sbpl_compiles(const char *profile) {
	void *h = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_LAZY | RTLD_LOCAL);
	if (h == NULL) {
		return 0;
	}
	void *(*compile)(const char *, void *, char **) = (void *(*)(const char *, void *, char **))dlsym(h, "sandbox_compile_string");
	void (*free_profile)(void *) = (void (*)(void *))dlsym(h, "sandbox_free_profile");
	void (*free_error)(char *) = (void (*)(char *))dlsym(h, "sandbox_free_error");
	int ok = 0;
	if (compile != NULL && free_profile != NULL && free_error != NULL) {
		char *err = NULL;
		void *p = compile(profile, NULL, &err);
		if (p != NULL) {
			ok = 1;
			free_profile(p);
		}
		if (err != NULL) {
			free_error(err);
		}
	}
	return ok;
}
*/
import "C"

import "unsafe"

// sbplCompiles reports whether this host's libsandbox compiles profile. It
// compiles only; nothing is applied to the calling process.
func sbplCompiles(profile string) bool {
	cs := C.CString(profile)
	defer C.free(unsafe.Pointer(cs))
	return C.k3sm_sbpl_compiles(cs) == 1
}
