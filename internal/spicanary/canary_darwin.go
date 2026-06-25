//go:build darwin && cgo

package spicanary

/*
#cgo LDFLAGS: -lsandbox
#include <stdint.h>

// Private/deprecated libsandbox SPI the Seatbelt backend links (NOT in the public
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
*/
import "C"

// sandboxSymbolsResolve reports whether the libsandbox SPI symbols linked. It is
// always true on a healthy build (the value is non-zero because it is built from
// real symbol addresses); the LOAD-BEARING check is that this file LINKS at all.
func sandboxSymbolsResolve() bool {
	return uintptr(C.k3sm_sandbox_symbols()) != 0
}
