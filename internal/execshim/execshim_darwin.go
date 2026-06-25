//go:build darwin && cgo

package execshim

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>

// Private, deprecated libsandbox SPI — NOT declared in the public <sandbox.h>.
// Modern libsandbox.1.dylib signatures (validated on macOS 26.5.1, arm64):
//   sandbox_compile_string returns an opaque profile handle (NULL on failure)
//   and sets *error to a malloc'd message; sandbox_apply confines the calling
//   process to that handle irreversibly. Documented per the standards (private
//   SPI behind a clean Go interface + the CI symbol-canary).
extern void *sandbox_compile_string(const char *data, void *params, char **error);
extern int   sandbox_apply(void *profile);
extern void  sandbox_free_error(char *error);

// k3sm_apply_sbpl compiles `profile` and applies it to the current process.
// Returns 0 on success. On failure returns non-zero and sets *errmsg to a
// malloc'd, caller-freed message (or NULL). On success *errmsg is NULL.
static int k3sm_apply_sbpl(const char *profile, char **errmsg) {
	char *err = NULL;
	void *p = sandbox_compile_string(profile, NULL, &err);
	if (p == NULL) {
		if (err != NULL) {
			// hand the message to Go (copied), then free libsandbox's buffer.
			*errmsg = err;
		} else {
			*errmsg = NULL;
		}
		return 1;
	}
	if (sandbox_apply(p) != 0) {
		*errmsg = NULL;
		return 2;
	}
	*errmsg = NULL;
	return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// confine compiles+applies the SBPL profile to the current process via
// libsandbox. After it returns nil the process is irreversibly sandboxed.
func confine(profile string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	var cErr *C.char
	rc := C.k3sm_apply_sbpl(cProfile, &cErr)
	if rc == 0 {
		return nil
	}
	msg := ""
	if cErr != nil {
		msg = C.GoString(cErr)
		C.sandbox_free_error(cErr)
	}
	if msg == "" {
		return fmt.Errorf("libsandbox apply failed (rc=%d)", int(rc))
	}
	return fmt.Errorf("libsandbox apply failed (rc=%d): %s", int(rc), msg)
}

// ConfineAndExec applies the SBPL profile to the current process and then
// execve's argv[0] with argv, PRESERVING the current process environment (so
// DYLD_INSERT_LIBRARIES survives into the pod). It never returns on success
// (the image is replaced); any return is an error.
func ConfineAndExec(profile string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("execshim: empty argv")
	}
	if err := confine(profile); err != nil {
		return err
	}
	// os.Environ() is the inherited environment, unmodified — this is the
	// load-bearing guarantee: DYLD_INSERT_LIBRARIES set by the supervisor flows
	// through to the pod process.
	if err := unix.Exec(argv[0], argv, os.Environ()); err != nil {
		return fmt.Errorf("execve %s: %w", argv[0], err)
	}
	return nil // unreachable on success
}
