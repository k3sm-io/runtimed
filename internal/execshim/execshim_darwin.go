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

package execshim

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>

// Private, deprecated libsandbox SPI — not declared in the public <sandbox.h>.
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
	"fmt"
	"unsafe"
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
