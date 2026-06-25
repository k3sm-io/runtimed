// Package execshim is the in-process Seatbelt apply + execve core of the
// k3sm-execshim helper. It exposes a single Go function, ConfineAndExec, that
// compiles+applies an SBPL profile to the CURRENT process via the private
// libsandbox SPI and then execve's the pod binary, preserving the environment.
//
// This is the only place the libsandbox cgo lives (execshim_darwin.go); it is
// linked into the cmd/k3sm-execshim helper. The helper is the M1 sandbox.Backend
// implementation: a tiny ad-hoc-signed binary the supervisor posix_spawns. Keeping
// the apply+exec in a leaf package (not in main) makes the SPI surface a single,
// canary-able symbol set and keeps cmd/k3sm-execshim's main thin.
//
// libsandbox SPI used (private + deprecated; see DESIGN §8 risk #1 and the CI
// symbol-canary in internal/spicanary):
//
//	void *sandbox_compile_string(const char *data, void *params, char **error);
//	int   sandbox_apply(void *profile);
//	void  sandbox_free_error(char *error);
//
// sandbox_compile_string returns an opaque profile handle (NULL on failure);
// sandbox_apply confines the calling process to it irreversibly. These are NOT
// declared in the public <sandbox.h>; we declare them extern and link -lsandbox.
package execshim
