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

// Package execshim is the in-process privilege-drop + Seatbelt apply + execve
// core of the k3sm-execshim helper. It exposes a single Go function, RunPodLaunch,
// that — in the irreversible order supervisor.RunLaunchSequence enforces — drops
// to the pod's securityContext identity (setgid→initgroups→setuid), compiles and
// applies an SBPL profile to the current process via the private libsandbox SPI,
// and then execve's the pod binary, preserving the environment.
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
// sandbox_apply confines the calling process to it irreversibly. These are not
// declared in the public <sandbox.h>; we declare them extern and link -lsandbox.
package execshim
