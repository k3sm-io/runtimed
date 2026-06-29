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

import "testing"

// TestSymbolsResolve is the libsandbox half of the symbol-canary: on darwin+cgo
// it confirms the private libsandbox SPI (sandbox_compile_string / sandbox_apply
// / sandbox_free_error) still links on the current macOS. The real guard is that
// canary_darwin.go LINKS at all — a removed symbol fails the build. This test
// makes the canary runnable from the standard `go test` gate and on every OS beta
// in CI.
func TestSymbolsResolve(t *testing.T) {
	if !sandboxSymbolsResolve() {
		t.Fatal("libsandbox SPI symbols did not resolve (an OS update may have removed them)")
	}
}

// TestResourceSymbolsResolve is the M2 half of the symbol-canary (acceptance
// M2.1-a2): it asserts the userspace-resource SPI the M2.5 memory subsystem links
// — proc_pid_rusage (public, <libproc.h>) and memorystatus_control (private
// jetsam SPI, no public header) — still resolves on the current macOS. As with
// the libsandbox half, the load-bearing check is that canary_darwin.go LINKS; a
// dropped export fails the build before the runtime can silently lose OOM
// accounting at runtime.
func TestResourceSymbolsResolve(t *testing.T) {
	if !resourceSymbolsResolve() {
		t.Fatal("M2 resource SPI symbols (proc_pid_rusage / memorystatus_control) did not resolve (an OS update may have removed them)")
	}
}
