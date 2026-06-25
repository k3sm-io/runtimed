package spicanary

import "testing"

// TestSymbolsResolve is the symbol-canary: on darwin+cgo it confirms the private
// libsandbox SPI (sandbox_compile_string / sandbox_apply / sandbox_free_error)
// still links on the current macOS. The real guard is that canary_darwin.go LINKS
// at all — a removed symbol fails the build. This test makes the canary runnable
// from the standard `go test` gate and on every OS beta in CI.
func TestSymbolsResolve(t *testing.T) {
	if !sandboxSymbolsResolve() {
		t.Fatal("libsandbox SPI symbols did not resolve (an OS update may have removed them)")
	}
}
