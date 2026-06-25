//go:build !(darwin && cgo)

package spicanary

// sandboxSymbolsResolve is only meaningful on darwin+cgo (where libsandbox is
// linked); off it the canary is vacuously satisfied so the package builds for
// non-darwin CI.
func sandboxSymbolsResolve() bool { return true }
