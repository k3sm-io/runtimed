//go:build !(darwin && cgo)

package spicanary

// sandboxSymbolsResolve is only meaningful on darwin+cgo (where libsandbox is
// linked); off it the canary is vacuously satisfied so the package builds for
// non-darwin CI.
func sandboxSymbolsResolve() bool { return true }

// resourceSymbolsResolve mirrors sandboxSymbolsResolve for the M2 resource SPI:
// only meaningful on darwin+cgo, vacuously satisfied elsewhere.
func resourceSymbolsResolve() bool { return true }
