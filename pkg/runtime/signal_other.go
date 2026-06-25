//go:build !darwin

package runtime

import "os"

// killSignal/termSignal off darwin (os.Kill / os.Interrupt); the supervisor's
// SignalGroup is a stub there, so these are only for the package to build on
// non-darwin CI.
var (
	killSignal os.Signal = os.Kill
	termSignal os.Signal = os.Interrupt
)
