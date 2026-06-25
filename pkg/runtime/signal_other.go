//go:build !darwin

package runtime

import "os"

// killSignal is SIGKILL off darwin (os.Kill); the supervisor's SignalGroup is a
// stub there, so this is only for the package to build on non-darwin CI.
var killSignal os.Signal = os.Kill
