//go:build darwin

package runtime

import (
	"os"

	"golang.org/x/sys/unix"
)

// killSignal is SIGKILL as the unix.Signal concrete type the supervisor's
// SignalGroup expects (a plain os.Signal whose dynamic type is unix.Signal).
var killSignal os.Signal = unix.SIGKILL
