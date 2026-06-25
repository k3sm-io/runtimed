//go:build darwin

package runtime

import (
	"os"

	"golang.org/x/sys/unix"
)

// killSignal is SIGKILL and termSignal is SIGTERM, as the unix.Signal concrete
// type the supervisor's SignalGroup expects (a plain os.Signal whose dynamic type
// is unix.Signal). termSignal is the graceful-stop first signal (M2.4); killSignal
// the escalation / immediate kill.
var (
	killSignal os.Signal = unix.SIGKILL
	termSignal os.Signal = unix.SIGTERM
)
