//go:build !darwin

package runtime

import (
	"errors"
	"os"
)

// errPTYUnsupported reports that a tty exec (pty allocation) is darwin-only. The
// runtime targets macOS; this stub lets the package build and run its non-tty
// exec tests on linux CI. A tty exec off darwin fails closed with this error.
var errPTYUnsupported = errors.New("runtime: tty exec (pty) requires darwin")

func openPTY() (*os.File, *os.File, error) { return nil, nil, errPTYUnsupported }

func setWinsize(*os.File, uint16, uint16) error { return errPTYUnsupported }
