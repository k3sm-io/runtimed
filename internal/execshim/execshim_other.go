//go:build !(darwin && cgo)

package execshim

import (
	"errors"

	"k3sm.io/runtimed/pkg/supervisor"
)

// ErrUnsupported reports that the libsandbox exec-shim is only available on
// darwin with cgo enabled.
var ErrUnsupported = errors.New("execshim: libsandbox confinement requires darwin+cgo")

// RunPodLaunch is unsupported off darwin/cgo; it returns ErrUnsupported so the
// helper fails closed rather than execing a pod unconfined.
func RunPodLaunch(profile string, argv []string, cred supervisor.Credential) error {
	return ErrUnsupported
}
