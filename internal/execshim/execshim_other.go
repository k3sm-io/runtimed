//go:build !(darwin && cgo)

package execshim

import "errors"

// ErrUnsupported reports that the libsandbox exec-shim is only available on
// darwin with cgo enabled.
var ErrUnsupported = errors.New("execshim: libsandbox confinement requires darwin+cgo")

// ConfineAndExec is unsupported off darwin/cgo; it returns ErrUnsupported so the
// helper fails closed rather than execing a pod unconfined.
func ConfineAndExec(profile string, argv []string) error {
	return ErrUnsupported
}
