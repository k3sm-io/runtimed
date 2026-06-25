//go:build !darwin

package sandbox

import "errors"

// darwinMajorVersion is unsupported off darwin; the exec-shim backend reports
// Available() == false there (the runtime then fails closed).
func darwinMajorVersion() (int, error) {
	return 0, errors.New("sandbox: macOS version unavailable on non-darwin")
}
