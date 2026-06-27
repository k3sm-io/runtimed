//go:build !(darwin && cgo)

package sandbox

// vzSupported / vzEntitled are the OFF-PLATFORM vm-backend probes: on any build
// lane that is NOT darwin+cgo — notably CGO_ENABLED=0 (which excludes the
// Virtualization.framework cgo shim, vm_darwin.go) and every non-darwin OS — they
// report false, so VMBackend.Available() is false and the pure-Go build lane stays
// unbroken. The vm backend can only run a guest on a Virtualization.framework-
// capable, entitled darwin host built with cgo.
func vzSupported() bool { return false }

func vzEntitled() bool { return false }
