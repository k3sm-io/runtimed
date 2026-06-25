//go:build !(darwin && cgo)

package supervisor

// PhysFootprinter off darwin/cgo is a non-functional stub so the package builds
// for linux CI; production runs on darwin (proc_pid_rusage is a darwin SPI).
type PhysFootprinter struct{}

// Footprint is unsupported off darwin/cgo.
func (PhysFootprinter) Footprint(int) (uint64, error) { return 0, errUnsupported }
