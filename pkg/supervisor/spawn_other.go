//go:build !(darwin && cgo)

package supervisor

import (
	"context"
	"errors"
	"os"
)

// errUnsupported reports that native spawn/reap is only available on darwin+cgo.
var errUnsupported = errors.New("supervisor: native posix_spawn/kqueue requires darwin+cgo")

// PosixSpawner off darwin/cgo is a non-functional stub so the package builds for
// linux CI; production runs on darwin.
type PosixSpawner struct{}

// Spawn is unsupported off darwin/cgo.
func (PosixSpawner) Spawn(context.Context, SpawnSpec) (int, error) { return 0, errUnsupported }

// KqueueReaper off darwin/cgo is a non-functional stub.
type KqueueReaper struct{}

// WaitExit is unsupported off darwin/cgo.
func (KqueueReaper) WaitExit(context.Context, int) (int, int, error) { return 0, 0, errUnsupported }

// SignalGroup is unsupported off darwin/cgo.
func SignalGroup(int, os.Signal) error { return errUnsupported }
