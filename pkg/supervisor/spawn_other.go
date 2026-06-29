//go:build !(darwin && cgo)

/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
