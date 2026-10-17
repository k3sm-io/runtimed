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

// Package wasmhosttest is test support for code that drives a wasmhost.Engine:
// a fail-closed fake that never runs guest code. It is imported only by tests.
package wasmhosttest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"k3sm.io/runtimed/pkg/wasmhost"
)

// wasmMagic is the four-byte preamble of every WebAssembly binary, core module
// and component alike.
var wasmMagic = []byte{0x00, 'a', 's', 'm'}

// ErrNotWasm reports a module file that does not start with the WebAssembly
// magic bytes.
var ErrNotWasm = errors.New("module is not a WebAssembly binary")

// ErrNoScriptedStatus reports a FakeEngine run with no scripted status left. A
// fake that ran out of script fails rather than inventing a result.
var ErrNoScriptedStatus = errors.New("fake engine: no scripted status left")

// FakeEngine is a fail-closed wasmhost.Engine. It refuses an unvalidated
// spec, opens the spec's preopens and module through wasmhost.OpenPreopens
// exactly as the real engine must (so a path swapped since Validate fails here
// too), refuses a module whose first bytes are not the WebAssembly magic, then
// returns its scripted statuses in order, one per run. It is safe for
// concurrent use.
type FakeEngine struct {
	mu       sync.Mutex
	statuses []wasmhost.ExitStatus
	runs     []wasmhost.Validated
}

var _ wasmhost.Engine = (*FakeEngine)(nil)

// NewFakeEngine returns a FakeEngine that answers successive runs with
// statuses, in order.
func NewFakeEngine(statuses ...wasmhost.ExitStatus) *FakeEngine {
	return &FakeEngine{statuses: append([]wasmhost.ExitStatus(nil), statuses...)}
}

// Run implements wasmhost.Engine.
func (f *FakeEngine) Run(ctx context.Context, spec wasmhost.Validated) (wasmhost.ExitStatus, error) {
	if !spec.Valid() {
		return wasmhost.ExitStatus{}, fmt.Errorf("fake engine: %w: not a validated spec", wasmhost.ErrInvalidSpec)
	}
	if err := ctx.Err(); err != nil {
		return wasmhost.ExitStatus{}, fmt.Errorf("fake engine: %w", err)
	}
	opened, err := wasmhost.OpenPreopens(spec)
	if err != nil {
		return wasmhost.ExitStatus{}, fmt.Errorf("fake engine: %w", err)
	}
	defer func() { _ = opened.Close() }() // read-only descriptors; a close error loses nothing
	head := make([]byte, len(wasmMagic))
	if _, err := io.ReadFull(opened.Module, head); err != nil {
		return wasmhost.ExitStatus{}, fmt.Errorf("fake engine: %w: %v", ErrNotWasm, err)
	}
	if !bytes.Equal(head, wasmMagic) {
		return wasmhost.ExitStatus{}, fmt.Errorf("fake engine: %w", ErrNotWasm)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) == 0 {
		return wasmhost.ExitStatus{}, ErrNoScriptedStatus
	}
	st := f.statuses[0]
	f.statuses = f.statuses[1:]
	f.runs = append(f.runs, spec)
	return st, nil
}

// Runs returns the specs of the runs that reached a scripted status, in order.
func (f *FakeEngine) Runs() []wasmhost.Validated {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wasmhost.Validated(nil), f.runs...)
}
