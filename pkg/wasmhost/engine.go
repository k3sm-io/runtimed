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

package wasmhost

import (
	"context"
	"fmt"
)

// Engine runs one validated launch spec to completion. The wasmtime
// implementation lives in a cgo subpackage linked only by the helper binary;
// wasmhosttest.FakeEngine is the fail-closed implementation for unit tests.
//
// An implementation MUST take its preopen directories and its module through
// OpenPreopens and never reopen a host path by name: the descriptors are what
// Validate's checks are about. It stops the guest when ctx is cancelled; the
// helper owns the stop-grace timer and cancels ctx from its own SIGTERM
// handling.
//
// Run returns an ExitStatus when the guest ran and ended (by its own exit, a
// trap, or a resource-limit trap), and an error when it could not be run at all
// (an invalid spec, an unreadable or malformed module, a cancelled context
// before start). An implementation must refuse a Validated whose Valid is
// false.
type Engine interface {
	Run(ctx context.Context, spec Validated) (ExitStatus, error)
}

// ExitKind is how a guest run ended.
type ExitKind int

const (
	// ExitUnknown is the zero ExitKind. No engine returns it with a nil error.
	ExitUnknown ExitKind = iota
	// ExitCode means the guest exited on its own (returned from its entry
	// point, or called proc_exit); ExitStatus.Code is its exit code.
	ExitCode
	// ExitTrap means the guest trapped (unreachable, an out-of-bounds access,
	// an interrupt on stop); ExitStatus.Detail names the trap.
	ExitTrap
	// ExitResourceLimit means the engine's own resource backstop trapped the
	// guest (a store limit on memory or tables). It is distinct from ExitTrap
	// because the start path reports it as OOMKilled, by operator ruling; the
	// mapping itself belongs to that path, not to this package.
	ExitResourceLimit
)

// String names the kind.
func (k ExitKind) String() string {
	switch k {
	case ExitCode:
		return "exit"
	case ExitTrap:
		return "trap"
	case ExitResourceLimit:
		return "resource-limit"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// ExitStatus is how a guest run ended.
type ExitStatus struct {
	// Kind distinguishes a guest exit, a guest trap and a resource-limit trap.
	Kind ExitKind
	// Code is the guest exit code when Kind is ExitCode, else zero.
	Code int
	// Detail is the engine's trap description when Kind is ExitTrap or
	// ExitResourceLimit.
	Detail string
}
