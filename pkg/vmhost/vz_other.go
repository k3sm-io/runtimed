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

package vmhost

import (
	"errors"
	"log/slog"
)

// ErrVZUnavailable reports that this build lane cannot construct a virtual
// machine: Virtualization.framework is reachable only from darwin with cgo, so
// every other lane — CGO_ENABLED=0, and every non-darwin OS — has no machine to
// build. Compare with errors.Is.
var ErrVZUnavailable = errors.New("vmhost: Virtualization.framework is not available in this build (needs darwin + cgo)")

// NewVZMachine is the OFF-PLATFORM constructor. It always fails with
// ErrVZUnavailable.
//
// The stub is what keeps the rest of this package honest. Everything except
// realize and vzRunner is pure Go, so with this file in place `go vet`, `go build`
// and the whole table-driven test suite — FromSpec's validation matrix, the
// lifecycle state machine, the proxy relay — run on ANY lane, including a Linux CI
// runner and a Mac with no entitlement. Without it, the package's build tag would
// be the package's test coverage.
func NewVZMachine(cfg MachineConfig, log *slog.Logger) (machineRunner, vsockDialer, error) {
	return nil, nil, ErrVZUnavailable
}
