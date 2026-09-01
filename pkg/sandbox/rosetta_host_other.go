//go:build !darwin

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

package sandbox

import "context"

// hostRosettaProbe is the off-DARWIN host-Rosetta probe: Rosetta 2 is a macOS
// translation runtime, so on every other OS the answer is definitionally
// HostRosettaAbsent. The split is by GOOS alone (not cgo) — the darwin
// implementation is pure Go, so the CGO_ENABLED=0 darwin lane gets the real probe
// rather than this stub.
func hostRosettaProbe(_ context.Context) HostRosettaState { return HostRosettaAbsent }
