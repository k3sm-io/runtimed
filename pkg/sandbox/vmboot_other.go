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

// CreateVM is the OFF-DARWIN typed refusal.
//
// The live boot is real (vmboot_darwin.go): it spawns the k3sm-vmhost helper and
// waits for the guest agent to answer. It is darwin-only by construction — the
// helper is a macOS binary carrying com.apple.security.virtualization, and the
// readiness handshake crosses a Virtualization.framework vsock device — so on
// every other lane this REFUSES with a typed error instead of compiling code
// that would fail later at a syscall with a worse message.
//
// The refusal is unreachable in practice: SelectBackend consults
// VMBackend.Available(), which is false off darwin, and fails a vm-requested pod
// closed before CreateVM. This exists so the failure is legible in the one case
// that ordering could ever be circumvented — a caller holding the backend
// directly.
func (b *VMBackend) CreateVM(ctx context.Context, spec VMSpec) error {
	return ErrVMBootNotImplemented
}
