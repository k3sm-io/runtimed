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

package guestartifacts

import (
	"fmt"

	"k3sm.io/runtimed/pkg/sandbox"
)

// Locator returns the sandbox.GuestArtifactLocator a vm backend calls to resolve
// this node's boot artifacts — one that RE-HASHES both files against pin on
// every call and returns them only if they still match.
//
// # Why the verification repeats
//
// EnsureGuestArtifacts verifies once, at daemon start. A locator that closed over
// that result would be asserting, at every guest boot for the life of the
// process, a fact that was measured once and never re-measured — and this daemon
// runs for weeks. Between that measurement and a boot the artifact file can be
// rewritten in place by anything with write access to the cache directory: an
// operator's stray command, a rolled-back restore, a process that found the path
// in a log. The gap between "checked at start" and "used at boot" is exactly a
// time-of-check-to-time-of-use window, and its width is the daemon's uptime.
//
// It is worth closing here, rather than trusting the cache's permissions,
// because the sha256 is the ENTIRE trust chain for a guest kernel. A VZ-booted
// kernel gets no code-signing check from macOS — the hypervisor loads the bytes
// at the path it is given — so nothing downstream of this comparison will ever
// notice that the bytes changed. Enforcing the pin per use is the only place the
// check can still mean something.
//
// The cost is two sha256 passes over roughly a hundred megabytes per vm pod
// start, which is small against booting a Linux guest and is paid on the pod
// start path rather than on any hot loop.
//
// # The failure
//
// A divergence returns an error wrapping ErrDigestMismatch and NAMING the FILE,
// so the operator learns which artifact moved rather than that "the vm capability
// is off". CreateVM turns any error from a locator into a closed failure for that
// pod (sandbox.ErrGuestArtifactsUnavailable), so a rotted artifact fails the pods
// that would have booted it and nothing else on the node.
func Locator(pin GuestKernelPin, art sandbox.GuestArtifacts) func() (sandbox.GuestArtifacts, error) {
	return func() (sandbox.GuestArtifacts, error) {
		for _, a := range []struct{ what, path, digest string }{
			{"kernel", art.KernelPath, pin.ImageSHA256},
			{"initramfs", art.InitramfsPath, pin.InitramfsSHA256},
		} {
			got, err := digestFile(a.path)
			if err != nil {
				return sandbox.GuestArtifacts{}, fmt.Errorf("re-verify the pinned guest %s at %s: %w", a.what, a.path, err)
			}
			if got != a.digest {
				return sandbox.GuestArtifacts{}, fmt.Errorf("the pinned guest %s at %s now hashes to %s, want %s: %w",
					a.what, a.path, got, a.digest, ErrDigestMismatch)
			}
		}
		return art, nil
	}
}
