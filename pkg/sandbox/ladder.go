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

import (
	"errors"
	"fmt"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrNoIsolation reports that no confining backend rung is available for the
// host, so the runtime must refuse to start the pod. It exists so the fallback
// selection can fail closed: when Seatbelt is unavailable (a tripped
// symbol-canary / missing libsandbox SPI) and no stronger rung can run, the
// answer is "refuse", never "run the pod unconfined".
var ErrNoIsolation = errors.New("sandbox: no isolation backend available; refusing to run pod unconfined")

// ErrBackendUnavailable reports that the backend a pod explicitly requested (via
// SandboxProfile.backend) cannot be satisfied on this host. It is the fail-closed
// outcome for an explicit request: a pod that asked for the vm backend (a Linux
// image / untrusted tenancy) on a host without Virtualization.framework + the
// com.apple.security.virtualization entitlement is refused here — never silently
// downgraded to the weaker Seatbelt rung (on which a Linux image cannot even exec,
// and which is not a hard tenancy boundary). Distinct from ErrNoIsolation, which
// means "the host can confine nothing at all". Compare with errors.Is.
var ErrBackendUnavailable = errors.New("sandbox: requested backend unavailable; refusing to downgrade")

// Ladder returns the ordered pod-isolation fallback ladder for the host. The
// rungs are the apis SandboxBackend kinds; selection prefers Seatbelt and, when
// it is unavailable, degrades to the stronger vm rung — never to a weaker one
// and never to "unconfined".
//
// uidjail is included only when running as root: a per-pod uid jail must
// setuid/chown to an unprivileged identity, which is impossible without root.
// The unprivileged user-space daemon (the _k3sm posture) therefore drops the
// uidjail rung entirely, leaving [seatbelt, vm] — both of which confine without
// per-pod root.
func Ladder(isRoot bool) []runtimev1.SandboxBackend {
	if isRoot {
		return []runtimev1.SandboxBackend{
			runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
			runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL,
			runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
		}
	}
	return []runtimev1.SandboxBackend{
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_VM,
	}
}

// SelectBackend chooses the pod-isolation backend rung for the host, honoring the
// REQUESTED backend (the provider stamps SandboxProfile.backend) and failing
// closed. The cases:
//
//   - UNSPECIFIED — the host-process default the provider stamps for a pod with no
//     vm RuntimeClass: walk the host-OS-gated ladder (selectLadder). Seatbelt is
//     the preferred rung; if it is unavailable (tripped symbol-canary / missing
//     SPI) degrade only to the stronger vm rung when present — never to a weaker
//     rung and never to unconfined; if nothing confines, ErrNoIsolation.
//   - VM — stamped for a Linux-image / untrusted-tenancy pod: require the vm
//     backend. If it is unavailable, ErrBackendUnavailable — never fall back to
//     Seatbelt (the cardinal M5.1 safety fix: a Linux ELF cannot exec under
//     Seatbelt, and an untrusted pod must not silently land on the weaker rung).
//   - SEATBELT_INPROC / SEATBELT_EXEC — an explicit pin: require Seatbelt, else
//     ErrBackendUnavailable. An explicit pin is honored exactly or refused; only
//     UNSPECIFIED runs the degrade-capable ladder.
//   - UIDJAIL / any other value: ErrBackendUnavailable (uidjail is not implemented;
//     an unknown enum is refused).
//
// uidjail is never *selected* by the ladder even when present on it: it is weaker
// than Seatbelt, so it is not a degrade target. It stays on the root ladder only
// as the documented rung an explicit request could pin to once implemented. The
// returned value is never SANDBOX_BACKEND_UNSPECIFIED with a nil error — an
// unconfined "rung" is not a valid outcome.
func SelectBackend(requested runtimev1.SandboxBackend, isRoot, seatbeltAvailable, vmAvailable bool) (runtimev1.SandboxBackend, error) {
	switch requested {
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED:
		return selectLadder(isRoot, seatbeltAvailable, vmAvailable)
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_VM:
		if vmAvailable {
			return runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, nil
		}
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			fmt.Errorf("%w: vm backend requested (needs Virtualization.framework + com.apple.security.virtualization) but not available on this host", ErrBackendUnavailable)
	case runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
		runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC:
		if seatbeltAvailable {
			return runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, nil
		}
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			fmt.Errorf("%w: seatbelt backend requested but unavailable on this host", ErrBackendUnavailable)
	default:
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED,
			fmt.Errorf("%w: backend %v is not supported by this runtime", ErrBackendUnavailable, requested)
	}
}

// selectLadder is the UNSPECIFIED (host-process default) path: the historical
// host-OS-gated Seatbelt ladder — degrade-UP-only and fail-closed. Factored out
// so SelectBackend's per-request dispatch stays readable.
//
// Seatbelt available → SEATBELT_INPROC (the default rung). Seatbelt unavailable
// (tripped canary / missing SPI) → degrade only UP the strength ladder, and only
// to a rung present on this host. Ladder(isRoot) drops the uidjail rung when not
// root; uidjail is weaker than Seatbelt regardless, so it is never a degrade
// target — vm (stronger) is the only one. Nothing confining → ErrNoIsolation.
func selectLadder(isRoot, seatbeltAvailable, vmAvailable bool) (runtimev1.SandboxBackend, error) {
	if seatbeltAvailable {
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, nil
	}
	for _, rung := range Ladder(isRoot) {
		if rung == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM && vmAvailable {
			return rung, nil
		}
	}
	return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED, ErrNoIsolation
}
