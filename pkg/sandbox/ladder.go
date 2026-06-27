package sandbox

import (
	"errors"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrNoIsolation reports that no confining backend rung is available for the
// host, so the runtime MUST refuse to start the pod. It exists so the fallback
// selection can FAIL CLOSED: when Seatbelt is unavailable (a tripped
// symbol-canary / missing libsandbox SPI) and no stronger rung can run, the
// answer is "refuse", never "run the pod unconfined".
var ErrNoIsolation = errors.New("sandbox: no isolation backend available; refusing to run pod unconfined")

// Ladder returns the ordered pod-isolation fallback ladder for the host. The
// rungs are the apis SandboxBackend kinds; selection prefers Seatbelt and, when
// it is unavailable, degrades to the STRONGER vm rung — never to a weaker one
// and never to "unconfined".
//
// uidjail is included ONLY when running as root: a per-pod uid jail must
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

// SelectBackend chooses the pod-isolation backend rung for the host, FAIL CLOSED.
// It walks Ladder(isRoot) and applies the availability probes:
//
//   - Seatbelt available → SEATBELT_INPROC (the default rung);
//   - Seatbelt unavailable (canary tripped / missing SPI) → degrade to the
//     STRONGER vm rung when it can run — NEVER fall through to a weaker rung or
//     to running the pod unconfined;
//   - nothing confining available → ErrNoIsolation (the caller refuses the pod).
//
// uidjail is never *selected* here even when present on the ladder: it is weaker
// than Seatbelt, so it is not a degrade target when Seatbelt trips. It stays on
// the root ladder only as the documented rung an explicit RuntimeClass request
// can pin to. The returned value is never SANDBOX_BACKEND_UNSPECIFIED with a nil
// error — an unconfined "rung" is not a valid outcome.
func SelectBackend(isRoot, seatbeltAvailable, vmAvailable bool) (runtimev1.SandboxBackend, error) {
	if seatbeltAvailable {
		return runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, nil
	}
	// Seatbelt is unavailable (tripped canary / missing SPI): degrade only UP the
	// strength ladder, and only to a rung PRESENT on this host. Ladder(isRoot)
	// drops the uidjail rung when not root; uidjail is weaker than Seatbelt
	// regardless, so it is never a degrade target — vm (stronger) is the only one.
	for _, rung := range Ladder(isRoot) {
		if rung == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM && vmAvailable {
			return rung, nil
		}
	}
	return runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED, ErrNoIsolation
}
