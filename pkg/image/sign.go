package image

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrSignatureRejected reports that a binary failed the SignaturePolicy gate.
// Callers map it to runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED.
var ErrSignatureRejected = errors.New("image: binary rejected by signature policy")

// ErrPolicyUnspecified reports a fail-closed decision: the SignaturePolicy is
// UNSPECIFIED (zero value), so the runtime refuses to run unverified code.
var ErrPolicyUnspecified = errors.New("image: signature policy unspecified (fail-closed)")

// SignatureInspector reports the code-signature facts about a Mach-O file the
// policy gate needs. It is the seam the gate consumes: the production
// implementation shells out to codesign/spctl (CodesignTool); unit tests fake it.
type SignatureInspector interface {
	// Signed reports whether path has a valid code signature (any authority,
	// including ad-hoc).
	Signed(ctx context.Context, path string) (bool, error)
	// AdHoc reports whether path's signature is ad-hoc (no real authority).
	AdHoc(ctx context.Context, path string) (bool, error)
	// Notarized reports whether path passes Gatekeeper notarization assessment.
	Notarized(ctx context.Context, path string) (bool, error)
}

// CheckSignaturePolicy enforces policy against path's signature facts from insp.
// It is FAIL-CLOSED: SIGNATURE_POLICY_UNSPECIFIED returns ErrPolicyUnspecified
// (never run). The mapping:
//
//   - ADHOC_OK         — any valid signature passes (ad-hoc included).
//   - REQUIRE_SIGNED   — a valid, non-ad-hoc signature is required.
//   - REQUIRE_NOTARIZED— a notarized signature is required.
//
// A binary that fails returns ErrSignatureRejected. This is enforced before exec.
func CheckSignaturePolicy(ctx context.Context, insp SignatureInspector, policy runtimev1.SignaturePolicy, path string) error {
	switch policy {
	case runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED:
		return ErrPolicyUnspecified

	case runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK:
		signed, err := insp.Signed(ctx, path)
		if err != nil {
			return fmt.Errorf("inspect signature %s: %w", path, err)
		}
		if !signed {
			return fmt.Errorf("%w: %s is unsigned (adhoc-ok requires a signature)", ErrSignatureRejected, path)
		}
		return nil

	case runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED:
		signed, err := insp.Signed(ctx, path)
		if err != nil {
			return fmt.Errorf("inspect signature %s: %w", path, err)
		}
		if !signed {
			return fmt.Errorf("%w: %s is unsigned (require-signed)", ErrSignatureRejected, path)
		}
		adhoc, err := insp.AdHoc(ctx, path)
		if err != nil {
			return fmt.Errorf("inspect signature %s: %w", path, err)
		}
		if adhoc {
			return fmt.Errorf("%w: %s is ad-hoc signed (require-signed needs a real authority)", ErrSignatureRejected, path)
		}
		return nil

	case runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_NOTARIZED:
		notarized, err := insp.Notarized(ctx, path)
		if err != nil {
			return fmt.Errorf("inspect notarization %s: %w", path, err)
		}
		if !notarized {
			return fmt.Errorf("%w: %s is not notarized (require-notarized)", ErrSignatureRejected, path)
		}
		return nil

	default:
		// Unknown future policy value: fail closed.
		return fmt.Errorf("%w: unknown signature policy %d", ErrPolicyUnspecified, int32(policy))
	}
}

// AdHocSign ad-hoc signs the Mach-O at path with codesign -s - -f, STRIPPING
// hardened-runtime and library-validation so a later DYLD insert (the darwin-net
// DNS shim) can load. It deliberately passes no -o runtime/library option:
// codesign then produces a plain ad-hoc signature (flags=0x2). This is run on
// pull. It is a no-op-safe wrapper around the codesign tool.
func AdHocSign(ctx context.Context, path string) error {
	// -s - : ad-hoc identity. -f : replace any existing signature. No -o options
	// => no hardened runtime, no library validation (both block DYLD insert).
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc sign %s: %w: %s", path, err, string(out))
	}
	return nil
}
