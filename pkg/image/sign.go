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

package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

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
// It is fail-closed: SIGNATURE_POLICY_UNSPECIFIED returns ErrPolicyUnspecified
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

// AdHocSignByReplace ad-hoc signs the Mach-O at path WITHOUT writing path's
// inode: it signs a copy in the same directory and rename(2)s it over path.
//
// Re-signing a Mach-O in place (codesign -f on the same inode) while any process
// has it mapped leaves the kernel's old signature binding on the vnode, and every
// new process that maps it is killed (SIGKILL, Code Signature Invalid). A pod
// binary can be mapped by a still-running instance of the container when the gate
// runs again, so the signed bytes always land on a NEW inode; a process holding
// the old one keeps it, unmodified, until it exits.
//
// The copy keeps path's permission bits and, when running as root, its owner and
// group. It is signed with an explicit identifier equal to path's base name,
// because codesign otherwise derives the identifier from the temp file's name.
// The copy is fsynced before the rename and the directory after it. On any error
// the temp file is removed and path is left exactly as it was.
//
// path must be a regular file: a symlink is refused rather than followed or
// replaced, the same containment rule AdHocSignTree applies.
func AdHocSignByReplace(ctx context.Context, path string) error {
	return signByReplace(ctx, path, codesignAs)
}

// codesignAs ad-hoc signs path in place under the code identifier ident, with the
// same flags as AdHocSign. It is only ever pointed at a private temp copy.
func codesignAs(ctx context.Context, path, ident string) error {
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "-f", "-i", ident, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc sign %s: %w: %s", path, err, string(out))
	}
	return nil
}

// signByReplace is AdHocSignByReplace with the signing step injected (tests).
func signByReplace(ctx context.Context, path string, sign func(ctx context.Context, path, ident string) error) (err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("sign by replace: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("sign by replace %s: not a regular file (%s)", path, fi.Mode().Type())
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}

	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sign by replace: %w", err)
	}
	defer func() { _ = src.Close() }() // read-only; a close error loses nothing

	tmp, err := os.CreateTemp(dir, "."+base+".k3sm-sign-*")
	if err != nil {
		return fmt.Errorf("sign by replace %s: create temp: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close() // already failing; the temp is removed next
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = io.Copy(tmp, src); err != nil {
		return fmt.Errorf("sign by replace %s: copy: %w", path, err)
	}
	if os.Geteuid() == 0 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if err = tmp.Chown(int(st.Uid), int(st.Gid)); err != nil {
				return fmt.Errorf("sign by replace %s: chown temp: %w", path, err)
			}
		}
	}
	// After chown, which clears set-id bits.
	if err = tmp.Chmod(fi.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)); err != nil {
		return fmt.Errorf("sign by replace %s: chmod temp: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("sign by replace %s: close temp: %w", path, err)
	}

	if err = sign(ctx, tmpPath, base); err != nil {
		return err
	}

	if err = fsyncPath(tmpPath); err != nil {
		return fmt.Errorf("sign by replace %s: fsync temp: %w", path, err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("sign by replace %s: rename: %w", path, err)
	}
	// The rename is done: path now names the signed inode, so a directory fsync
	// failure is reported but the temp (now path) must not be removed.
	if derr := fsyncPath(dir); derr != nil {
		return fmt.Errorf("sign by replace %s: fsync dir: %w", path, derr)
	}
	return nil
}

func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close() // the sync error is the one that matters
		return err
	}
	return f.Close()
}
