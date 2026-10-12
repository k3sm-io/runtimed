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
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/pathsafe"
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

// ErrSignTarget reports that a binary to be ad-hoc signed does not resolve to a
// regular file inside its root: the path is outside the root, its symlink chain
// leaves the root or dangles, or a component was swapped for a symlink between
// the resolution and the open.
var ErrSignTarget = errors.New("image: sign target is not a regular file inside its root")

// ErrSignStaging reports a sign staging directory that is not a directory
// private to this process: not a directory, not owned by the effective uid, or
// accessible to group or other.
var ErrSignStaging = errors.New("image: sign staging dir is not private to the daemon")

// ErrSignCrossVolume reports that the sign staging directory and the binary are
// on different volumes, so the signed copy cannot be renamed into place. The
// binary is then NOT signed: there is no in-place fallback.
var ErrSignCrossVolume = errors.New("image: sign staging dir is on a different volume from the target")

// signStagingName is the sign staging directory's name under the ingest dir.
//
// It sits under IngestSubdir rather than beside it on purpose. The ingest dir is
// already a daemon-private staging tree: created 0700, a sibling of pods/ on the
// same volume, read by no GC enumerator, and denied to every pod by the Seatbelt
// profile (sandbox.ImageIngestSubdir). A new top-level sibling would need its own
// entry in that deny list to get the same protection.
const signStagingName = "sign"

// signTempPrefix prefixes every temp file in the sign staging directory, so the
// startup sweep removes only what this package put there.
const signTempPrefix = ".sign-"

// SignStagingDir returns the directory AdHocSignByReplace stages a signed copy
// in (<root>/ingest/sign).
func (c *Cache) SignStagingDir() string {
	return filepath.Join(c.ingestRoot(), signStagingName)
}

// AdHocSignByReplace ad-hoc signs the binary at target, which must lie inside
// root, WITHOUT writing any existing inode: it signs a copy in staging and
// renames the copy over the resolved file.
//
// WHY A NEW INODE. Re-signing a Mach-O in place (codesign -f on the same inode)
// while any process has it mapped leaves the kernel's old signature binding on
// the vnode, and every new process that maps it is killed (SIGKILL, Code
// Signature Invalid). A still-running instance of a container can hold that
// mapping when the gate runs again, so the signed bytes always land on a new
// inode. A process holding the old one keeps it, unmodified, until it exits, and
// so does every other hard link to it: the rename detaches this name only.
//
// SYMLINKS. target is resolved inside root with chroot semantics
// (pathsafe.WalkInRoot): an image's argv[0] is often a link (python3 to a
// versioned file, sh to dash), relative or root-absolute, and the file at the
// end of the chain is the one signed. A chain that leaves root, or dangles, is
// refused with ErrSignTarget.
//
// THE WRITER IS NOT TRUSTED. Pods can write their own rootfs, and in the default
// install they run as the same uid as this daemon (_k3sm), so file permissions do
// not keep them out of it. Every step that touches the rootfs therefore acts on
// a descriptor, never a name:
//   - the resolved file's parent directory is opened through an os.Root on root,
//     which refuses any component that leads outside it, with O_NOFOLLOW and
//     O_DIRECTORY, BEFORE anything is copied;
//   - the file is opened relative to that directory with O_NOFOLLOW (a symlink
//     swapped in after the resolution fails the open), checked with fstat, and
//     copied from the descriptor;
//   - the copy is made and signed in staging, by name, which is safe only because
//     staging is private to the daemon: it must be a directory owned by the
//     effective uid with no group or other access (ErrSignStaging otherwise),
//     and it lies under a tree the pod sandbox profile denies, which is what
//     keeps a same-uid pod out;
//   - the copy is moved into place with renameat(2) from the staging directory's
//     descriptor to the parent's.
//
// staging must be on the same volume as the binary (compared by st_dev);
// otherwise the call fails with ErrSignCrossVolume and nothing is signed.
//
// The copy keeps the file's permission bits, including set-id bits, and, when
// running as root, its owner and group. It does NOT carry extended attributes,
// ACLs or BSD file flags: those of a pulled image's argv[0] are not part of the
// image contract this daemon materializes. It is signed with an explicit
// identifier equal to the resolved file's base name, because codesign otherwise
// derives the identifier from the temp file's name. It is flushed with
// F_FULLFSYNC before the rename and the parent directory is fsynced after it. On
// any error before the rename the temp file is removed and the original is left
// exactly as it was.
func AdHocSignByReplace(ctx context.Context, staging, root, target string) error {
	return signByReplace(ctx, staging, root, target, codesignAs, nil)
}

// codesignAs ad-hoc signs path under the code identifier ident, with the same
// flags as AdHocSign. It is only ever pointed at a temp file in the private
// staging directory.
func codesignAs(ctx context.Context, path, ident string) error {
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "-f", "-i", ident, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc sign %s: %w: %s", path, err, string(out))
	}
	return nil
}

// signFunc signs the file at path under the code identifier ident.
type signFunc func(ctx context.Context, path, ident string) error

// signByReplace is AdHocSignByReplace with its signing step injected, plus a
// hook run between the resolution and the first open (tests use it to swap a
// component for a symlink in exactly that window).
func signByReplace(ctx context.Context, staging, root, target string, sign signFunc, afterResolve func(resolved string)) (err error) {
	root = filepath.Clean(root)
	rel, rerr := filepath.Rel(root, filepath.Clean(target))
	if rerr != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s is not inside %s", ErrSignTarget, target, root)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("sign %s: open root: %w", target, err)
	}
	defer func() { _ = r.Close() }() // read-only handle

	resolved, _, exists, err := pathsafe.WalkInRoot(r, filepath.ToSlash(rel))
	if err != nil {
		return fmt.Errorf("%w: resolve %s in %s: %w", ErrSignTarget, target, root, err)
	}
	if !exists || resolved == "" {
		return fmt.Errorf("%w: %s does not resolve to a file in %s", ErrSignTarget, target, root)
	}
	if afterResolve != nil {
		afterResolve(filepath.Join(root, filepath.FromSlash(resolved)))
	}
	dirRel, base := path.Split(resolved)
	if dirRel == "" {
		dirRel = "."
	}

	parent, err := r.OpenFile(dirRel, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: open parent of %s: %w", ErrSignTarget, target, err)
	}
	defer func() { _ = parent.Close() }() // read-only directory handle
	parentFd := int(parent.Fd())

	srcFd, err := unix.Openat(parentFd, base, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: open %s: %w", ErrSignTarget, target, err)
	}
	src := os.NewFile(uintptr(srcFd), base)
	defer func() { _ = src.Close() }() // read-only
	var st unix.Stat_t
	if err = unix.Fstat(srcFd, &st); err != nil {
		return fmt.Errorf("sign %s: fstat: %w", target, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file", ErrSignTarget, target)
	}

	stage, stageSt, err := openStaging(staging)
	if err != nil {
		return err
	}
	defer func() { _ = stage.Close() }() // read-only directory handle
	if stageSt.Dev != st.Dev {
		return fmt.Errorf("%w: %s (dev %d) and %s (dev %d)", ErrSignCrossVolume, staging, stageSt.Dev, target, st.Dev)
	}

	tmp, err := os.CreateTemp(staging, signTempPrefix+"*")
	if err != nil {
		return fmt.Errorf("sign %s: create temp: %w", target, err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if err != nil && !renamed {
			_ = tmp.Close() // already failing; the temp is removed next
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = io.Copy(tmp, src); err != nil {
		return fmt.Errorf("sign %s: copy: %w", target, err)
	}
	tmpFd := int(tmp.Fd())
	if os.Geteuid() == 0 {
		if err = unix.Fchown(tmpFd, int(st.Uid), int(st.Gid)); err != nil {
			return fmt.Errorf("sign %s: chown temp: %w", target, err)
		}
	}
	// After the chown, which clears set-id bits. Raw mode bits through unix:
	// os.FileMode spells set-id differently from st_mode.
	if err = unix.Fchmod(tmpFd, uint32(st.Mode&0o7777)); err != nil {
		return fmt.Errorf("sign %s: chmod temp: %w", target, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("sign %s: close temp: %w", target, err)
	}

	if err = sign(ctx, tmpPath, base); err != nil {
		return err
	}
	// Reopened by name after signing: codesign may have replaced the file, and
	// staging is private, so the name is ours.
	if err = fullFsync(tmpPath); err != nil {
		return fmt.Errorf("sign %s: flush temp: %w", target, err)
	}
	if err = unix.Renameat(int(stage.Fd()), filepath.Base(tmpPath), parentFd, base); err != nil {
		return fmt.Errorf("sign %s: rename into place: %w", target, err)
	}
	renamed = true
	// The rename is done: the resolved name now holds the signed inode, so a
	// directory fsync failure is reported but nothing is removed.
	if err = unix.Fsync(parentFd); err != nil {
		return fmt.Errorf("sign %s: fsync parent dir: %w", target, err)
	}
	return nil
}

// openStaging creates staging (0700) if needed and opens it without following a
// symlink. It refuses anything but a directory owned by the effective uid with
// no group or other access, since signing there by name is safe only while
// nothing else can write it.
func openStaging(staging string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, st, fmt.Errorf("%w: create %s: %w", ErrSignStaging, staging, err)
	}
	fd, err := unix.Open(staging, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, fmt.Errorf("%w: open %s: %w", ErrSignStaging, staging, err)
	}
	f := os.NewFile(uintptr(fd), staging)
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close() // the fstat error is the one reported
		return nil, st, fmt.Errorf("%w: fstat %s: %w", ErrSignStaging, staging, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		_ = f.Close() // refused; nothing was written
		return nil, st, fmt.Errorf("%w: %s is mode %#o owned by uid %d (want a 0700 directory owned by uid %d)",
			ErrSignStaging, staging, st.Mode&0o7777, st.Uid, os.Geteuid())
	}
	return f, st, nil
}

// fullFsync flushes path to stable storage with F_FULLFSYNC, which on macOS also
// flushes the drive's write cache (plain fsync does not). A filesystem that does
// not support it gets a plain fsync.
func fullFsync(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0); err != nil {
		if !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.ENOTTY) && !errors.Is(err, unix.EINVAL) {
			_ = f.Close() // the flush error is the one that matters
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close() // the sync error is the one that matters
			return err
		}
	}
	return f.Close()
}

// SweepSignStaging removes the temp files a previous daemon run left in the sign
// staging directory (a crash between the copy and the rename). It must run
// before the daemon signs anything, so every temp present is stale; it touches
// only names carrying this package's temp prefix. A missing directory is not an
// error. It reports how many files it removed.
func SweepSignStaging(staging string) (int, error) {
	entries, err := os.ReadDir(staging)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("sweep sign staging %s: %w", staging, err)
	}
	removed := 0
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), signTempPrefix) || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(staging, e.Name())); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}
