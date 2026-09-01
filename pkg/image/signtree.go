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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrTreeSignPolicy reports an attempt to ad-hoc sign a tree under a policy that
// forbids it. Ad-hoc signing is STRUCTURALLY UNREACHABLE under REQUIRE_SIGNED and
// REQUIRE_NOTARIZED: `codesign -s - -f` replaces a real authority with an ad-hoc
// signature, which would silently downgrade the very binaries those policies exist
// to require. UNSPECIFIED is refused for the same fail-closed reason the per-binary
// gate refuses it.
var ErrTreeSignPolicy = errors.New("image: signature policy does not permit ad-hoc tree signing")

// ErrTreeSignRoot reports a rootfs that cannot be walked safely: absent, not a
// directory, or a symlink standing in for one. A symlinked root is refused rather
// than resolved because the caller's containment claim ("everything under this
// path") would then be about a directory the caller did not name.
var ErrTreeSignRoot = errors.New("image: sign-tree root is not a directory")

// TreeSigner is the code-signing seam AdHocSignTree consumes: verify a slice, or
// ad-hoc sign a file. CodesignTreeSigner is the production implementation; unit
// tests fake it, which is what lets the walk's containment and skip rules be proven
// with no codesign, no Mach-O toolchain, and no privilege.
type TreeSigner interface {
	// VerifyArch reports whether path carries a valid signature. arch names the
	// slice to verify in a UNIVERSAL binary; it is empty for a thin one, where the
	// file has exactly one slice and verifying the whole file verifies it.
	VerifyArch(ctx context.Context, path, arch string) (bool, error)
	// Sign ad-hoc signs the Mach-O at path.
	Sign(ctx context.Context, path string) error
}

// CodesignTreeSigner is the production TreeSigner, backed by the codesign tool.
// The zero value is usable.
type CodesignTreeSigner struct{}

// VerifyArch runs `codesign --verify --strict [--arch <arch>] <path>`. A non-zero
// exit is "not validly signed", not a tool failure — the same convention
// CodesignTool.Signed uses.
func (CodesignTreeSigner) VerifyArch(ctx context.Context, path, arch string) (bool, error) {
	args := []string{"--verify", "--strict"}
	if arch != "" {
		args = append(args, "--arch", arch)
	}
	return runCodesignVerify(ctx, append(args, path))
}

// Sign ad-hoc signs path (AdHocSign: no hardened runtime, no library validation, so
// a later DYLD insert can load).
func (CodesignTreeSigner) Sign(ctx context.Context, path string) error {
	return AdHocSign(ctx, path)
}

// TreeSignStats is what one AdHocSignTree call did. It is returned rather than
// logged so a caller can assert on it and an operator can see the shape of a tree:
// on a healthy wheel tree Signed is 0 and Valid equals MachO, because the arm64
// linker signs every Mach-O it emits.
type TreeSignStats struct {
	// Files is how many directory entries were walked.
	Files int
	// MachO is how many of them were Mach-O binaries.
	MachO int
	// Valid is how many Mach-Os already carried a valid signature for the slice
	// that will execute, and were therefore left untouched.
	Valid int
	// Signed is how many were ad-hoc signed by this call.
	Signed int
	// SkippedLinks is how many candidates were refused on containment grounds: a
	// symlink, or a regular file with more than one hard link. See AdHocSignTree.
	SkippedLinks int
}

// AdHocSignTree walks an unpacked image tree and ad-hoc signs the Mach-O binaries
// that need it — once, at pull/materialize time, over the content-addressed tree,
// rather than per pod.
//
// check, then SIGN only IF INVALID. An ad-hoc signature is content-addressed, so it
// survives clonefile verbatim: a pod rootfs cloned from a signed tree execs without
// any signing step (measured — a 330 MB tree clones in ~1.0 s at ~0 bytes, and the
// cloned Mach-Os exec unmodified under Seatbelt). An unconditional `codesign -f`
// would rewrite each file and thereby DE-CoW it, turning a free clone into a full
// copy, so a file that is already valid is never touched.
//
// per-ARCH VERIFICATION, and this is where a whole-file check goes wrong. A
// universal binary whose arm64 slice is validly signed and whose x86_64 slice is
// unsigned — an ordinary shape for a universal2 wheel; one was found in the
// reference dependency closure — makes a bare `codesign -v` report "code object is
// not signed at all" for the whole FILE. Acting on that verdict would re-sign a
// file whose executing slice was already fine, de-CoWing it on every arrival. So a
// universal binary is verified with --arch, naming the slice that will actually
// execute here, and a thin one is verified whole (it has only the one slice).
//
// CONTAINMENT. The walk is lstat-based and follows nothing: a symlink is never
// descended and never signed, so a link named "libfoo.dylib" pointing at a host
// binary cannot steer the daemon's codesign at a file outside the tree. A regular
// file with more than one hard link is likewise refused — signing rewrites the
// inode, which would mutate every other name for it, including one outside the
// tree. The cost is explicit: a legitimately hardlinked, UNSIGNED Mach-O inside the
// tree is left unsigned, and the per-start argv[0] gate then rejects it under
// ADHOC_OK rather than running it. Refusing to write through an alias the walk
// cannot see is the safer half of that trade.
//
// POLICY. Only ADHOC_OK reaches the signing path; every other policy returns
// ErrTreeSignPolicy before a single file is opened (see ErrTreeSignPolicy).
//
// Errors fail the whole call: a tree whose signing is half-applied is a tree whose
// pods fail at exec for reasons that no longer point at the cause.
func AdHocSignTree(ctx context.Context, signer TreeSigner, policy runtimev1.SignaturePolicy, rootfs string) (TreeSignStats, error) {
	var stats TreeSignStats
	if policy != runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK {
		return stats, fmt.Errorf("%w: policy %s", ErrTreeSignPolicy, policy)
	}
	if signer == nil {
		return stats, errors.New("image: sign tree: no signer")
	}
	root := filepath.Clean(rootfs)
	if !filepath.IsAbs(root) {
		return stats, fmt.Errorf("%w: %q is not absolute", ErrTreeSignRoot, rootfs)
	}
	// lstat, so a SYMLINK standing in for the root is refused instead of resolved.
	fi, err := os.Lstat(root)
	if err != nil {
		return stats, fmt.Errorf("%w: %s: %w", ErrTreeSignRoot, root, err)
	}
	if !fi.IsDir() {
		return stats, fmt.Errorf("%w: %s is %s", ErrTreeSignRoot, root, fi.Mode().Type())
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if d.IsDir() {
			return nil
		}
		stats.Files++
		// Containment, restated at the leaf: WalkDir never follows a symlink, so a
		// path outside the root cannot be reached — this check is the sink that
		// holds if that ever changes.
		if !strictlyUnderRoot(path, root) {
			stats.SkippedLinks++
			return nil
		}
		info, err := d.Info() // lstat: never the symlink's target
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			// Symlinks, fifos, sockets, devices: never candidates, never followed.
			if info.Mode()&fs.ModeSymlink != 0 {
				stats.SkippedLinks++
			}
			return nil
		}
		if hardLinked(info) {
			stats.SkippedLinks++
			return nil
		}

		arches, isMachO, err := machoSlices(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !isMachO {
			return nil
		}
		stats.MachO++

		arch := pickVerifyArch(arches, runtime.GOARCH)
		valid, err := signer.VerifyArch(ctx, path, arch)
		if err != nil {
			return fmt.Errorf("verify %s: %w", path, err)
		}
		if valid {
			stats.Valid++
			return nil
		}
		if err := signer.Sign(ctx, path); err != nil {
			return fmt.Errorf("sign %s: %w", path, err)
		}
		stats.Signed++
		return nil
	})
	if err != nil {
		return stats, fmt.Errorf("sign tree %s: %w", root, err)
	}
	return stats, nil
}

// strictlyUnderRoot reports whether path is a proper descendant of root. Both are
// already cleaned by the caller.
func strictlyUnderRoot(path, root string) bool {
	return path != root && strings.HasPrefix(path, root+string(filepath.Separator))
}

// hardLinked reports whether info describes a regular file with more than one hard
// link. It is best-effort: on a platform whose FileInfo carries no link count the
// answer is false, which matches the pre-existing behavior of every other path in
// this package that has no darwin-specific fact to consult.
func hardLinked(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// Mach-O magic numbers. The thin magics are read in the file's own byte order; the
// fat magics are big-endian by definition (a fat header is always big-endian).
const (
	machoMagic64    = 0xFEEDFACF
	machoCigam64    = 0xCFFAEDFE
	machoMagic32    = 0xFEEDFACE
	machoCigam32    = 0xCEFAEDFE
	machoFatMagic   = 0xCAFEBABE
	machoFatMagic64 = 0xCAFEBABF
)

// maxFatArches bounds the fat-header arch count this reader will accept. It is a
// sanity bound, and it is also the first half of the Java-class-file defence: a
// .class file starts with the same 0xCAFEBABE magic, and its next four bytes are
// version numbers that land far outside this range for every real class file.
const maxFatArches = 32

// machoCPUTypes maps the Mach-O cpu_type values k3sm can encounter to the arch
// names codesign uses. The map is a closed allowlist and it is the second half of
// the Java defence: a fat header whose entries do not name known CPU types is not
// treated as a Mach-O at all, so a stray .class file is never handed to codesign.
var machoCPUTypes = map[uint32]string{
	0x00000007: "i386",
	0x01000007: "x86_64",
	0x0000000C: "arm",
	0x0100000C: "arm64",
	0x0200000C: "arm64_32",
}

// machoARM64ESubtype is CPU_SUBTYPE_ARM64E. It is distinguished because codesign
// names the slice "arm64e", and asking it to verify "arm64" on an arm64e-only file
// errors out ("object file format unrecognized") rather than reporting unsigned.
const machoARM64ESubtype = 2

// machoSlices classifies path as a Mach-O and, for a UNIVERSAL binary, names its
// slices. A thin Mach-O returns an empty slice list with isMachO true: it has one
// slice, so there is nothing to choose between.
//
// The classification is by MAGIC, read in-process — not by file extension (a wheel
// tree's suffixes are unreliable in both directions) and not by exec'ing `file`
// once per entry (a tree has thousands of entries and the cost is a fork each).
func machoSlices(path string) (arches []string, isMachO bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()

	var head [8]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		// Shorter than a header: not a Mach-O. Not an error — image trees are full
		// of small text files.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, nil
		}
		return nil, false, err
	}
	magic := binary.BigEndian.Uint32(head[:4])
	switch magic {
	case machoMagic64, machoCigam64, machoMagic32, machoCigam32:
		return nil, true, nil // thin: verify the whole file
	case machoFatMagic, machoFatMagic64:
		// fall through to the fat parse below
	default:
		// The byte-swapped thin magics as seen big-endian.
		if swapped := binary.LittleEndian.Uint32(head[:4]); swapped == machoMagic64 ||
			swapped == machoMagic32 {
			return nil, true, nil
		}
		return nil, false, nil
	}

	nfat := binary.BigEndian.Uint32(head[4:8])
	if nfat == 0 || nfat > maxFatArches {
		return nil, false, nil // not a plausible fat header (see maxFatArches)
	}
	// fat_arch is 20 bytes (32-bit offsets) and fat_arch_64 is 32; only the first 8
	// bytes of each — cputype, cpusubtype — are read here.
	entry := 20
	if magic == machoFatMagic64 {
		entry = 32
	}
	buf := make([]byte, int(nfat)*entry)
	if _, err := io.ReadFull(f, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, nil
		}
		return nil, false, err
	}
	arches = make([]string, 0, nfat)
	for i := 0; i < int(nfat); i++ {
		off := i * entry
		cpuType := binary.BigEndian.Uint32(buf[off : off+4])
		cpuSubtype := binary.BigEndian.Uint32(buf[off+4 : off+8])
		name, ok := machoCPUTypes[cpuType]
		if !ok {
			// An unknown CPU type means this is not a Mach-O we can reason about —
			// fail closed and leave the file alone rather than sign something whose
			// format we mis-identified.
			return nil, false, nil
		}
		if name == "arm64" && cpuSubtype&0xFF == machoARM64ESubtype {
			name = "arm64e"
		}
		arches = append(arches, name)
	}
	return arches, true, nil
}

// archPreference is the order in which a universal binary's slices are considered
// for verification, given the daemon's own GOARCH. The first present slice wins.
//
// The daemon's arch comes first because that is the slice a pod binary executes
// natively. The arm64 variants follow, so an arm64-only tree verified by an
// amd64-built daemon still names a slice the file actually has. x86_64 is last: on
// an Apple-silicon host it executes only under translation, which is a real
// execution path and therefore worth verifying, but never the preferred one.
func archPreference(goarch string) []string {
	switch goarch {
	case "arm64":
		return []string{"arm64e", "arm64", "x86_64"}
	case "amd64":
		return []string{"x86_64", "arm64e", "arm64"}
	default:
		return []string{"arm64e", "arm64", "x86_64"}
	}
}

// pickVerifyArch chooses which slice of a universal binary to verify. It returns ""
// for a thin binary (no slice list), which makes the verifier check the whole file.
//
// When a universal binary carries none of the preferred slices — a fat file of
// i386 and arm only, say — the FIRST slice is named rather than "": a whole-file
// verdict on a universal binary is exactly the misleading answer this function
// exists to avoid.
func pickVerifyArch(arches []string, goarch string) string {
	if len(arches) == 0 {
		return ""
	}
	present := make(map[string]bool, len(arches))
	for _, a := range arches {
		present[a] = true
	}
	for _, want := range archPreference(goarch) {
		if present[want] {
			return want
		}
	}
	return arches[0]
}
