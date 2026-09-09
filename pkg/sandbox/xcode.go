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

// The developer-toolchain read grant (SandboxProfile.xcode_toolchain_dir).
//
// # What this grants, and why each line is here
//
// The rule set below is ABLATION-DERIVED, not guessed: every path here was added
// because its absence produced a real, named failure under the shipped generator's
// own output, and every path that could be removed without one was removed. The
// derivation was re-run on 2026-09-09 against Xcode 26.6 (17F113) on macOS 26.6.2,
// which both widened the grant and narrowed two of its existing rules.
//
// Rooted at D, the node's DEVELOPER_DIR (`xcode-select -p`, e.g.
// /Applications/Xcode.app/Contents/Developer), with B the enclosing application
// bundle (D/../.., recognised only when D ends in Contents/Developer):
//
//   - subpath D/usr/bin — the developer-dir tool shims: xcrun, xcodebuild, and the
//     `swift`/`swiftc` front ends that re-exec into the toolchain.
//   - subpath D/usr/lib — the libraries those shims dlopen (libxcrun and the
//     developer-dir support dylibs). A shim that cannot map them exits before it
//     ever reaches the compiler.
//   - subpath D/Toolchains/XcodeDefault.xctoolchain — the toolchain proper: the
//     clang and swift drivers, the linker, and their resource dirs. This is the
//     compiler; without it there is no grant worth making.
//   - subpath D/Platforms/MacOSX.platform/Developer — the macOS platform's
//     developer tree: the SDK (headers, .tbd stubs, module maps) plus the
//     platform's own usr/lib and Library/Frameworks, which xcodebuild resolves
//     when it initialises the macOS platform. Scoped to MacOSX.platform, so the
//     iOS, watchOS, tvOS, visionOS and DriverKit platform trees stay denied —
//     roughly a third of Platforms by size, and the part a macOS build never reads.
//   - subpath D/Library/Frameworks/XcodeKit.framework — libxcodebuildLoader links
//     @rpath/XcodeKit.framework. Named individually rather than granting
//     D/Library/Frameworks, which holds far more than xcodebuild needs.
//   - subpath B/Contents/SharedFrameworks — the Swift driver links
//     @rpath/llbuild.framework out of the bundle's shared frameworks, so a grant
//     confined to D alone fails at dyld time with an image-not-found abort.
//   - subpath B/Contents/Frameworks — xcodebuild dlopens
//     @rpath/libxcodebuildLoader.dylib from here, and the loader in turn pulls
//     IDEFoundation, Xcode3Core, DevToolsCore, DVTNFASupport, IDENoticesFoundation,
//     DevToolsSupport and libclang out of the same directory. It is granted WHOLE
//     rather than as those seven names because the frameworks register each other's
//     plug-in extension points: a profile naming the seven loads them and then dies
//     with "did not find extension point with identifier Xcode.XCSpecProvider".
//     The set is an interdependent unit, and enumerating it would also be brittle
//     across Xcode releases. It is the smaller of the two bundle framework trees —
//     47M against SharedFrameworks' 522M on 26.6 — so this grant does not change
//     the order of magnitude of what was already reachable.
//
//   - literal D, D/Toolchains, D/Platforms, D/Platforms/MacOSX.platform — these
//     directories are OPENED, not merely stat'd: xcrun opendir()s the developer-dir
//     chain while resolving a platform (a metadata-only grant fails with "developer
//     directory … isn't accessible"), and swift-frontend stats D/Toolchains on its
//     way into the toolchain — without it a compile fails with the opaque
//     "unable to execute command: <unknown>". They are literals rather than
//     subpaths so the grant stops at the directory entry itself and never reaches
//     the other children (D/Library, the other .xctoolchain and .platform trees).
//   - literal D/Platforms/MacOSX.platform/Info.plist — the platform manifest
//     xcodebuild reads to identify the platform it just opened.
//   - literal B/Contents/Info.plist, B/Contents/version.plist — the two bundle
//     plists the toolchain reads to identify which Xcode it is running inside.
//     Files, named individually; Contents itself is never a subpath.
//
//   - file-read-metadata on every ancestor of D and of B up to but excluding /
//     (e.g. /Applications, /Applications/Xcode.app,
//     /Applications/Xcode.app/Contents) — EXISTENCE ONLY. The tools stat-walk
//     down to the developer dir, and a denied stat on an intermediate directory
//     aborts the walk. file-read-metadata cannot open, list, or read any of them.
//     Metadata is enough: an earlier reading that /Applications needed file-read*
//     did not reproduce, and granting it would hand every pod the list of
//     applications installed on the node.
//
// # What this grant reaches, and where it stops
//
// Covered: the compilers, the linker, the SDK, xcrun, and the xcodebuild
// subcommands that only interrogate the installation — `-version`, `-showsdks`,
// `-find-executable`. Verified by ablation on 26.6: a confined swiftc compiles and
// links a program that then runs, `swift build --disable-sandbox` does the same for
// a package, and `xcodebuild -showsdks` lists the macOS SDK.
//
// NOT covered, and NOT a path-list problem: driving a full `xcodebuild build`.
// Anything that must evaluate a project or package (`-list`, `-showBuildSettings`,
// `build`) exits 66 under this profile, and the kernel log says why — such a build
// needs job-creation (it spawns XCBBuildService through launchd), mach-lookup to
// coreservicesd, lsd, FSEvents and DiskArbitration, write access to the invoking
// user's shared /var/folders DeveloperTools cache, and reads of that user's
// LaunchServices preferences under /Users. /Users is a PROTECTED deny and the Mach
// services are not file paths at all, so no widening of a read grant reaches this:
// it is a different isolation posture, which is what the vm backend is for. The
// line is therefore Mach services and host-user state, NOT "the IDE's frameworks" —
// those are granted above and xcodebuild loads them.
//
//   - Anything writable. This stanza emits file-read* and file-read-metadata and
//     nothing else; the pod's own data volume remains the only writable tree. The
//     xcrun and DeveloperTools caches under /var/folders stay denied; xcrun and
//     xcodebuild print a "couldn't create cache file" error and proceed.
//   - Any subpath on the bundle root, on B/Contents, or on D itself — each would
//     collapse the narrow grants above into "read the whole of Xcode".
//   - B/Contents/PlugIns, B/Contents/SystemFrameworks, B/Contents/Resources and
//     D/Library beyond XcodeKit.framework — reached only by the project-evaluating
//     path above, which cannot work regardless.
//
// # Placement
//
// Generate emits the stanza in the ALLOWS tier, immediately after the allow_gpu
// stanza, so the protected denies (/Users, the daemon trees, the pods root) still
// outrank it under SBPL's last-match-wins. A toolchain dir that landed inside the
// deny-set is refused at validation instead — see validateXcodeToolchainDir.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrXcodeToolchainDir reports a SandboxProfile.xcode_toolchain_dir that cannot
// be turned into a toolchain grant: one that is relative, unclean, the filesystem
// root, at or under the protected deny-set, or not shaped like a DEVELOPER_DIR
// (its base name is not "Developer" — a Command Line Tools root such as
// /Library/Developer/CommandLineTools is refused by this test).
//
// It is its own sentinel rather than a reuse of ErrProtectedPath even though the
// deny-set check is shared, for the reason ErrDataVolumeUnbounded already
// records: ErrProtectedPath is returned for many distinct conditions across the
// caller-supplied path tiers, so a test asserting it could pass because an
// unrelated fixture tripped the same sentinel — proving nothing about this field.
// The deny-set failure is therefore reported with its reason as TEXT under this
// sentinel, not as a second wrapped error.
var ErrXcodeToolchainDir = errors.New("sbpl: invalid xcode toolchain dir")

// xcodeDeveloperDirBase is the base name a DEVELOPER_DIR must carry. It is the
// cheap structural check that keeps the grant pointed at a developer dir: every
// path this stanza derives is relative to D, so a D of, say, /Applications would
// render five subpath allows over unrelated trees.
const xcodeDeveloperDirBase = "Developer"

// validateXcodeToolchainDir checks a raw xcode_toolchain_dir and returns the
// cleaned DEVELOPER_DIR the stanza is rendered from. An empty value is not an
// error: it returns "" and grants nothing (the default).
//
// It fails closed — a value that cannot be validated returns ErrXcodeToolchainDir
// and Generate emits no profile at all, rather than emitting one with the
// toolchain grant silently dropped. protectedPrefixes and dataVol are the same
// deny-set and carve-out Generate applies to every other caller-supplied path;
// the check is delegated to validateExtraPaths (with the dir as a one-element
// group) so this field cannot drift away from the tier that defends the rest.
func validateXcodeToolchainDir(raw, dataVol string, protectedPrefixes []string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%w: %q is not absolute", ErrXcodeToolchainDir, raw)
	}
	if filepath.Clean(raw) != raw {
		return "", fmt.Errorf("%w: %q is not a clean path", ErrXcodeToolchainDir, raw)
	}
	if raw == "/" {
		return "", fmt.Errorf("%w: %q is the filesystem root", ErrXcodeToolchainDir, raw)
	}
	if err := validateExtraPaths(dataVol, protectedPrefixes, []string{raw}); err != nil {
		return "", fmt.Errorf("%w: %v", ErrXcodeToolchainDir, err)
	}
	if filepath.Base(raw) != xcodeDeveloperDirBase {
		return "", fmt.Errorf("%w: %q is not a developer dir (base name is not %q)", ErrXcodeToolchainDir, raw, xcodeDeveloperDirBase)
	}
	return raw, nil
}

// xcodeBundleRoot returns the application bundle enclosing a DEVELOPER_DIR — B =
// D/../.. — and whether one was recognised. Recognition is structural and
// deliberately narrow: only a D ending in Contents/Developer has a bundle, and a
// bundle that computes to the filesystem root is refused. A D with no bundle
// (a relocated or synthetic developer dir) renders no bundle-level rule at all
// rather than guessing a root, so the SharedFrameworks and plist grants are made
// only where they mean something.
func xcodeBundleRoot(dir string) (string, bool) {
	if filepath.Base(dir) != xcodeDeveloperDirBase {
		return "", false
	}
	contents := filepath.Dir(dir)
	if filepath.Base(contents) != "Contents" {
		return "", false
	}
	bundle := filepath.Dir(contents)
	if bundle == "/" || bundle == "." {
		return "", false
	}
	return bundle, true
}

// xcodeAncestors returns the strict ancestors of p, root-first, excluding "/" and
// p itself: for /Applications/Xcode.app/Contents/Developer it is /Applications,
// /Applications/Xcode.app, /Applications/Xcode.app/Contents. These are the
// directories a stat-walk traverses on the way down, and the metadata-only tier
// is the whole grant they get.
func xcodeAncestors(p string) []string {
	var out []string
	for cur := filepath.Dir(p); cur != "/" && cur != "." && cur != p; cur = filepath.Dir(cur) {
		out = append(out, cur)
	}
	// reverse into root-first order, which is how the stat-walk reads.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// xcodeToolchainStanza renders the toolchain grant for a validated DEVELOPER_DIR
// in the profile's house style: a comment naming the grant and its provenance,
// then one rule per grant class. dir must already have passed
// validateXcodeToolchainDir. The output is deterministic for a given dir (the
// path order is the fixed, documented one above, and the ancestor set is
// deduped root-first), so the golden fixture pins the same bytes Generate emits.
func xcodeToolchainStanza(dir string) string {
	bundle, hasBundle := xcodeBundleRoot(dir)

	subpaths := []string{
		filepath.Join(dir, "usr", "bin"),
		filepath.Join(dir, "usr", "lib"),
		filepath.Join(dir, "Toolchains", "XcodeDefault.xctoolchain"),
		filepath.Join(dir, "Platforms", "MacOSX.platform", "Developer"),
		filepath.Join(dir, "Library", "Frameworks", "XcodeKit.framework"),
	}
	// The two bundle-level subtrees: the Swift driver links @rpath/llbuild.framework
	// out of SharedFrameworks, and xcodebuild dlopens libxcodebuildLoader.dylib out
	// of Frameworks. Neither the bundle root nor Contents is ever a subpath.
	if hasBundle {
		subpaths = append(subpaths,
			filepath.Join(bundle, "Contents", "SharedFrameworks"),
			filepath.Join(bundle, "Contents", "Frameworks"),
		)
	}

	// The developer-dir chain is opened as directories, so each level needs a
	// literal read — metadata alone fails ("developer directory isn't accessible").
	literals := []string{
		dir,
		filepath.Join(dir, "Toolchains"),
		filepath.Join(dir, "Platforms"),
		filepath.Join(dir, "Platforms", "MacOSX.platform"),
		filepath.Join(dir, "Platforms", "MacOSX.platform", "Info.plist"),
	}
	if hasBundle {
		literals = append(literals,
			filepath.Join(bundle, "Contents", "Info.plist"),
			filepath.Join(bundle, "Contents", "version.plist"),
		)
	}

	// Existence only, for the stat-walk down to D (and to B, which is itself an
	// ancestor of D whenever a bundle was recognised).
	metaSeen := map[string]bool{}
	var metadata []string
	metaSources := []string{dir}
	if hasBundle {
		metaSources = append(metaSources, bundle)
	}
	for _, src := range metaSources {
		for _, anc := range xcodeAncestors(src) {
			if metaSeen[anc] {
				continue
			}
			metaSeen[anc] = true
			metadata = append(metadata, anc)
		}
	}

	var b strings.Builder
	b.WriteString(";; xcode: developer-toolchain READ access (xcode_toolchain_dir) rooted\n")
	b.WriteString(";; at the node's DEVELOPER_DIR. Lab-derived by ablation — every path\n")
	b.WriteString(";; below was a real denial; nothing here is writable, and neither the\n")
	b.WriteString(";; application bundle nor its Contents is ever granted as a subpath.\n")
	b.WriteString(";; Covers the compilers, linker, SDK, xcrun, and the xcodebuild\n")
	b.WriteString(";; subcommands that only interrogate the install. A full xcodebuild\n")
	b.WriteString(";; build is out of reach of ANY read grant: it needs job-creation,\n")
	b.WriteString(";; mach-lookup and host-user state under /Users, which stays denied.\n")
	b.WriteString("(allow file-read*\n")
	writeFirmlinkSubpaths(&b, subpaths)
	b.WriteString("  )\n")
	b.WriteString(";; the developer-dir chain is OPENED as directories by xcrun (metadata\n")
	b.WriteString(";; alone fails: \"developer directory isn't accessible\") and Toolchains\n")
	b.WriteString(";; is stat'd by swift-frontend, plus the platform manifest and the two\n")
	b.WriteString(";; bundle plists the toolchain reads — files, named one by one.\n")
	b.WriteString("(allow file-read*\n")
	writeFirmlinkLiterals(&b, literals)
	b.WriteString("  )\n")
	b.WriteString(";; existence only: the ancestors the tools stat-walk on the way down.\n")
	b.WriteString("(allow file-read-metadata\n")
	writeFirmlinkLiterals(&b, metadata)
	b.WriteString("  )\n")
	return b.String()
}

// writeFirmlinkLiterals is writeFirmlinkSubpaths' literal counterpart: it writes a
// `(literal …)` line for every firmlink form of each path. Same reason — libsandbox
// matches the symlink-resolved path, so a rule written only against the /var,/tmp,/etc
// alias of a relocated developer dir would silently grant nothing (an allow fails
// closed). On the ordinary /Applications layout the two forms coincide and one line
// is emitted per path.
func writeFirmlinkLiterals(b *strings.Builder, paths []string) {
	for _, p := range paths {
		for _, form := range firmlinkForms(p) {
			b.WriteString(fmt.Sprintf("  (literal %q)\n", form))
		}
	}
}
