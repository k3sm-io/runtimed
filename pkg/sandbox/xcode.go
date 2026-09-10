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
// Rooted at D, the developer directory this field NAMES — the value a pod's
// DEVELOPER_DIR is set to, e.g. /Applications/Xcode.app/Contents/Developer.
//
// D is not "whatever `xcode-select -p` prints", and the two must not be
// conflated: that command reports the node's ACTIVE developer-dir selection,
// which is very often /Library/Developer/CommandLineTools — a root of an
// entirely different shape, for which every path derived below would be wrong,
// and which ValidateXcodeToolchainDir therefore refuses. A node whose selection
// is the Command Line Tools has no developer dir this stanza can be rooted at;
// it grants nothing and needs nothing, because the Command Line Tools are
// already reachable under the base profile's read set.
//
// With B the enclosing application bundle (D/../.., recognised only when D ends
// in Contents/Developer):
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
//     SIBLING platform bundles — iPhoneOS, iPhoneSimulator, WatchOS, AppleTVOS,
//     XROS, DriverKit and the rest — stay denied, roughly two thirds of Platforms
//     by size. Say "sibling" and not "iOS" precisely: MacOSX.platform contains its
//     own iOSSupport/ tree (the Mac Catalyst shape), and that IS inside the grant.
//     What is excluded is the other .platform bundles, not everything iOS-shaped.
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
// That ceiling rests on TWO invariants, and the second is easy to lose track of
// because it lives in another file. The first is that /Users stays a protected
// deny. The second is that no profile carrying this grant ever gains a
// mach-lookup that resolves to a system service: today the only mach-lookup the
// generator emits anywhere is network.go's pair of exact (global-name …) rules
// for mDNSResponder, so even a pod that asks for both AllowNetwork and this
// field cannot reach tccd, launchservicesd or coreservicesd. The same invariant
// is what keeps the Apple-private entitlements on some of the granted content
// inert (see writeXcodeHelperCarve). TestXcodeGrantNoMachLookupWhenCombined
// pins it at the Generate level, where the composition actually happens, rather
// than only over this stanza in isolation.
//
//   - Anything EXECUTABLE that was not already executable. This is worth stating
//     because the natural inference is wrong: file-read* and process-exec* are
//     distinct Seatbelt operations and the base profile allows process-exec*
//     unconditionally, so a pod could already exec any binary on the box before
//     this grant existed — measured, not assumed. Widening the READ scope adds
//     no exec reach, and narrowing it (the carve below) removes none.
//   - Anything writable. This stanza emits file-read*, file-read-metadata and one
//     file-read* deny, and nothing else; the pod's own data volume remains the
//     only writable tree. The
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
	"regexp"
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
//
// It rests on Apple's Contents/Developer bundle convention rather than on a
// published contract, which is worth stating: the rule is a strong structural
// heuristic, not a guarantee the vendor made.
const xcodeDeveloperDirBase = "Developer"

// ValidateXcodeToolchainDir reports whether dir is usable as a
// SandboxProfile.xcode_toolchain_dir under posture, and returns the cleaned
// DEVELOPER_DIR the grant would be rendered from. An empty dir is not an error:
// it returns "" and nil, the default that grants nothing. Every rejection is
// ErrXcodeToolchainDir, with the reason as text.
//
// It is EXPORTED for the caller that must decide, BEFORE it sets the field,
// whether a candidate developer dir will be accepted — the provider in k3sm,
// which stamps this field from the node's active developer-dir selection and
// must not stamp a value that will fail the whole profile at CreatePod. The
// precedent is ValidateNetworkScope in this package: a relational property the
// generator decides internally, exported so a caller can ask the authoritative
// question instead of re-deriving the answer.
//
// One implementation, so the two answers cannot drift: Generate and this
// function both call the unexported validateXcodeToolchainDir over a
// protected-prefix set both derive from resolvePosture. The rule set here is
// under active revision (the grant was re-derived against Xcode 26.6 on
// 2026-09-09, which narrowed two of its rules), so a second hand-maintained
// copy of "what is a valid DEVELOPER_DIR" in another repo would be wrong within
// one release.
//
// Residual, recorded rather than hidden: part of the deny-set is derived from
// the node's runtimed work-dir, which is a Posture input. A caller passing the
// zero Posture gets the DefaultWorkDir deny-set, so on a node whose runtimed
// runs with a different work-dir this function's verdict differs from
// Generate's for exactly one class of dir — one at or under THAT work-dir's
// pods/podreap/server/agent/run/blobs trees. A caller that knows the node's
// pod-root passes it and the class is empty.
func ValidateXcodeToolchainDir(dir string, posture Posture) (string, error) {
	_, _, protectedPrefixes, err := resolvePosture(posture)
	if err != nil {
		return "", err
	}
	return validateXcodeToolchainDir(dir, protectedPrefixes)
}

// validateXcodeToolchainDir checks a raw xcode_toolchain_dir and returns the
// cleaned DEVELOPER_DIR the stanza is rendered from. An empty value is not an
// error: it returns "" and grants nothing (the default).
//
// It fails closed — a value that cannot be validated returns ErrXcodeToolchainDir
// and Generate emits no profile at all, rather than emitting one with the
// toolchain grant silently dropped. protectedPrefixes is the same deny-set
// Generate applies to every other caller-supplied path; the check is delegated
// to validateExtraPaths (with the dir as a one-element group) so this field
// cannot drift away from the tier that defends the rest.
//
// Unlike the extra-path tier it passes NO data volume to that check, so the
// pod's own volume is not carved out and a "developer dir" inside it is refused
// like any other protected path. That is deliberate and is what lets the same
// predicate answer a caller who holds a candidate dir and no pod: the verdict
// must not depend on which pod happens to be asking. Nothing is lost — a
// developer dir under the pod's own writable volume is not an installation this
// ablation-derived path set describes, and the pod already reads that tree.
func validateXcodeToolchainDir(raw string, protectedPrefixes []string) (string, error) {
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
	if err := validateExtraPaths("", protectedPrefixes, []string{raw}); err != nil {
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
	writeXcodeHelperCarve(&b, dir, bundle, hasBundle)
	return b.String()
}

// writeXcodeHelperCarve denies the helper BUNDLES that sit inside the two granted
// trees — the .xpc services under the bundle's Frameworks and the .app agents
// under the macOS platform. It is emitted last inside the stanza, so under
// last-match-wins it subtracts from the subpath allows just above it, and the
// protected denies that follow still outrank the whole stanza.
//
// Why they are worth subtracting: they are not part of the interdependent dylib
// set the whole-tree grant exists for (removing them changes no observed
// behaviour — verified by re-running the acceptance pod script under the carved
// profile), and some carry Apple-private entitlements. `Xcode Helper.app` holds
// com.apple.private.tcc.allow-prompting = kTCCServiceAll on 26.6. A confined pod
// could not use that entitlement in any case — exercising it needs a Mach
// connection to tccd, and no rule in any profile this generator emits grants a
// mach-lookup that resolves there — but a grant that does not hand out the
// binary at all needs no such argument, and this one costs nothing.
//
// Be precise about what this carve does and does not do, because the obvious
// reading is wrong: file-read* and process-exec* are DISTINCT Seatbelt
// operations, and the base profile allows process-exec* unconditionally. So
// denying the read does NOT make these unexecutable — a pod with no toolchain
// grant at all can already exec them, which is measurable and was measured. The
// carve narrows what a pod may READ (the Mach-O contents, the entitlement plist,
// the Info.plist); it is not, and must not be described as, an exec boundary.
//
// A pattern rather than a name list: the members change between Xcode releases,
// and a deny that silently stops matching is worse than one that occasionally
// matches something new.
func writeXcodeHelperCarve(b *strings.Builder, dir, bundle string, hasBundle bool) {
	var pats []string
	if hasBundle {
		for _, form := range firmlinkForms(filepath.Join(bundle, "Contents", "Frameworks")) {
			pats = append(pats, "^"+regexp.QuoteMeta(form)+"/.*\\.xpc/")
		}
	}
	for _, form := range firmlinkForms(filepath.Join(dir, "Platforms", "MacOSX.platform", "Developer")) {
		pats = append(pats, "^"+regexp.QuoteMeta(form)+"/.*\\.(app|xpc)/")
	}
	if len(pats) == 0 {
		return
	}
	b.WriteString(";; carve: the helper .xpc/.app bundles inside the trees granted above\n")
	b.WriteString(";; are not part of the interdependent dylib set, and some carry private\n")
	b.WriteString(";; entitlements. Denied LAST so last-match-wins subtracts them. This is a\n")
	b.WriteString(";; READ carve only — process-exec* is allowed profile-wide and is a\n")
	b.WriteString(";; separate operation, so this is not an exec boundary.\n")
	b.WriteString("(deny file-read*\n")
	for _, pat := range pats {
		// NOT %q: the pattern already carries its own regex escapes, and Go's
		// quoting would double every backslash. SBPL accepts the result either
		// way — it just silently stops matching, which is the worst possible
		// failure for a deny. TestXcodeHelperCarveActuallyDenies runs the
		// rendered profile to prove this one still bites.
		b.WriteString("  (regex #\"" + pat + "\")\n")
	}
	b.WriteString("  )\n")
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
