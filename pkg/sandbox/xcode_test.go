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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// xcodeDevDir is the canonical DEVELOPER_DIR the fixtures render from — the value
// `xcode-select -p` returns for a stock Xcode install, and the one the 2026-09-09
// ablation was run against.
const xcodeDevDir = "/Applications/Xcode.app/Contents/Developer"

// xcodeProfile renders the canonical toolchain pod profile the golden pins. It
// reuses TestGenerateGPUGolden's fixture inputs verbatim and adds only the
// toolchain dir, so the golden also pins the EMISSION ORDER: the toolchain stanza
// must land immediately after the allow_gpu stanza and before the protected denies.
func xcodeProfile(t *testing.T) string {
	t.Helper()
	sp := &runtimev1.SandboxProfile{
		DataVolumePath:    "/var/lib/k3sm/pods/pod-gpu123/rootfs",
		AllowGpu:          true,
		XcodeToolchainDir: xcodeDevDir,
	}
	got, err := Generate(sp, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return got
}

// TestGenerateXcodeToolchainGolden pins the full rendered xcode_toolchain_dir
// profile byte-for-byte against testdata/pod-xcode.golden.sb.
//
// A golden rather than a substring assertion for the reason the Metal golden
// gives: the deliverable is an ABLATION-MINIMAL path set, and a substring check
// passes a profile that also granted Contents/Frameworks, the module cache, or a
// subpath on the bundle root. The golden is what makes an ADDED rule as red as a
// changed one. Run with -update to regenerate.
func TestGenerateXcodeToolchainGolden(t *testing.T) {
	got := xcodeProfile(t)

	goldenPath := filepath.Join("testdata", "pod-xcode.golden.sb")
	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("generated xcode_toolchain_dir SBPL differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestXcodeToolchainStanzaShape pins the properties the golden alone would let a
// future edit satisfy in a wrong way: every ablation-derived rule is present in
// the right grant class, nothing became writable, and the bundle is never granted
// wholesale.
func TestXcodeToolchainStanzaShape(t *testing.T) {
	profile := xcodeProfile(t)
	rules := ruleLines(profile)
	const bundle = "/Applications/Xcode.app"

	// Each of these was a real Seatbelt denial in the ablation; its presence in
	// the right grant class is the deliverable.
	t.Run("every-ablation-rule-present", func(t *testing.T) {
		for _, want := range []string{
			`(subpath "` + xcodeDevDir + `/usr/bin")`,
			`(subpath "` + xcodeDevDir + `/usr/lib")`,
			`(subpath "` + xcodeDevDir + `/Toolchains/XcodeDefault.xctoolchain")`,
			`(subpath "` + xcodeDevDir + `/Platforms/MacOSX.platform/Developer")`,
			`(subpath "` + xcodeDevDir + `/Library/Frameworks/XcodeKit.framework")`,
			`(subpath "` + bundle + `/Contents/SharedFrameworks")`,
			`(subpath "` + bundle + `/Contents/Frameworks")`,
			`(literal "` + xcodeDevDir + `")`,
			`(literal "` + xcodeDevDir + `/Toolchains")`,
			`(literal "` + xcodeDevDir + `/Platforms")`,
			`(literal "` + xcodeDevDir + `/Platforms/MacOSX.platform")`,
			`(literal "` + xcodeDevDir + `/Platforms/MacOSX.platform/Info.plist")`,
			`(literal "` + bundle + `/Contents/Info.plist")`,
			`(literal "` + bundle + `/Contents/version.plist")`,
		} {
			if !strings.Contains(rules, want) {
				t.Errorf("toolchain profile is missing the ablation-derived rule %s", want)
			}
		}
	})

	// The stat-walk tier: existence only, and it must be the metadata rule that
	// carries the ancestors — a file-read* on /Applications/Xcode.app/Contents
	// would be a readable bundle by another name.
	t.Run("ancestors-are-metadata-only", func(t *testing.T) {
		metaAt := strings.Index(rules, "(allow file-read-metadata")
		if metaAt < 0 {
			t.Fatalf("no file-read-metadata rule in:\n%s", profile)
		}
		meta := rules[metaAt:]
		for _, want := range []string{
			`(literal "/Applications")`,
			`(literal "/Applications/Xcode.app")`,
			`(literal "/Applications/Xcode.app/Contents")`,
		} {
			if !strings.Contains(meta, want) {
				t.Errorf("stat-walk ancestor %s is not in the file-read-metadata rule", want)
			}
		}
		// The same paths must NOT appear in a read rule above it.
		readTier := rules[:metaAt]
		for _, banned := range []string{
			`(literal "/Applications/Xcode.app/Contents")` + "\n",
			`(literal "/Applications/Xcode.app")` + "\n",
		} {
			if strings.Contains(readTier, banned) {
				t.Errorf("ancestor rule %q was granted file-read*, not metadata-only", strings.TrimSpace(banned))
			}
		}
	})

	// The bundle is never granted wholesale: no subpath on the bundle root, on
	// Contents, or on the developer dir itself, and none of the IDE-only trees the
	// ablation dropped.
	t.Run("no-bundle-wide-grant", func(t *testing.T) {
		for _, banned := range []string{
			`(subpath "` + bundle + `")`,
			`(subpath "` + bundle + `/Contents")`,
			`(subpath "` + xcodeDevDir + `")`,
			// The two bundle framework trees are granted; the IDE trees beside
			// them are not, and neither is D/Library above XcodeKit.framework.
			`(subpath "` + bundle + `/Contents/SystemFrameworks")`,
			`(subpath "` + bundle + `/Contents/PlugIns")`,
			`(subpath "` + bundle + `/Contents/Resources")`,
			`(subpath "` + xcodeDevDir + `/Library")`,
			`(subpath "` + xcodeDevDir + `/Library/Frameworks")`,
			// Sibling platforms: only MacOSX.platform is in scope.
			xcodeDevDir + `/Platforms/iPhoneOS.platform`,
			xcodeDevDir + `/Platforms/DriverKit.platform`,
			// The per-user caches a full xcodebuild build wants. They are not a
			// path-list gap — see xcode.go on why that build is out of reach.
			"DARWIN_USER_CACHE_DIR",
			"DARWIN_USER_TEMP_DIR",
			"user-preference-read",
			"job-creation",
			"mach-lookup",
		} {
			if strings.Contains(rules, banned) {
				t.Errorf("toolchain profile contains out-of-scope grant %q (the ablation excluded it)", banned)
			}
		}
	})

	// Read-only, structurally: the stanza emits file-read*/file-read-metadata and
	// nothing else, and it did not add a write-allow rule anywhere.
	t.Run("nothing-writable", func(t *testing.T) {
		withXcode := strings.Count(profile, "(allow file-write*") + strings.Count(profile, "(allow file-read* file-write*")
		plain, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-gpu123/rootfs",
			AllowGpu:       true,
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		without := strings.Count(plain, "(allow file-write*") + strings.Count(plain, "(allow file-read* file-write*")
		if withXcode != without {
			t.Fatalf("xcode_toolchain_dir changed the write scope (%d write-allow rules with it, %d without)", withXcode, without)
		}
		// and no write rule mentions the toolchain at all.
		for _, line := range strings.Split(rules, "\n") {
			if strings.Contains(line, "file-write*") && strings.Contains(line, "Xcode") {
				t.Errorf("a write rule names the toolchain: %q", strings.TrimSpace(line))
			}
		}
	})

	// Emission tier: after the GPU allow, before the protected denies, so
	// last-match-wins keeps /Users and the daemon trees denied for a build pod.
	t.Run("emitted-after-gpu-before-protected-denies", func(t *testing.T) {
		gpuAt := strings.Index(profile, "(allow iokit-open")
		xcodeAt := strings.Index(profile, `(subpath "`+xcodeDevDir+`/usr/bin")`)
		denyAt := strings.Index(profile, "(deny file-read* file-write*")
		if gpuAt < 0 || xcodeAt < 0 || denyAt < 0 {
			t.Fatalf("expected the GPU allow, the toolchain allow and the protected denies in:\n%s", profile)
		}
		if !(gpuAt < xcodeAt && xcodeAt < denyAt) {
			t.Fatalf("emission order is gpu=%d xcode=%d denies=%d; want gpu < xcode < denies", gpuAt, xcodeAt, denyAt)
		}
	})
}

// TestXcodeToolchainAbsentWhenEmpty is the off-by-default proof: a profile that
// did not ask for the toolchain renders byte-identically to the pod.golden.sb
// fixture, so the feature adds nothing to the default profile.
func TestXcodeToolchainAbsentWhenEmpty(t *testing.T) {
	got, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: "/var/lib/k3sm/pods/pod-abc123/rootfs",
		AllowNetwork:   true,
	}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "pod.golden.sb"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if got != string(want) {
		t.Errorf("an empty xcode_toolchain_dir changed the default profile.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if strings.Contains(got, "Xcode") || strings.Contains(got, "file-read-metadata") {
		t.Errorf("a profile without xcode_toolchain_dir carries a toolchain rule:\n%s", got)
	}
}

// TestXcodeToolchainDirValidation pins the fail-closed validation: every rejected
// shape returns ErrXcodeToolchainDir and NO profile, so a bad value can never be
// silently dropped from an otherwise-emitted profile.
func TestXcodeToolchainDirValidation(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		ok   bool
	}{
		{"valid-xcode-app", xcodeDevDir, true},
		{"valid-relocated-bundle", "/Volumes/Build/Xcode.app/Contents/Developer", true},
		{"empty-grants-nothing", "", true},
		{"relative", "Applications/Xcode.app/Contents/Developer", false},
		{"unclean", "/Applications/Xcode.app/Contents/../Contents/Developer", false},
		{"filesystem-root", "/", false},
		{"under-users", "/Users/someone/Xcode.app/Contents/Developer", false},
		{"under-pods-root", "/var/lib/k3sm/pods/other/Developer", false},
		{"base-not-developer", "/Applications/Xcode.app/Contents", false},
		// The Command Line Tools root is a real, common `xcode-select -p` value and
		// is refused on purpose: it is not a DEVELOPER_DIR of the shape this
		// ablation covers, and every path the stanza derives would be wrong for it.
		{"command-line-tools", "/Library/Developer/CommandLineTools", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := &runtimev1.SandboxProfile{
				DataVolumePath:    "/var/lib/k3sm/pods/pod-xc/rootfs",
				XcodeToolchainDir: tc.dir,
			}
			got, err := Generate(sp, GenerateOptions{})
			if tc.ok {
				if err != nil {
					t.Fatalf("Generate(%q): unexpected error %v", tc.dir, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Generate(%q): want ErrXcodeToolchainDir, got a profile:\n%s", tc.dir, got)
			}
			if !errors.Is(err, ErrXcodeToolchainDir) {
				t.Fatalf("Generate(%q): want ErrXcodeToolchainDir, got %v", tc.dir, err)
			}
			if got != "" {
				t.Fatalf("Generate(%q): returned a profile alongside the error", tc.dir)
			}
		})
	}
}

// TestXcodeStanzaWithoutBundle pins the no-bundle case: a DEVELOPER_DIR that is
// not inside a Contents/Developer bundle renders the developer-dir grants and NO
// bundle-level rule — neither framework subpath, no plists — rather than guessing
// a bundle root two levels up. Such a toolchain cannot run xcodebuild (the loader
// dylib lives in the bundle), which is the honest consequence of not having one.
func TestXcodeStanzaWithoutBundle(t *testing.T) {
	const dir = "/opt/toolchains/Developer"
	stanza := xcodeToolchainStanza(dir)
	for _, want := range []string{
		`(subpath "` + dir + `/usr/bin")`,
		`(literal "` + dir + `")`,
		`(literal "/opt")`,
		`(literal "/opt/toolchains")`,
	} {
		if !strings.Contains(stanza, want) {
			t.Errorf("no-bundle stanza is missing %s:\n%s", want, stanza)
		}
	}
	// Banned by their BUNDLE-relative shape, not by bare file name: the stanza
	// legitimately names the macOS platform's own Info.plist, which lives under
	// the developer dir and has nothing to do with a bundle.
	for _, banned := range []string{
		"SharedFrameworks",
		"Contents/Frameworks",
		"Contents/Info.plist",
		"version.plist",
	} {
		if strings.Contains(stanza, banned) {
			t.Errorf("no-bundle stanza emitted a bundle-level rule %q:\n%s", banned, stanza)
		}
	}
}

// TestXcodeProfileAppliesOnDarwin feeds the toolchain profile to the same
// libsandbox the runtime uses, so an invalid SBPL construct (file-read-metadata
// is a distinct operation from file-read*, and a bad filter would compile-fail)
// is caught here rather than at the first build pod on a node.
func TestXcodeProfileAppliesOnDarwin(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	prof := xcodeProfile(t)
	f := filepath.Join(t.TempDir(), "xcode.sb")
	if err := os.WriteFile(f, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", f, "/usr/bin/true").CombinedOutput(); err != nil {
		t.Fatalf("sandbox-exec rejected the toolchain profile: %v\n--- output ---\n%s\n--- profile ---\n%s", err, out, prof)
	}
}

// TestXcodeGrantDoesNotOutrankProtectedDenies is the regression guard the widening
// of 2026-09-09 earns. The grant grew — it now reaches both of the bundle's
// framework trees and the macOS platform whole — so the property that matters is
// no longer "the stanza is small" but "however large it gets, the protected denies
// still win". SBPL is last-match-wins, so that is a statement about ORDER, and it
// is asserted per deny-set member rather than once for the block: a future edit
// that appends a toolchain rule after a single deny would still pass a check that
// only looked at the first one.
func TestXcodeGrantDoesNotOutrankProtectedDenies(t *testing.T) {
	profile := xcodeProfile(t)

	lastGrant := strings.LastIndex(profile, `"`+xcodeDevDir)
	if lastGrant < 0 {
		t.Fatalf("no toolchain rule in:\n%s", profile)
	}
	// Every protected deny must be emitted AFTER the last toolchain rule.
	for _, deny := range []string{
		`(subpath "/Users")`,
		`(subpath "/private/var/db")`,
		`(subpath "/var/lib/k3sm/pods")`,
		`(subpath "/var/lib/k3sm/server")`,
		`(subpath "/var/lib/k3sm/agent")`,
	} {
		at := strings.Index(profile, deny)
		if at < 0 {
			t.Errorf("protected deny %s is missing from a toolchain profile", deny)
			continue
		}
		if at < lastGrant {
			t.Errorf("protected deny %s is emitted at %d, BEFORE the last toolchain grant at %d — last-match-wins would let the grant override it", deny, at, lastGrant)
		}
	}
}

// TestXcodeGrantStaysReadOnlyAndFileScoped pins the two properties that make the
// widened grant still a READ grant: it names no non-file operation, and the paths
// a full `xcodebuild build` would additionally need are absent. That build is out
// of reach by construction (job-creation, Mach services, and host-user state under
// the /Users deny), so its absence here is the API contract, not an oversight —
// see the "What this grant reaches, and where it stops" block in xcode.go.
func TestXcodeGrantStaysReadOnlyAndFileScoped(t *testing.T) {
	stanza := xcodeToolchainStanza(xcodeDevDir)
	// Rules only: the stanza's own comment NAMES the operations a full xcodebuild
	// build would need, in order to say they are not granted. Scanning the comment
	// would make that explanation trip the check it exists to describe.
	rules := ruleLines(stanza)

	// Only file-read operations. A future edit that reached for a Mach service or
	// a process right to "make xcodebuild work" fails here first.
	for _, banned := range []string{
		"job-creation",
		"mach-lookup",
		"mach-register",
		"iokit-open",
		"sysctl-read",
		"ipc-posix-shm",
		"process-exec",
		"network",
		"file-write",
	} {
		if strings.Contains(rules, banned) {
			t.Errorf("the toolchain stanza names %q; it must emit file-read rules only:\n%s", banned, stanza)
		}
	}

	// Exactly the read tiers, and nothing else.
	for _, want := range []string{"(allow file-read*", "(allow file-read-metadata"} {
		if !strings.Contains(rules, want) {
			t.Errorf("the toolchain stanza is missing its %s tier:\n%s", want, stanza)
		}
	}
	if n := strings.Count(rules, "(allow "); n != 3 {
		t.Errorf("the toolchain stanza emits %d allow rules; want exactly 3 (two read tiers plus the metadata tier)", n)
	}
}

// TestXcodeToolchainGrantReachesTheToolchain is the in-tree, generator-driven
// re-derivation of the ablation: it renders a profile with Generate — the shipped
// renderer, not a replica — and runs the real toolchain under it via sandbox-exec.
//
// It exists because every other test here asserts the SHAPE of the stanza, and a
// shape can be exactly right and still not work: the 2026-09-09 derivation found
// that the previously-shipped path set compiled nothing on Xcode 26.6, because
// swift-frontend stats DEVELOPER_DIR/Toolchains and no golden could have said so.
// A path list is a hypothesis about another program's behaviour, and only running
// that program tests it.
//
// Skipped, never failed, when the host has no usable Xcode: the assertion is about
// the profile, and a machine without the toolchain cannot answer it either way.
func TestXcodeToolchainGrantReachesTheToolchain(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	devDir, err := exec.Command("/usr/bin/xcode-select", "-p").Output()
	if err != nil {
		t.Skip("xcode-select -p failed; no developer dir to grant")
	}
	dir := strings.TrimSpace(string(devDir))
	if filepath.Base(dir) != xcodeDeveloperDirBase {
		t.Skipf("xcode-select -p is %q, not a DEVELOPER_DIR this grant covers", dir)
	}
	if err := exec.Command("/usr/bin/xcodebuild", "-version").Run(); err != nil {
		t.Skipf("the host's own xcodebuild does not run (%v); nothing to confine", err)
	}

	// The pod's data volume must live under the configured pods root, and the
	// profile denies /Users outright — so t.TempDir() (under /var/folders on a
	// normal run) cannot serve. Build the posture around a temp work-dir instead.
	work := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(work); err == nil {
		work = resolved
	}
	if strings.HasPrefix(work, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s), which the pod profile denies", work)
	}
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	// The toolchain writes temporaries; TMPDIR below points here, and a pod that
	// cannot create them fails for a reason that is not the grant.
	if err := os.MkdirAll(filepath.Join(dataVol, "tmp", "mc"), 0o755); err != nil {
		t.Fatal(err)
	}

	profile, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:    dataVol,
		XcodeToolchainDir: dir,
	}, GenerateOptions{Posture: Posture{WorkDir: work}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	profPath := filepath.Join(work, "xcode.sb")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}

	// Each case runs from INSIDE the data volume with DEVELOPER_DIR set, which is
	// how a pod reaches the toolchain (the pod's cwd is its data volume, and the
	// profile denies metadata on that volume's ancestors, so absolute paths and
	// mkdir -p are the pod's problem, not the grant's).
	confined := func(t *testing.T, argv ...string) (string, int) {
		t.Helper()
		cmd := exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", profPath}, argv...)...)
		cmd.Dir = dataVol
		cmd.Env = append(os.Environ(),
			"DEVELOPER_DIR="+dir,
			"HOME="+dataVol,
			"TMPDIR="+filepath.Join(dataVol, "tmp"),
			// The compiler's module cache defaults to the invoking user's shared
			// /var/folders tree, which the pod profile denies and this grant
			// deliberately does not open. Pointing it at the pod's own volume is
			// the documented workload-side setting, the same one the B264
			// acceptance pod uses — not a widening of the profile.
			"CLANG_MODULE_CACHE_PATH="+filepath.Join(dataVol, "tmp", "mc"),
		)
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("sandbox-exec %v: %v", argv, err)
		}
		return string(out), code
	}

	// REACH: the tools the grant claims to cover.
	t.Run("xcrun-resolves-into-the-granted-toolchain", func(t *testing.T) {
		out, code := confined(t, "/usr/bin/xcrun", "--find", "swift")
		if code != 0 {
			t.Fatalf("xcrun --find swift exited %d under the grant:\n%s", code, out)
		}
		// The point of the grant is that the pod reaches THIS toolchain. A resolve
		// to /Library/Developer/CommandLineTools is the failure mode that looks
		// like success: xcrun falls back to it whenever the Xcode lookup breaks.
		var found string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.HasSuffix(strings.TrimSpace(line), "/swift") {
				found = strings.TrimSpace(line)
			}
		}
		if !strings.HasPrefix(found, dir) {
			t.Errorf("xcrun --find swift resolved to %q, not under the granted developer dir %q — the pod fell back to the Command Line Tools", found, dir)
		}
	})

	t.Run("xcodebuild-can-interrogate-the-install", func(t *testing.T) {
		for _, arg := range []string{"-version", "-showsdks"} {
			if out, code := confined(t, "/usr/bin/xcodebuild", arg); code != 0 {
				t.Errorf("xcodebuild %s exited %d under the grant:\n%s", arg, code, out)
			}
		}
	})

	t.Run("swiftc-compiles-and-the-binary-runs", func(t *testing.T) {
		src := filepath.Join(dataVol, "main.swift")
		if err := os.WriteFile(src, []byte(`print("hello from a pod")`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sdk := filepath.Join(dir, "Platforms", "MacOSX.platform", "Developer", "SDKs", "MacOSX.sdk")
		tc := filepath.Join(dir, "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin", "swiftc")
		if out, code := confined(t, tc, "-sdk", sdk, "-module-cache-path", "tmp/mc", "-o", "one", "main.swift"); code != 0 {
			t.Fatalf("confined swiftc exited %d:\n%s", code, out)
		}
		out, code := confined(t, filepath.Join(dataVol, "one"))
		if code != 0 || !strings.Contains(out, "hello from a pod") {
			t.Errorf("the binary swiftc built exited %d and said %q; want 0 and the sentinel", code, out)
		}
	})

	// CEILING: a pod must NOT be able to drive a project-evaluating build. This is
	// the half that would silently rot — a future widening that "fixes xcodebuild"
	// by granting Mach services or /Users would pass every reach case above.
	t.Run("project-evaluation-stays-out-of-reach", func(t *testing.T) {
		if out, code := confined(t, "/usr/bin/xcodebuild", "-list"); code == 0 {
			t.Errorf("xcodebuild -list succeeded under the toolchain grant:\n%s\nthe documented ceiling did not hold — the profile is granting more than a toolchain read scope", out)
		}
	})
}

// TestXcodeGrantNoMachLookupWhenCombined pins the second of the two invariants
// the documented ceiling rests on, at the level where it can actually break.
//
// The first invariant — /Users stays denied — is asserted per-member by
// TestXcodeGrantDoesNotOutrankProtectedDenies. The second is that a profile
// carrying the toolchain grant never also carries a mach-lookup that reaches a
// system service: that is what stops a full xcodebuild build, and it is also what
// keeps the Apple-private entitlements on some of the granted content inert.
//
// It is asserted over Generate rather than over the stanza because the stanza
// cannot break it. The failure mode is COMPOSITIONAL: some other opt-in grows a
// broader mach-lookup, and a pod that sets both fields silently acquires it. So
// the case that matters is every combination of the widening opt-ins at once.
func TestXcodeGrantNoMachLookupWhenCombined(t *testing.T) {
	// The exact global-names the generator is allowed to reach today. A new one
	// belongs in this list only alongside an argument about the ceiling above.
	allowed := map[string]bool{
		"com.apple.dnssd.service": true,
		"com.apple.mDNSResponder": true,
	}

	for _, tc := range []struct {
		name string
		sp   *runtimev1.SandboxProfile
	}{
		{"toolchain-only", &runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-xc/rootfs", XcodeToolchainDir: xcodeDevDir}},
		{"toolchain-and-network", &runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-xc/rootfs", XcodeToolchainDir: xcodeDevDir,
			AllowNetwork: true}},
		{"toolchain-network-gpu-egress", &runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-xc/rootfs", XcodeToolchainDir: xcodeDevDir,
			AllowNetwork: true, AllowGpu: true, AllowInternetEgress: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := Generate(tc.sp, GenerateOptions{})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			rules := ruleLines(profile)
			if !strings.Contains(rules, "mach-lookup") {
				return // nothing to check
			}
			// Every mach-lookup that IS emitted must be global-name-scoped to a
			// name on the list. An unscoped `(allow mach-lookup)` has no
			// global-name at all and therefore cannot satisfy this.
			for _, line := range strings.Split(rules, "\n") {
				if !strings.Contains(line, "mach-lookup") && !strings.Contains(line, "global-name") {
					continue
				}
				if strings.Contains(line, "(allow mach-lookup)") {
					t.Fatalf("profile grants UNSCOPED mach-lookup alongside the toolchain grant: %q", strings.TrimSpace(line))
				}
				for _, m := range regexp.MustCompile(`\(global-name "([^"]+)"\)`).FindAllStringSubmatch(line, -1) {
					if !allowed[m[1]] {
						t.Errorf("profile grants mach-lookup to %q alongside the toolchain grant; the documented ceiling depends on no such service being reachable", m[1])
					}
				}
			}
		})
	}
}

// TestXcodeHelperCarveSubtractsFromTheGrantedTrees pins the read carve: the
// helper bundles inside the two granted trees are denied, the deny lands AFTER
// the allows it subtracts from (last-match-wins, so order is the whole
// mechanism), and it is a READ carve — it must never be written or described as
// an exec boundary, because process-exec* is allowed profile-wide.
func TestXcodeHelperCarveSubtractsFromTheGrantedTrees(t *testing.T) {
	stanza := xcodeToolchainStanza(xcodeDevDir)
	rules := ruleLines(stanza)

	denyAt := strings.Index(rules, "(deny file-read*")
	if denyAt < 0 {
		t.Fatalf("the toolchain stanza emits no helper carve:\n%s", stanza)
	}
	// It must come after BOTH subpath allows it subtracts from.
	for _, granted := range []string{
		`(subpath "/Applications/Xcode.app/Contents/Frameworks")`,
		`(subpath "` + xcodeDevDir + `/Platforms/MacOSX.platform/Developer")`,
	} {
		at := strings.Index(rules, granted)
		if at < 0 {
			t.Fatalf("the grant %s the carve subtracts from is missing", granted)
		}
		if at > denyAt {
			t.Errorf("the carve is emitted at %d, BEFORE the allow at %d — last-match-wins would let the allow win", denyAt, at)
		}
	}
	// Both patterns present, and the carve names only file-read.
	// Single-escaped, as SBPL reads it. The doubled form is the %q bug
	// TestXcodeHelperCarveActuallyDenies exists for: it renders, it compiles,
	// and it matches nothing.
	for _, want := range []string{`\.xpc/`, `\.(app|xpc)/`} {
		if !strings.Contains(rules, want) {
			t.Errorf("the carve is missing the pattern %s:\n%s", want, stanza)
		}
	}
	carve := rules[denyAt:]
	if strings.Contains(carve, "process-exec") || strings.Contains(carve, "file-write") {
		t.Errorf("the carve names an operation other than file-read; it is a READ carve only:\n%s", carve)
	}
}

// TestXcodeHelperCarveActuallyDenies runs the rendered profile, because a deny is
// the one rule class a shape test cannot check.
//
// This exists for a specific bug it would have caught: the carve was first
// emitted through Go's %q, which doubled every backslash in the pattern. SBPL
// accepted the result without complaint and it matched nothing — a deny that
// silently grants. Every structural assertion in this file passed. Only running
// it found the problem, so the regression guard has to run it too.
func TestXcodeHelperCarveActuallyDenies(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	devDir, err := exec.Command("/usr/bin/xcode-select", "-p").Output()
	if err != nil {
		t.Skip("xcode-select -p failed; no developer dir to grant")
	}
	dir := strings.TrimSpace(string(devDir))
	if filepath.Base(dir) != xcodeDeveloperDirBase {
		t.Skipf("xcode-select -p is %q, not a DEVELOPER_DIR this grant covers", dir)
	}
	bundle, ok := xcodeBundleRoot(dir)
	if !ok {
		t.Skipf("%q has no enclosing bundle, so no carve is rendered", dir)
	}

	// A carved path and an un-carved sibling in the SAME granted tree. Both must
	// be found on this host, or the test proves nothing and says so.
	carved := findOne(t, filepath.Join(bundle, "Contents", "Frameworks"), ".xpc")
	kept := filepath.Join(bundle, "Contents", "Frameworks", "libxcodebuildLoader.dylib")
	if _, err := os.Stat(kept); err != nil {
		t.Skipf("%s absent on this host", kept)
	}

	work := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(work); err == nil {
		work = resolved
	}
	if strings.HasPrefix(work, "/Users/") {
		t.Skipf("TMPDIR resolves under /Users (%s), which the pod profile denies", work)
	}
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	profile, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath: dataVol, XcodeToolchainDir: dir,
	}, GenerateOptions{Posture: Posture{WorkDir: work}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	profPath := filepath.Join(work, "carve.sb")
	if err := os.WriteFile(profPath, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	readable := func(path string) bool {
		cmd := exec.Command("/usr/bin/sandbox-exec", "-f", profPath, "/bin/cat", path)
		cmd.Dir = dataVol
		cmd.Stdout, cmd.Stderr = nil, nil
		return cmd.Run() == nil
	}

	if readable(carved) {
		t.Errorf("the carve did not bite: %s is still readable under the rendered profile", carved)
	}
	// The other half: the carve must not have swallowed the tree it subtracts
	// from. A deny that denies everything would pass the assertion above.
	if !readable(kept) {
		t.Errorf("the carve over-reached: %s is no longer readable, but it is the dylib the whole-tree grant exists for", kept)
	}
}

// findOne returns the first entry under root whose name ends in suffix, failing
// the test when there is none — the carve cases are only meaningful if the host
// actually has something for them to match.
func findOne(t *testing.T, root, suffix string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || found != "" {
			return nil //nolint:nilerr // an unreadable subtree is not this test's concern
		}
		if info.IsDir() && strings.HasSuffix(p, suffix) {
			// a file INSIDE the bundle: the carve pattern ends in "/", so it
			// matches the contents, which is what a reader would actually open.
			found = filepath.Join(p, "Contents", "Info.plist")
		}
		return nil
	})
	if found == "" {
		t.Skipf("no %s bundle under %s on this host", suffix, root)
	}
	return found
}

// TestValidateXcodeToolchainDirIsGenerateSOwnVerdict is the anti-drift gate on
// the exported predicate: over one table it asserts that
// ValidateXcodeToolchainDir and Generate reach the SAME verdict for every
// rejection class, so the answer a caller gets before it sets the field is the
// answer the field will get.
//
// It runs the same six rejection classes TestXcodeToolchainDirValidation pins
// (relative, unclean, filesystem-root, under-users, under-pods-root,
// base-not-developer) plus the valid and empty cases, because a predicate that
// honoured only the base-name rule would look right on the interesting cases
// and wave through a developer dir under /Users.
//
// The pairing is the point. Asserting the predicate alone would pass against a
// hand-written second copy of the rules — which is exactly the outcome the
// export exists to prevent.
func TestValidateXcodeToolchainDirIsGenerateSOwnVerdict(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		ok   bool
	}{
		{"valid-xcode-app", xcodeDevDir, true},
		{"valid-relocated-bundle", "/Volumes/Build/Xcode.app/Contents/Developer", true},
		{"empty-grants-nothing", "", true},
		{"relative", "Applications/Xcode.app/Contents/Developer", false},
		{"unclean", "/Applications/Xcode.app/Contents/../Contents/Developer", false},
		{"filesystem-root", "/", false},
		{"under-users", "/Users/someone/Xcode.app/Contents/Developer", false},
		{"under-pods-root", "/var/lib/k3sm/pods/other/Developer", false},
		{"base-not-developer", "/Applications/Xcode.app/Contents", false},
		// The Command Line Tools root: the value `xcode-select -p` prints on a
		// node with no Xcode, and the one a caller most needs a verdict on.
		{"command-line-tools", "/Library/Developer/CommandLineTools", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The zero Posture is the default work-dir posture Generate below
			// also runs under, so the two see the same deny-set.
			got, err := ValidateXcodeToolchainDir(tc.dir, Posture{})
			if tc.ok {
				if err != nil {
					t.Fatalf("ValidateXcodeToolchainDir(%q): unexpected error %v", tc.dir, err)
				}
				if got != tc.dir {
					t.Errorf("ValidateXcodeToolchainDir(%q) = %q; the accepted value must come back unchanged", tc.dir, got)
				}
			} else {
				if err == nil {
					t.Fatalf("ValidateXcodeToolchainDir(%q): want ErrXcodeToolchainDir, got %q", tc.dir, got)
				}
				if !errors.Is(err, ErrXcodeToolchainDir) {
					t.Fatalf("ValidateXcodeToolchainDir(%q): want ErrXcodeToolchainDir, got %v", tc.dir, err)
				}
				if got != "" {
					t.Errorf("ValidateXcodeToolchainDir(%q) returned %q alongside the error", tc.dir, got)
				}
			}

			// The same question asked the long way round. A disagreement here
			// is the drift the export exists to make impossible.
			_, genErr := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:    "/var/lib/k3sm/pods/pod-xc/rootfs",
				XcodeToolchainDir: tc.dir,
			}, GenerateOptions{})
			if errors.Is(genErr, ErrXcodeToolchainDir) == (err == nil) {
				t.Fatalf("the predicate and Generate disagree on %q: predicate err = %v, Generate err = %v", tc.dir, err, genErr)
			}
		})
	}
}

// TestValidateXcodeToolchainDirTracksThePosture pins the one input that is not
// a property of the dir: the deny-set derived from the node's work-dir. A
// developer dir sitting inside a node's pods root is refused, and it is refused
// only when the caller says where that root is — the residual the exported
// doc comment records, asserted rather than merely described.
func TestValidateXcodeToolchainDirTracksThePosture(t *testing.T) {
	const dir = "/opt/k3sm-home/pods/tenant/Developer"
	if _, err := ValidateXcodeToolchainDir(dir, Posture{}); err != nil {
		t.Fatalf("under the DEFAULT posture %q is not in any deny-set; got %v", dir, err)
	}
	_, err := ValidateXcodeToolchainDir(dir, Posture{WorkDir: "/opt/k3sm-home"})
	if !errors.Is(err, ErrXcodeToolchainDir) {
		t.Fatalf("under a work-dir of /opt/k3sm-home, %q is inside the pods root; want ErrXcodeToolchainDir, got %v", dir, err)
	}
}
