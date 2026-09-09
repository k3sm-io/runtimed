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
			`(subpath "` + xcodeDevDir + `/Platforms/MacOSX.platform/Developer/SDKs")`,
			`(subpath "` + bundle + `/Contents/SharedFrameworks")`,
			`(literal "` + xcodeDevDir + `")`,
			`(literal "` + xcodeDevDir + `/Platforms")`,
			`(literal "` + xcodeDevDir + `/Platforms/MacOSX.platform")`,
			`(literal "` + xcodeDevDir + `/Platforms/MacOSX.platform/Developer")`,
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
			bundle + `/Contents/Frameworks`,
			bundle + `/Contents/SystemFrameworks`,
			bundle + `/Contents/PlugIns`,
			xcodeDevDir + `/Library`,
			"DARWIN_USER_CACHE_DIR",
			"DARWIN_USER_TEMP_DIR",
			"user-preference-read",
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
		{"under-users", "/Users/miko/Xcode.app/Contents/Developer", false},
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
// not inside a Contents/Developer bundle renders the four developer-dir grants
// and NO bundle-level rule — no SharedFrameworks subpath, no plists — rather than
// guessing a bundle root two levels up.
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
	for _, banned := range []string{"SharedFrameworks", "Info.plist", "version.plist"} {
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
