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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/supervisor"
)

// gpuProfile renders the canonical allow_gpu pod profile the golden pins.
func gpuProfile(t *testing.T) string {
	t.Helper()
	sp := &runtimev1.SandboxProfile{
		DataVolumePath: "/var/lib/k3sm/pods/pod-gpu123/rootfs",
		AllowGpu:       true,
	}
	got, err := Generate(sp, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return got
}

// TestGenerateGPUGolden is acceptance M8.2-a1's Metal half: the FULL rendered
// allow_gpu profile is pinned byte-for-byte against testdata/pod-gpu.golden.sb.
//
// A golden rather than a substring assertion because the thing under test is a
// pair of exact IOKit class-name STRINGS with no linker-symbol canary behind them
// (SBPL class names are data): a substring check would pass a profile that also
// granted mach-lookup, iokit-get-properties, or a shader-cache write — every one
// of which the S1 spike measured unnecessary and rejected as over-scope. The
// golden is what makes an ADDED rule as red as a changed one. Run with -update to
// regenerate.
func TestGenerateGPUGolden(t *testing.T) {
	got := gpuProfile(t)

	goldenPath := filepath.Join("testdata", "pod-gpu.golden.sb")
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
		t.Errorf("generated allow_gpu SBPL differs from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestMetalStanzaShape pins the properties of the allow-set that the golden alone
// would let a future edit satisfy in a wrong way: the two EXACT class names, their
// presence in ONE iokit-open rule, and — the load-bearing negatives — the absence
// of every candidate the S1 ablation dropped.
func TestMetalStanzaShape(t *testing.T) {
	profile := gpuProfile(t)

	t.Run("two-exact-classes", func(t *testing.T) {
		want := "(allow iokit-open\n" +
			"  (iokit-registry-entry-class \"AGXDeviceUserClient\")\n" +
			"  (iokit-registry-entry-class \"IOSurfaceRootUserClient\"))\n"
		if !strings.Contains(profile, want) {
			t.Fatalf("allow_gpu profile does not carry the exact two-rule allow-set:\n%s", profile)
		}
	})

	// The negatives below scan RULE lines only: the stanza's own comment names the
	// candidates it does not grant ("no mach-lookup, no iokit-get-properties…"),
	// which is documentation, not a grant.
	rules := ruleLines(profile)

	// Each of these is a rule the plan or the research hints proposed and the lab
	// measured UNNECESSARY. Their absence is the deliverable, not an accident, so
	// re-adding one must go red here as well as in the golden.
	t.Run("no-over-scope", func(t *testing.T) {
		for _, banned := range []string{
			"iokit-registry-entry-class-prefix", // the disproved prefix rule (wrong filter axis)
			"AGXAcceleratorG",                   // the IOService name the prefix was derived from
			"com.apple.MTLCompilerService",      // ablated: cold JIT compiles in-process
			"iokit-get-properties",              // ablated
			"/private/var/db/CVMS",              // ablated
			"com.apple.metalfe",                 // no shader-cache scope
			"DARWIN_USER_CACHE_DIR",             // no shader-cache scope
		} {
			if strings.Contains(rules, banned) {
				t.Errorf("allow_gpu profile contains over-scope rule fragment %q (S1 ablated it)", banned)
			}
		}
	})

	// The pod's own data volume stays the ONLY writable tree: allow_gpu must not
	// have widened file-write* anywhere, which is exactly how a shader-cache allow
	// would have arrived.
	t.Run("no-new-write-scope", func(t *testing.T) {
		withGPU := strings.Count(profile, "(allow file-read* file-write*")
		plain, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-gpu123/rootfs",
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if without := strings.Count(plain, "(allow file-read* file-write*"); withGPU != without {
			t.Fatalf("allow_gpu changed the write scope (%d write-allow rules with GPU, %d without)", withGPU, without)
		}
	})

	// Emission tier: the Metal allow must sit in the ALLOWS tier, BEFORE the
	// protected denies, so last-match-wins keeps /Users and the daemon trees denied
	// for a GPU pod exactly as for any other.
	t.Run("emitted-before-protected-denies", func(t *testing.T) {
		gpuAt := strings.Index(profile, "(allow iokit-open")
		denyAt := strings.Index(profile, "(deny file-read* file-write*")
		if gpuAt < 0 || denyAt < 0 {
			t.Fatalf("expected both the GPU allow and the protected denies in:\n%s", profile)
		}
		if gpuAt > denyAt {
			t.Fatal("the Metal allow is emitted AFTER the protected denies; last-match-wins would let it outrank them")
		}
	})

	// Off by default: a profile that did not ask for the GPU gets no iokit rule.
	t.Run("absent-without-allow-gpu", func(t *testing.T) {
		plain, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/pod-plain/rootfs",
		}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if strings.Contains(plain, "iokit-open") {
			t.Fatalf("a profile without allow_gpu granted iokit-open:\n%s", plain)
		}
	})
}

// ruleLines returns profile with its ;;-comment lines removed — the RULE text a
// Seatbelt compiler would act on.
func ruleLines(profile string) string {
	var keep []string
	for _, line := range strings.Split(profile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), ";") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// stubBackend is a Backend whose Available/Name are fixed — the seam
// SandboxGPUSupported consumes.
type stubBackend struct {
	name      string
	available bool
}

func (b stubBackend) Available() bool { return b.available }
func (b stubBackend) Name() string    { return b.name }
func (b stubBackend) WrapCommand(_ context.Context, _ string, _ []string, _ supervisor.LaunchSpec) (string, []string, func() error, error) {
	return "", nil, func() error { return nil }, nil
}

// TestSandboxGPUSupported pins the fail-closed advertisement control (Resolution
// 14): sandbox_gpu_supported is the AND of "the selected backend can express the
// Metal allow-set" and "the functional probe passed". Every other combination
// reports false.
func TestSandboxGPUSupported(t *testing.T) {
	functional := MetalStatus{Functional: true, Reason: MetalReasonOK}
	cases := []struct {
		name    string
		backend Backend
		metal   MetalStatus
		want    bool
	}{
		{"seatbelt-available-functional", stubBackend{ExecShimBackendName, true}, functional, true},
		{"seatbelt-available-probe-failed", stubBackend{ExecShimBackendName, true}, MetalStatus{Reason: MetalReasonNoDevice}, false},
		{"seatbelt-available-paravirtual", stubBackend{ExecShimBackendName, true}, MetalStatus{Paravirtual: true, Reason: MetalReasonParavirtual}, false},
		{"seatbelt-unavailable", stubBackend{ExecShimBackendName, false}, functional, false},
		{"vm-backend", stubBackend{VMBackendName, true}, functional, false},
		{"unknown-backend", stubBackend{"future-rung", true}, functional, false},
		{"nil-backend", nil, functional, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SandboxGPUSupported(tc.backend, tc.metal); got != tc.want {
				t.Fatalf("SandboxGPUSupported = %v, want %v", got, tc.want)
			}
		})
	}
}
