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

// Package acceptance holds the tests of runtimed's hack/ scripts.
package acceptance

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestStaticcheckCandidateOrder pins the lookup order of
// staticcheck_pick in hack/staticcheck-pick.sh: the versioned
// $GOPATH/bin/staticcheck-<pin> first, then PATH, then $GOPATH/bin/staticcheck,
// each accepted only when it reports exactly the pin; no candidate at the pin
// is a named red. The fakes are shell stubs on a temp GOPATH and PATH, so no
// real staticcheck and no network are involved.
func TestStaticcheckCandidateOrder(t *testing.T) {
	t.Run("ci_sh_wires_picker", checkStaticcheckCIWiring)
	const pin = "2026.2.2"
	const other = "staticcheck 2025.1 (0.6.0)"
	atPin := "staticcheck " + pin + " (0.8.1)"
	script, err := filepath.Abs(filepath.Join("..", "staticcheck-pick.sh"))
	if err != nil {
		t.Fatal(err)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go not on PATH: %v", err)
	}

	cases := []struct {
		name      string
		versioned string // GOPATH/bin/staticcheck-<pin> -version output; "" = absent
		onPath    string // PATH staticcheck
		plain     string // GOPATH/bin/staticcheck
		wantRed   bool
		wantBy    string // "versioned", "path" or "plain"
		wantOut   []string
	}{
		{name: "versioned_binary_wins", versioned: atPin, onPath: atPin, plain: atPin, wantBy: "versioned"},
		{name: "versioned_wrong_version_falls_back", versioned: other, onPath: atPin, plain: atPin, wantBy: "path"},
		{name: "path_before_plain_gopath", onPath: atPin, plain: atPin, wantBy: "path"},
		{name: "plain_gopath_last_resort", plain: atPin, wantBy: "plain"},
		{name: "path_wrong_version_falls_back_to_plain", onPath: other, plain: atPin, wantBy: "plain"},
		{name: "no_candidate_is_named_red", wantRed: true, wantOut: []string{"not installed", "staticcheck@" + pin, "staticcheck-" + pin}},
		{name: "no_candidate_at_pin_is_named_red", versioned: other, onPath: other, wantRed: true, wantOut: []string{pin, "2025.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gopath, pathDir := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(gopath, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			fake := func(path, who, line string) {
				if line == "" {
					return
				}
				body := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo '%s'; exit 0; fi\necho %s\n", line, who)
				if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			fake(filepath.Join(gopath, "bin", "staticcheck-"+pin), "versioned", tc.versioned)
			fake(filepath.Join(pathDir, "staticcheck"), "path", tc.onPath)
			fake(filepath.Join(gopath, "bin", "staticcheck"), "plain", tc.plain)

			// PATH holds only the real go (via a link) plus the tools the
			// function uses, so no host staticcheck is reachable.
			bin := t.TempDir()
			for name, p := range map[string]string{"go": goBin} {
				if err := os.Symlink(p, filepath.Join(bin, name)); err != nil {
					t.Fatal(err)
				}
			}
			for _, tool := range []string{"awk", "sh", "echo"} {
				if p, err := exec.LookPath(tool); err == nil {
					if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
						t.Fatal(err)
					}
				}
			}
			// The function's `command -v staticcheck` must see only the case's
			// PATH fake, so that fake's directory is searched after bin.
			driver := fmt.Sprintf(". %q\nSTATICCHECK_VERSION=%s\nstaticcheck_pick || exit 7\n\"$sc\" -tests=false ./...\n", script, pin)
			cmd := exec.Command("bash", "-c", driver)
			cmd.Env = []string{
				"PATH=" + bin + ":" + pathDir,
				"HOME=" + telemetryOffHome(t),
				"GOPATH=" + gopath,
				"GOFLAGS=",
				"GOTOOLCHAIN=local",
				"GOROOT=" + goEnv(t, goBin, "GOROOT"),
				"GOCACHE=" + t.TempDir(),
				"GOWORK=off",
			}
			outB, err := cmd.CombinedOutput()
			out := string(outB)
			if tc.wantRed {
				if err == nil {
					t.Fatalf("picked a binary, want a red:\n%s", out)
				}
				for _, w := range tc.wantOut {
					if !strings.Contains(out, w) {
						t.Errorf("output lacks %q:\n%s", w, out)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("pick failed: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(out); got != tc.wantBy {
				t.Errorf("linted by %q, want %q", got, tc.wantBy)
			}
		})
	}
}

// checkStaticcheckCIWiring pins the call site, which the order test never sees
// because it sources the picker directly: hack/ci.sh must source the picker and
// call staticcheck_pick followed by `|| exit 1`, so a red pick stops the gate.
func checkStaticcheckCIWiring(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "ci.sh"))
	if err != nil {
		t.Fatalf("read ci.sh: %v", err)
	}
	ci := string(raw)
	if !regexp.MustCompile(`(?m)^\s*(source|\.)\s+hack/staticcheck-pick\.sh\s*$`).MatchString(ci) {
		t.Errorf("ci.sh does not source hack/staticcheck-pick.sh")
	}
	if !regexp.MustCompile(`(?m)^\s*staticcheck_pick\s*\|\|\s*exit 1\s*$`).MatchString(ci) {
		t.Errorf("ci.sh does not call staticcheck_pick followed by || exit 1")
	}
}

func goEnv(t *testing.T, goBin, key string) string {
	t.Helper()
	out, err := exec.Command(goBin, "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}

// telemetryOffHome returns a temp HOME whose Go telemetry mode is off, for a
// child that runs go. In the default local mode every go invocation under a
// fresh HOME starts a telemetry sidecar in its own session (setsid, so the test
// cannot wait for it) that keeps writing under HOME/Library/Application
// Support/go after go exits, and t.TempDir cleanup then races it ("directory
// not empty"). GOTELEMETRY is read-only in the environment; the mode file is the
// switch, and with it off go opens no counter file and starts no sidecar.
func telemetryOffHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Application Support", "go", "telemetry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Registered after t.TempDir, so it runs before the removal: anything
		// beside the mode file means go ignored it and a late writer may exist.
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("read telemetry dir: %v", err)
			return
		}
		for _, e := range ents {
			if e.Name() != "mode" {
				t.Errorf("go wrote telemetry %s despite mode off", e.Name())
			}
		}
	})
	return home
}
