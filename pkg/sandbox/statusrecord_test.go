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

// TestExtraPathsRefuseStatusRecord pins the node's status record directory
// (<WorkDir>/status, /var/lib/k3sm/status on an installed node) into the
// protected deny-set. The status report reads the node-local budget record
// there as evidence, so a pod able to write it could forge that record.
//
// The paths are literals, not built from StatusSubdir, so dropping the entry
// from the deny-set fails here rather than moving with it.
//
// "Refused" means two things, matching how every other protected tree is held:
// a path AT or UNDER the directory is rejected by validation (ErrProtectedPath),
// and a path ABOVE it (the work-dir itself) is permitted by validation, as it is
// for every other tree, but the profile re-denies the status directory, in both
// firmlink forms, after that ancestor allow, so the last match is the deny.
func TestExtraPathsRefuseStatusRecord(t *testing.T) {
	const (
		dataVol   = "/var/lib/k3sm/pods/p1/rootfs"
		statusDir = "/var/lib/k3sm/status"
		workDir   = "/var/lib/k3sm"
	)

	for _, p := range []string{statusDir, statusDir + "/budget.json", statusDir + "/sub/dir"} {
		for name, build := range map[string]func(string) (*runtimev1.SandboxProfile, GenerateOptions){
			"extra-write": func(p string) (*runtimev1.SandboxProfile, GenerateOptions) {
				return &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraWritePaths: []string{p}}, GenerateOptions{}
			},
			"pv-write": func(p string) (*runtimev1.SandboxProfile, GenerateOptions) {
				return &runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{WritePaths: []string{p}}
			},
			"extra-read": func(p string) (*runtimev1.SandboxProfile, GenerateOptions) {
				return &runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{p}}, GenerateOptions{}
			},
		} {
			t.Run("refused/"+name+"/"+p, func(t *testing.T) {
				sp, opts := build(p)
				if _, err := Generate(sp, opts); !errors.Is(err, ErrProtectedPath) {
					t.Errorf("Generate with %s %q: err = %v, want ErrProtectedPath", name, p, err)
				}
			})
		}
	}

	t.Run("validate-seam", func(t *testing.T) {
		_, _, protected, err := resolvePosture(Posture{})
		if err != nil {
			t.Fatalf("resolvePosture: %v", err)
		}
		if err := validateExtraPaths(dataVol, protected, []string{statusDir}); !errors.Is(err, ErrProtectedPath) {
			t.Errorf("validateExtraPaths(%q) = %v, want ErrProtectedPath", statusDir, err)
		}
	})

	t.Run("ancestor allow is overridden by the status deny", func(t *testing.T) {
		out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraWritePaths: []string{workDir}}, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate with the work-dir as an extra write path: %v", err)
		}
		iAllow := strings.Index(out, "(allow file-write*\n  (subpath \""+workDir+"\")")
		if iAllow < 0 {
			t.Fatalf("expected the ancestor work-dir write allow in the profile:\n%s", out)
		}
		for _, form := range []string{statusDir, "/private" + statusDir} {
			i := strings.LastIndex(out, "(subpath \""+form+"\")")
			if i < 0 {
				t.Errorf("status directory form %q is not denied:\n%s", form, out)
				continue
			}
			if i <= iAllow {
				t.Errorf("status deny %q (%d) must come after the ancestor allow (%d)", form, i, iAllow)
			}
		}
	})

	for _, p := range []string{"/var/lib/k3sm/storage/prod/pgdata", "/var/lib/k3sm/statusx", "/var/lib/k3sm/status-old/x"} {
		t.Run("unrelated passes/"+p, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{WritePaths: []string{p}})
			if err != nil {
				t.Fatalf("Generate with unrelated write path %q: %v", p, err)
			}
			if !strings.Contains(out, "(allow file-write*\n  (subpath \""+p+"\")") {
				t.Errorf("unrelated path %q lost its write allow:\n%s", p, out)
			}
		})
	}
}

// TestStatusRecordDeniedUnderACustomPodRoot pins the deny to where the record
// really is. On a node started with a non-default pod root the record lives at
// the data root, outside <WorkDir>, and the <WorkDir>/status deny lands on a
// directory nothing writes. The status directory is reached here through a write
// allow on its parent, because default-deny alone would refuse the write and
// prove nothing about the deny.
func TestStatusRecordDeniedUnderACustomPodRoot(t *testing.T) {
	const (
		workDir   = "/opt/k3sm-pods"
		dataRoot  = "/opt/k3sm-data"
		statusDir = dataRoot + "/status"
		dataVol   = workDir + "/pods/p1/rootfs"
	)
	posture := Posture{WorkDir: workDir, StatusRecordDir: statusDir}
	sp := func() *runtimev1.SandboxProfile { return &runtimev1.SandboxProfile{DataVolumePath: dataVol} }

	t.Run("the deny follows both allows and keeps the work-dir deny", func(t *testing.T) {
		s := sp()
		s.ExtraWritePaths = []string{dataRoot}
		out, err := Generate(s, GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		iAllow := strings.Index(out, "(allow file-write*\n  (subpath \""+dataRoot+"\")")
		if iAllow < 0 {
			t.Fatalf("expected the ancestor write allow in the profile:\n%s", out)
		}
		for _, denied := range []string{statusDir, workDir + "/status"} {
			if i := strings.LastIndex(out, "(subpath \""+denied+"\")"); i <= iAllow {
				t.Errorf("deny of %q at %d must come after the ancestor allow at %d:\n%s", denied, i, iAllow, out)
			}
		}
	})

	t.Run("a firmlinked record dir is denied in both forms", func(t *testing.T) {
		const firmlinked = "/var/k3sm-data/status"
		out, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir, StatusRecordDir: firmlinked}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		for _, form := range []string{firmlinked, "/private" + firmlinked} {
			if !strings.Contains(out, "(subpath \""+form+"\")") {
				t.Errorf("form %q is not denied:\n%s", form, out)
			}
		}
	})

	for _, p := range []string{statusDir, statusDir + "/budget.json"} {
		t.Run("caller paths are refused/"+p, func(t *testing.T) {
			if _, err := Generate(sp(), GenerateOptions{Posture: posture, WritePaths: []string{p}}); !errors.Is(err, ErrProtectedPath) {
				t.Errorf("Generate with write path %q: err = %v, want ErrProtectedPath", p, err)
			}
		})
	}

	t.Run("empty keeps the work-dir deny and renders the same as the work-dir value", func(t *testing.T) {
		unset, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir}})
		if err != nil {
			t.Fatalf("Generate unset: %v", err)
		}
		if !strings.Contains(unset, "(subpath \""+workDir+"/status\")") {
			t.Errorf("empty field lost the work-dir deny:\n%s", unset)
		}
		same, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir, StatusRecordDir: workDir + "/status"}})
		if err != nil {
			t.Fatalf("Generate same: %v", err)
		}
		if same != unset {
			t.Errorf("the work-dir value changed the profile, which would drift a re-attached pod:\n--- unset ---\n%s\n--- same ---\n%s", unset, same)
		}
	})

	// The rendered text above is what a reader can check; this is the kernel's
	// verdict on it, through the libsandbox the runtime uses.
	for name, leaf := range map[string]string{
		"plain":               "data",
		"space and non-ascii": "data root \u00e9",
	} {
		t.Run("enforced/"+name, func(t *testing.T) {
			if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
				t.Skip("sandbox-exec not present")
			}
			base, err := os.MkdirTemp("/tmp", "k3sm-sr-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(base) })

			pods, data := filepath.Join(base, "pods-root"), filepath.Join(base, leaf)
			status := filepath.Join(data, "status")
			record := filepath.Join(status, "budget.json")
			if err := os.MkdirAll(status, 0o755); err != nil {
				t.Fatal(err)
			}
			const original = "evidence\n"
			if err := os.WriteFile(record, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			prof, err := Generate(&runtimev1.SandboxProfile{
				DataVolumePath:  filepath.Join(pods, "pods", "p1", "rootfs"),
				ExtraWritePaths: []string{data},
			}, GenerateOptions{Posture: Posture{WorkDir: pods, StatusRecordDir: status}})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			sb := filepath.Join(t.TempDir(), "status.sb")
			if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
				t.Fatal(err)
			}
			write := func(target string) ([]byte, error) {
				return exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/sh", "-c", `printf forged > "$1"`, "sh", target).CombinedOutput()
			}

			// The control: the same grant does reach the record's sibling, so a
			// refusal below is the deny and not the default.
			sibling := filepath.Join(data, "sibling")
			if out, err := write(sibling); err != nil {
				t.Fatalf("the ancestor grant did not reach %s, so the deny is unproven: %v\n%s\n--- profile ---\n%s", sibling, err, out, prof)
			}
			for _, target := range []string{record, "/private" + record, filepath.Join(status, "new.json")} {
				if out, err := write(target); err == nil {
					t.Errorf("write to %s succeeded under the generated profile: %s\n--- profile ---\n%s", target, out, prof)
				}
			}
			if got, err := os.ReadFile(record); err != nil || string(got) != original {
				t.Errorf("record after the attempts = %q, %v; want %q", got, err, original)
			}
			if _, err := os.Stat(filepath.Join(status, "new.json")); err == nil {
				t.Errorf("a new file landed in the status directory")
			}
		})
	}
}

// TestStatusRecordDirRefusesWhatCannotHoldTheDeny pins the fail-closed half: a
// value the deny could not honestly be written from fails the whole profile
// rather than dropping the deny, and the startup check gives the same answer.
func TestStatusRecordDirRefusesWhatCannotHoldTheDeny(t *testing.T) {
	const workDir = "/opt/k3sm-pods"
	generate := func(dir string) (string, error) {
		return Generate(&runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"},
			GenerateOptions{Posture: Posture{WorkDir: workDir, StatusRecordDir: dir}})
	}
	for name, dir := range map[string]string{
		"relative":            "data/status",
		"dot relative":        "./status",
		"filesystem root":     "/",
		"trailing slash":      "/opt/data/status/",
		"doubled separator":   "/opt//data/status",
		"parent segment":      "/opt/x/../status",
		"double quote":        `/opt/da"ta/status`,
		"sbpl breakout":       `/opt/x")) (allow file-write* (subpath "/`,
		"backslash":           `/opt/da\ta/status`,
		"newline":             "/opt/da\nta/status",
		"tab":                 "/opt/da\tta/status",
		"nul":                 "/opt/da\x00ta/status",
		"del":                 "/opt/da\x7fta/status",
		"invalid utf-8":       "/opt/da\xffta/status",
		"non-printable rune":  "/opt/da\u200bta/status",
		"the pods root":       workDir + "/pods",
		"under the pods root": workDir + "/pods/status",
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := generate(dir); !errors.Is(err, ErrInvalidStatusRecordDir) {
				t.Errorf("Generate(%q) err = %v, want ErrInvalidStatusRecordDir; profile:\n%s", dir, err, out)
			} else if out != "" {
				t.Errorf("Generate(%q) returned a profile beside its error:\n%s", dir, out)
			}
			if err := ValidateStatusRecordDir(dir, workDir); !errors.Is(err, ErrInvalidStatusRecordDir) {
				t.Errorf("ValidateStatusRecordDir(%q) = %v, want ErrInvalidStatusRecordDir", dir, err)
			}
		})
	}

	for name, dir := range map[string]string{
		"empty":             "",
		"plain":             "/opt/data/status",
		"space and parens":  "/opt/data (1)/status",
		"printable unicode": "/opt/data \u00e9/status",
		"private form":      "/private/var/data/status",
		"sibling of pods":   workDir + "/podsx/status",
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := generate(dir); err != nil {
				t.Errorf("Generate(%q): %v", dir, err)
			}
			if err := ValidateStatusRecordDir(dir, workDir); err != nil {
				t.Errorf("ValidateStatusRecordDir(%q): %v", dir, err)
			}
		})
	}
}
