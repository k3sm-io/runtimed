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

// TestDataRootSecretsDeniedUnderACustomPodRoot pins the denies to where the
// control-plane state really is. On a node started with a non-default pod root the
// CA keys, the kine database and the node password stay at the data root, outside
// <WorkDir>, and the <WorkDir>/server and <WorkDir>/agent denies land on directories
// nothing writes. Default-deny alone would refuse a pod and prove nothing about the
// denies, so the enforced cases reach those directories through an allow on their
// parent, the shape a manual --work-dir or an admin's PV above the data root takes.
//
// The directory names are literals, not built from ServerSubdir and AgentSubdir, so
// dropping one from the list fails here rather than moving with it.
func TestDataRootSecretsDeniedUnderACustomPodRoot(t *testing.T) {
	const (
		workDir  = "/opt/k3sm-pods"
		dataRoot = "/opt/k3sm-data"
		dataVol  = workDir + "/pods/p1/rootfs"
	)
	posture := Posture{WorkDir: workDir, DataRoot: dataRoot}
	sp := func() *runtimev1.SandboxProfile { return &runtimev1.SandboxProfile{DataVolumePath: dataVol} }
	secretDirs := []string{"server", "agent"}

	for _, sub := range secretDirs {
		t.Run("the deny follows both allows and keeps the work-dir deny/"+sub, func(t *testing.T) {
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
			for _, denied := range []string{dataRoot + "/" + sub, workDir + "/" + sub} {
				if i := strings.LastIndex(out, "(subpath \""+denied+"\")"); i <= iAllow {
					t.Errorf("deny of %q at %d must come after the ancestor allow at %d:\n%s", denied, i, iAllow, out)
				}
			}
		})

		t.Run("a firmlinked data root is denied in both forms/"+sub, func(t *testing.T) {
			const firmlinked = "/var/k3sm-data"
			out, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: firmlinked}})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			for _, form := range []string{firmlinked + "/" + sub, "/private" + firmlinked + "/" + sub} {
				if !strings.Contains(out, "(subpath \""+form+"\")") {
					t.Errorf("form %q is not denied:\n%s", form, out)
				}
			}
		})

		for _, p := range []string{dataRoot + "/" + sub, dataRoot + "/" + sub + "/tls/ca.key"} {
			t.Run("caller paths are refused/"+p, func(t *testing.T) {
				for name, opts := range map[string]GenerateOptions{
					"read":  {Posture: posture, ReadPaths: []string{p}},
					"write": {Posture: posture, WritePaths: []string{p}},
				} {
					if _, err := Generate(sp(), opts); !errors.Is(err, ErrProtectedPath) {
						t.Errorf("Generate with %s path %q: err = %v, want ErrProtectedPath", name, p, err)
					}
				}
			})
		}
	}

	t.Run("the data root itself is not denied", func(t *testing.T) {
		out, err := Generate(sp(), GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if strings.Contains(out, "(subpath \""+dataRoot+"\")") {
			t.Errorf("the data root is denied whole, where only its children were named:\n%s", out)
		}
	})

	t.Run("empty and the work-dir value render the same profile", func(t *testing.T) {
		unset, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir}})
		if err != nil {
			t.Fatalf("Generate unset: %v", err)
		}
		for _, sub := range secretDirs {
			if !strings.Contains(unset, "(subpath \""+workDir+"/"+sub+"\")") {
				t.Errorf("empty field lost the work-dir deny of %q:\n%s", sub, unset)
			}
		}
		same, err := Generate(sp(), GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: workDir}})
		if err != nil {
			t.Fatalf("Generate same: %v", err)
		}
		if same != unset {
			t.Errorf("the work-dir value changed the profile, which would drift a re-attached pod:\n--- unset ---\n%s\n--- same ---\n%s", unset, same)
		}
	})

	t.Run("the default posture's own value renders the same profile", func(t *testing.T) {
		defaultVol := &runtimev1.SandboxProfile{DataVolumePath: DefaultWorkDir + "/pods/p1/rootfs"}
		unset, err := Generate(defaultVol, GenerateOptions{})
		if err != nil {
			t.Fatalf("Generate unset: %v", err)
		}
		same, err := Generate(defaultVol, GenerateOptions{Posture: Posture{DataRoot: DefaultWorkDir}})
		if err != nil {
			t.Fatalf("Generate same: %v", err)
		}
		if same != unset {
			t.Errorf("the default data root changed the default profile:\n--- unset ---\n%s\n--- same ---\n%s", unset, same)
		}
	})

	// The rendered text above is what a reader can check; this is the kernel's
	// verdict on it, through the libsandbox the runtime uses.
	for name, leaf := range map[string]string{
		"plain":               "data",
		"space and non-ascii": "data root \u00e9",
	} {
		for _, sub := range secretDirs {
			t.Run("enforced/"+name+"/"+sub, func(t *testing.T) {
				if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
					t.Skip("sandbox-exec not present")
				}
				base, err := os.MkdirTemp("/tmp", "k3sm-dr-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(base) })

				pods, data := filepath.Join(base, "pods-root"), filepath.Join(base, leaf)
				secrets := filepath.Join(data, sub)
				secret, sibling := filepath.Join(secrets, "ca.key"), filepath.Join(data, "sibling")
				if err := os.MkdirAll(secrets, 0o755); err != nil {
					t.Fatal(err)
				}
				const original = "private-key\n"
				for _, f := range []string{secret, sibling} {
					if err := os.WriteFile(f, []byte(original), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				run := func(posture Posture, script, target string) ([]byte, string, error) {
					t.Helper()
					prof, err := Generate(&runtimev1.SandboxProfile{
						DataVolumePath:  filepath.Join(pods, "pods", "p1", "rootfs"),
						ExtraReadPaths:  []string{data},
						ExtraWritePaths: []string{data},
					}, GenerateOptions{Posture: posture})
					if err != nil {
						t.Fatalf("Generate: %v", err)
					}
					sb := filepath.Join(t.TempDir(), "dataroot.sb")
					if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
						t.Fatal(err)
					}
					// Stdout alone: the shell's own startup noise goes to stderr and
					// would otherwise read as the file's content.
					out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/sh", "-c", script, "sh", target).Output()
					return out, prof, err
				}
				const (
					writeScript = `printf forged > "$1"`
					readScript  = `IFS= read -r line < "$1" && printf '%s' "$line"`
				)
				withRoot := Posture{WorkDir: pods, DataRoot: data}

				// The controls: the same grant reaches the secret's sibling with the
				// field set, and reaches the secret itself without it, so a refusal
				// below is these denies and not the default.
				if out, prof, err := run(withRoot, readScript, sibling); err != nil || string(out) != "private-key" {
					t.Fatalf("the ancestor grant did not read %s, so the deny is unproven: %v\n%s\n--- profile ---\n%s", sibling, err, out, prof)
				}
				if out, prof, err := run(withRoot, writeScript, sibling); err != nil {
					t.Fatalf("the ancestor grant did not write %s, so the deny is unproven: %v\n%s\n--- profile ---\n%s", sibling, err, out, prof)
				}
				if out, prof, err := run(Posture{WorkDir: pods}, readScript, secret); err != nil || string(out) != "private-key" {
					t.Fatalf("without the field the secret was not readable, so this case proves nothing about it: %v\n%s\n--- profile ---\n%s", err, out, prof)
				}

				for _, target := range []string{secret, "/private" + secret} {
					if out, prof, err := run(withRoot, readScript, target); err == nil || strings.Contains(string(out), "private-key") {
						t.Errorf("read of %s succeeded under the generated profile: %q\n--- profile ---\n%s", target, out, prof)
					}
				}
				newFile := filepath.Join(secrets, "new.key")
				for _, target := range []string{secret, "/private" + secret, newFile} {
					if out, prof, err := run(withRoot, writeScript, target); err == nil {
						t.Errorf("write to %s succeeded under the generated profile: %s\n--- profile ---\n%s", target, out, prof)
					}
				}
				if got, err := os.ReadFile(secret); err != nil || string(got) != original {
					t.Errorf("secret after the attempts = %q, %v; want %q", got, err, original)
				}
				if _, err := os.Stat(newFile); err == nil {
					t.Errorf("a new file landed in %s", secrets)
				}
			})
		}
	}
}

// TestDataRootRefusesWhatCannotHoldTheDeny pins the fail-closed half: a value the
// denies could not honestly be written from fails the whole profile rather than
// dropping them, and the startup check gives the same answer.
func TestDataRootRefusesWhatCannotHoldTheDeny(t *testing.T) {
	const workDir = "/opt/k3sm-pods"
	generate := func(workDir, dir string) (string, error) {
		return Generate(&runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"},
			GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: dir}})
	}
	for name, tc := range map[string]struct{ workDir, dir string }{
		"relative":                   {workDir, "data"},
		"dot relative":               {workDir, "./data"},
		"filesystem root":            {workDir, "/"},
		"trailing slash":             {workDir, "/opt/data/"},
		"doubled separator":          {workDir, "/opt//data"},
		"parent segment":             {workDir, "/opt/x/../data"},
		"double quote":               {workDir, `/opt/da"ta`},
		"sbpl breakout":              {workDir, `/opt/x")) (allow file-write* (subpath "/`},
		"backslash":                  {workDir, `/opt/da\ta`},
		"newline":                    {workDir, "/opt/da\nta"},
		"nul":                        {workDir, "/opt/da\x00ta"},
		"invalid utf-8":              {workDir, "/opt/da\xffta"},
		"non-printable rune":         {workDir, "/opt/da\u200bta"},
		"the pods root":              {workDir, workDir + "/pods"},
		"under the pods root":        {workDir, workDir + "/pods/data"},
		"work-dir is the server dir": {"/opt/data/server", "/opt/data"},
		"work-dir is under server":   {"/opt/data/server/pods-root", "/opt/data"},
		"work-dir is the agent dir":  {"/opt/data/agent", "/opt/data"},
		"work-dir is under agent":    {"/opt/data/agent/pods-root", "/opt/data"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := generate(tc.workDir, tc.dir); !errors.Is(err, ErrInvalidDataRoot) {
				t.Errorf("Generate(%q) err = %v, want ErrInvalidDataRoot; profile:\n%s", tc.dir, err, out)
			} else if out != "" {
				t.Errorf("Generate(%q) returned a profile beside its error:\n%s", tc.dir, out)
			}
			if err := ValidateDataRoot(tc.dir, tc.workDir); !errors.Is(err, ErrInvalidDataRoot) {
				t.Errorf("ValidateDataRoot(%q) = %v, want ErrInvalidDataRoot", tc.dir, err)
			}
		})
	}

	for name, dir := range map[string]string{
		"empty":             "",
		"plain":             "/opt/data",
		"space and parens":  "/opt/data (1)",
		"printable unicode": "/opt/data \u00e9",
		"private form":      "/private/var/data",
		"sibling of pods":   workDir + "/podsx",
		"above the workdir": "/opt",
		"the workdir":       workDir,
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := generate(workDir, dir); err != nil {
				t.Errorf("Generate(%q): %v", dir, err)
			}
			if err := ValidateDataRoot(dir, workDir); err != nil {
				t.Errorf("ValidateDataRoot(%q): %v", dir, err)
			}
		})
	}
}
