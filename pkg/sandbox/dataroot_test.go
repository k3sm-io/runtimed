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
		// Both bounds compare every firmlink spelling, and case-insensitively.
		"private spelling under a var pods root": {"/var/lib/k3sm", "/private/var/lib/k3sm/pods/data"},
		"var spelling under a private pods root": {"/private/var/lib/k3sm", "/var/lib/k3sm/pods/data"},
		"var work-dir in the private server dir": {"/var/data/server/pods-root", "/private/var/data"},
		"private work-dir in the var agent dir":  {"/private/var/data/agent", "/var/data"},
		"other case under the pods root":         {workDir, "/opt/k3sm-pods/Pods/data"},
		"work-dir in the other-case server dir":  {"/opt/data/SERVER/pods-root", "/opt/data"},
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

// TestStateDirDeniedUnderACustomLeaf pins the deny to the role's real state dir.
// The DataRoot denies name only <data root>/server and <data root>/agent, so a
// --work-dir with another leaf, <data root>/cp, kept its CA keys, kine database
// and node password outside every deny. Each row lists the trees that must be
// denied exactly once per firmlink form, and the profile must otherwise match the
// one rendered without the field plus those lines.
//
// The paths are literals, not built from ServerSubdir and AgentSubdir, so a
// dropped or renamed leaf fails here rather than moving with it.
func TestStateDirDeniedUnderACustomLeaf(t *testing.T) {
	const (
		workDir  = "/opt/k3sm-pods"
		dataRoot = "/opt/k3sm-data"
	)
	sp := func() *runtimev1.SandboxProfile {
		return &runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"}
	}
	render := func(t *testing.T, p Posture) string {
		t.Helper()
		out, err := Generate(sp(), GenerateOptions{Posture: p})
		if err != nil {
			t.Fatalf("Generate(%+v): %v", p, err)
		}
		return out
	}
	for name, tc := range map[string]struct {
		dataRoot, stateDir string
		// once lists every subpath form that must appear exactly once.
		once []string
		// sameAsUnset is set when the field must not change the profile at all.
		sameAsUnset bool
	}{
		"custom leaf under the data root": {
			dataRoot: dataRoot, stateDir: dataRoot + "/cp",
			once: []string{dataRoot + "/cp", dataRoot + "/server", dataRoot + "/agent"},
		},
		"custom leaf under a firmlinked data root": {
			dataRoot: "/var/k3sm-data", stateDir: "/var/k3sm-data/cp",
			once: []string{"/var/k3sm-data/cp", "/private/var/k3sm-data/cp"},
		},
		"default server leaf adds no duplicate": {
			dataRoot: dataRoot, stateDir: dataRoot + "/server",
			once: []string{dataRoot + "/server", dataRoot + "/agent"}, sameAsUnset: true,
		},
		"default agent leaf adds no duplicate": {
			dataRoot: dataRoot, stateDir: dataRoot + "/agent",
			once: []string{dataRoot + "/server", dataRoot + "/agent"}, sameAsUnset: true,
		},
		"default leaf under the work-dir data root adds no duplicate": {
			dataRoot: workDir, stateDir: workDir + "/server",
			once: []string{workDir + "/server", workDir + "/agent"}, sameAsUnset: true,
		},
		"private form of a denied leaf adds no duplicate": {
			dataRoot: "/var/k3sm-data", stateDir: "/private/var/k3sm-data/agent",
			once: []string{"/var/k3sm-data/agent", "/private/var/k3sm-data/agent"}, sameAsUnset: true,
		},
		"default leaf without a data root is still denied": {
			stateDir: dataRoot + "/server",
			once:     []string{dataRoot + "/server"},
		},
		"state dir outside the data root is its own tree": {
			dataRoot: dataRoot, stateDir: "/srv/k3sm-state",
			once: []string{"/srv/k3sm-state", dataRoot + "/server", dataRoot + "/agent"},
		},
		"empty keeps the data root profile": {
			dataRoot: dataRoot,
			once:     []string{dataRoot + "/server", dataRoot + "/agent"}, sameAsUnset: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			unset := render(t, Posture{WorkDir: workDir, DataRoot: tc.dataRoot})
			out := render(t, Posture{WorkDir: workDir, DataRoot: tc.dataRoot, StateDir: tc.stateDir})
			for _, form := range tc.once {
				if n := strings.Count(out, "(subpath \""+form+"\")\n"); n != 1 {
					t.Errorf("subpath %q appears %d times, want 1:\n%s", form, n, out)
				}
			}
			if tc.sameAsUnset && out != unset {
				t.Errorf("the state dir changed the profile, which would drift a re-attached pod:\n--- unset ---\n%s\n--- set ---\n%s", unset, out)
			}
			if !tc.sameAsUnset {
				// The only difference is the state dir's own deny lines.
				var extra strings.Builder
				writeFirmlinkSubpaths(&extra, []string{tc.stateDir})
				if got := strings.Replace(out, extra.String(), "", 1); got != unset {
					t.Errorf("the state dir changed more than its own deny:\n--- unset ---\n%s\n--- set ---\n%s", unset, out)
				}
			}
			for _, p := range []string{tc.stateDir, tc.stateDir + "/tls/server-ca.key"} {
				if tc.stateDir == "" {
					continue
				}
				opts := GenerateOptions{
					Posture:   Posture{WorkDir: workDir, DataRoot: tc.dataRoot, StateDir: tc.stateDir},
					ReadPaths: []string{p},
				}
				if _, err := Generate(sp(), opts); !errors.Is(err, ErrProtectedPath) {
					t.Errorf("Generate with read path %q: err = %v, want ErrProtectedPath", p, err)
				}
			}
		})
	}

	t.Run("DataRootDenyTrees is the rendered list", func(t *testing.T) {
		for name, tc := range map[string]struct {
			dataRoot, stateDir string
			want               []string
		}{
			"custom leaf":   {dataRoot, dataRoot + "/cp", []string{dataRoot + "/server", dataRoot + "/agent", dataRoot + "/cp"}},
			"server leaf":   {dataRoot, dataRoot + "/server", []string{dataRoot + "/server", dataRoot + "/agent"}},
			"agent leaf":    {dataRoot, dataRoot + "/agent", []string{dataRoot + "/server", dataRoot + "/agent"}},
			"outside":       {dataRoot, "/srv/state", []string{dataRoot + "/server", dataRoot + "/agent", "/srv/state"}},
			"no data root":  {"", "/srv/state", []string{"/srv/state"}},
			"empty":         {dataRoot, "", []string{dataRoot + "/server", dataRoot + "/agent"}},
			"both empty":    {"", "", nil},
			"private alias": {"/var/d", "/private/var/d/server", []string{"/var/d/server", "/var/d/agent", "/private/var/d/server"}},
		} {
			t.Run(name, func(t *testing.T) {
				got := DataRootDenyTrees(tc.dataRoot, tc.stateDir)
				if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
					t.Errorf("DataRootDenyTrees(%q, %q) = %q, want %q", tc.dataRoot, tc.stateDir, got, tc.want)
				}
			})
		}
	})
}

// TestStateDirRefusesWhatCannotHoldTheDeny pins the fail-closed half: a state
// dir the deny could not honestly be written from, a non-canonical spelling
// included, fails the whole profile, exactly as a data root does, and the startup
// check gives the same answer.
func TestStateDirRefusesWhatCannotHoldTheDeny(t *testing.T) {
	const workDir = "/opt/k3sm-pods"
	generate := func(workDir, dir string) (string, error) {
		return Generate(&runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"},
			GenerateOptions{Posture: Posture{WorkDir: workDir, DataRoot: "/opt/k3sm-data", StateDir: dir}})
	}
	for name, tc := range map[string]struct{ workDir, dir string }{
		"relative":                 {workDir, "cp"},
		"parent segment":           {workDir, "/opt/k3sm-data/x/../cp"},
		"parent segment to leaf":   {workDir, "/opt/k3sm-data/cp/.."},
		"trailing slash":           {workDir, "/opt/k3sm-data/cp/"},
		"doubled separator":        {workDir, "/opt/k3sm-data//cp"},
		"filesystem root":          {workDir, "/"},
		"sbpl breakout":            {workDir, `/opt/x")) (allow file-write* (subpath "/`},
		"newline":                  {workDir, "/opt/c\np"},
		"the pods root":            {workDir, workDir + "/pods"},
		"under the pods root":      {workDir, workDir + "/pods/cp"},
		"the work-dir":             {workDir, workDir},
		"above the work-dir":       {workDir, "/opt"},
		"work-dir under state dir": {"/opt/k3sm-data/cp/pods-root", "/opt/k3sm-data/cp"},
		// The pods root is compared in both firmlink spellings: the k3sm caller
		// hands over a resolved /private path while the runtime's work-dir is
		// often the /var one, and each names the same directory.
		"private ancestor of a var pods root":     {"/var/lib/k3sm", "/private/var/lib"},
		"private spelling of a var work-dir":      {"/var/lib/k3sm", "/private/var/lib/k3sm"},
		"bare private above a var pods root":      {"/var/lib/k3sm", "/private"},
		"private spelling under a var pods root":  {"/var/lib/k3sm", "/private/var/lib/k3sm/pods/cp"},
		"var ancestor of a private pods root":     {"/private/var/lib/k3sm", "/var/lib"},
		"var spelling of a private work-dir":      {"/private/var/lib/k3sm", "/var/lib/k3sm"},
		"var spelling under a private pods root":  {"/private/var/lib/k3sm", "/var/lib/k3sm/pods/cp"},
		"tmp ancestor of a private tmp pods root": {"/private/tmp/k3sm", "/tmp"},
		"private tmp ancestor of a tmp pods root": {"/tmp/k3sm", "/private/tmp"},
		// The artifact view allows are emitted after the protected deny, so a
		// state dir at, under or above <WorkDir>/artifacts would be re-opened by
		// a pod's view grant.
		"the artifacts root":                       {workDir, workDir + "/artifacts"},
		"under the artifacts root":                 {workDir, workDir + "/artifacts/cp"},
		"an artifact view":                         {workDir, workDir + "/artifacts/" + strings.Repeat("a", 64) + "/" + strings.Repeat("b", 64)},
		"above the artifacts root":                 {"/opt/k3sm-data/cp/root", "/opt/k3sm-data/cp"},
		"private artifacts root of a var work-dir": {"/var/lib/k3sm", "/private/var/lib/k3sm/artifacts"},
		"var view under a private work-dir":        {"/private/var/lib/k3sm", "/var/lib/k3sm/artifacts/cp"},
		// The default volume is case-insensitive and so is the kernel's match, so
		// a spelling that differs only by case is the same directory.
		"other case of the work-dir":          {workDir, "/OPT/K3SM-PODS"},
		"other case of the pods root":         {workDir, "/opt/k3sm-pods/PODS"},
		"other case under the pods root":      {workDir, "/opt/K3sm-Pods/pods/cp"},
		"other case of the artifacts root":    {workDir, "/opt/k3sm-pods/Artifacts"},
		"other case under the artifacts root": {workDir, "/OPT/k3sm-pods/ARTIFACTS/cp"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := generate(tc.workDir, tc.dir); !errors.Is(err, ErrInvalidStateDir) {
				t.Errorf("Generate(%q) err = %v, want ErrInvalidStateDir; profile:\n%s", tc.dir, err, out)
			} else if out != "" {
				t.Errorf("Generate(%q) returned a profile beside its error:\n%s", tc.dir, out)
			}
			if err := ValidateStateDir(tc.dir, tc.workDir); !errors.Is(err, ErrInvalidStateDir) {
				t.Errorf("ValidateStateDir(%q) = %v, want ErrInvalidStateDir", tc.dir, err)
			}
		})
	}
	for name, dir := range map[string]string{
		"empty":             "",
		"custom leaf":       "/opt/k3sm-data/cp",
		"default leaf":      "/opt/k3sm-data/server",
		"outside":           "/srv/k3sm-state",
		"sibling of pods":   workDir + "/podsx",
		"private form":      "/private/var/k3sm-data/cp",
		"artifacts sibling": workDir + "/artifactsx",
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := generate(workDir, dir); err != nil {
				t.Errorf("Generate(%q): %v", dir, err)
			}
			if err := ValidateStateDir(dir, workDir); err != nil {
				t.Errorf("ValidateStateDir(%q): %v", dir, err)
			}
		})
	}
	for name, tc := range map[string]struct{ workDir, dir string }{
		"private sibling leaf of a var work-dir": {"/var/lib/k3sm", "/private/var/lib/k3sm-cp"},
		"var sibling leaf of a private work-dir": {"/private/var/lib/k3sm", "/var/lib/k3sm-cp"},
		"private data root leaf beside var pods": {"/var/lib/k3sm/pods-root", "/private/var/lib/k3sm/cp"},
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := generate(tc.workDir, tc.dir); err != nil {
				t.Errorf("Generate(%q): %v", tc.dir, err)
			}
			if err := ValidateStateDir(tc.dir, tc.workDir); err != nil {
				t.Errorf("ValidateStateDir(%q): %v", tc.dir, err)
			}
		})
	}
}

// TestProtectedPathsMatchEverySpelling pins validateExtraPaths to the directory
// rather than the bytes: a caller-supplied allow spelled in the other firmlink
// form, or in another case, still names a protected tree on the default volume,
// and the post-deny allows (the credential read-only scope above all) would
// re-open it. Every group a caller can fill is checked.
func TestProtectedPathsMatchEverySpelling(t *testing.T) {
	const workDir = "/opt/k3sm-pods"
	for name, tc := range map[string]struct {
		dataRoot, stateDir, path string
	}{
		"private spelling under a var state dir":   {"/var/k3sm-data", "/var/k3sm-data/cp", "/private/var/k3sm-data/cp/tls/server-ca.key"},
		"var spelling under a private state dir":   {"/private/var/k3sm-data", "/private/var/k3sm-data/cp", "/var/k3sm-data/cp/tls/server-ca.key"},
		"var spelling of a private state dir":      {"/private/var/k3sm-data", "/private/var/k3sm-data/cp", "/var/k3sm-data/cp"},
		"other case under the state dir":           {"/opt/k3sm-data", "/opt/k3sm-data/cp", "/opt/k3sm-data/CP/tls/server-ca.key"},
		"other case under a data root child":       {"/opt/k3sm-data", "", "/opt/K3SM-DATA/server/tls/server-ca.key"},
		"other case under the pods root":           {"", "", "/opt/k3sm-pods/PODS/p2/rootfs"},
		"var spelling under the private db prefix": {"", "", "/var/db/sudo"},
		"other case under the user homes":          {"", "", "/users/alice/.ssh/id_ed25519"},
	} {
		t.Run(name, func(t *testing.T) {
			posture := Posture{WorkDir: workDir, DataRoot: tc.dataRoot, StateDir: tc.stateDir}
			for group, opts := range map[string]GenerateOptions{
				"read-only": {Posture: posture, ReadOnlyPaths: []string{tc.path}},
				"write":     {Posture: posture, WritePaths: []string{tc.path}},
				"read":      {Posture: posture, ReadPaths: []string{tc.path}},
			} {
				sp := &runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"}
				if _, err := Generate(sp, opts); !errors.Is(err, ErrProtectedPath) {
					t.Errorf("Generate with %s path %q: err = %v, want ErrProtectedPath", group, tc.path, err)
				}
			}
			for group, sp := range map[string]*runtimev1.SandboxProfile{
				"extra read":  {DataVolumePath: workDir + "/pods/p1/rootfs", ExtraReadPaths: []string{tc.path}},
				"extra write": {DataVolumePath: workDir + "/pods/p1/rootfs", ExtraWritePaths: []string{tc.path}},
			} {
				if _, err := Generate(sp, GenerateOptions{Posture: posture}); !errors.Is(err, ErrProtectedPath) {
					t.Errorf("Generate with %s path %q: err = %v, want ErrProtectedPath", group, tc.path, err)
				}
			}
		})
	}
	// A path beside a protected tree whose name only extends it is not under it,
	// in either case: the fold respects the segment boundary.
	for name, path := range map[string]string{
		"sibling of the state dir":    "/opt/k3sm-data/cpx/file",
		"other-case sibling":          "/opt/k3sm-data/CPX/file",
		"sibling of the users prefix": "/UsersX/file",
		"the pod's own data volume":   workDir + "/pods/p1/rootfs/secret",
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			sp := &runtimev1.SandboxProfile{DataVolumePath: workDir + "/pods/p1/rootfs"}
			opts := GenerateOptions{
				Posture:       Posture{WorkDir: workDir, DataRoot: "/opt/k3sm-data", StateDir: "/opt/k3sm-data/cp"},
				ReadOnlyPaths: []string{path},
			}
			if _, err := Generate(sp, opts); err != nil {
				t.Errorf("Generate with read-only path %q: %v", path, err)
			}
		})
	}
}

// stateDirTree is a temp work-dir layout for the enforced state-dir cases: a
// pods root and a data root side by side, the role's state dir at
// <data>/<leaf> holding a secret, and a sibling file beside it that the ancestor
// grant on <data> reaches.
type stateDirTree struct {
	pods, data, stateDir, secret, sibling string
}

const stateDirSecret = "private-key\n"

// newStateDirTree builds a stateDirTree under a fresh directory in tmp, spelled
// with its /private prefix when private is set, and removes it at cleanup.
func newStateDirTree(t *testing.T, tmp string, private bool, leaf string) stateDirTree {
	t.Helper()
	base, err := os.MkdirTemp(tmp, "k3sm-sd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if private {
		base = "/private" + base
	}
	tr := stateDirTree{pods: filepath.Join(base, "pods-root"), data: filepath.Join(base, "data")}
	tr.stateDir = filepath.Join(tr.data, leaf)
	tr.secret, tr.sibling = filepath.Join(tr.stateDir, "server-ca.key"), filepath.Join(tr.data, "sibling")
	if err := os.MkdirAll(tr.stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{tr.secret, tr.sibling} {
		if err := os.WriteFile(f, []byte(stateDirSecret), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return tr
}

// run renders a profile for posture that grants the whole data root read and
// write, the ancestor grant the state-dir deny has to beat, and runs script
// under sandbox-exec with target as $1.
func (tr stateDirTree) run(t *testing.T, posture Posture, script, target string) ([]byte, string, error) {
	t.Helper()
	prof, err := Generate(&runtimev1.SandboxProfile{
		DataVolumePath:  filepath.Join(tr.pods, "pods", "p1", "rootfs"),
		ExtraReadPaths:  []string{tr.data},
		ExtraWritePaths: []string{tr.data},
	}, GenerateOptions{Posture: posture})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "statedir.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/sh", "-c", script, "sh", target).Output()
	return out, prof, err
}

const (
	stateDirWriteScript = `printf forged > "$1"`
	stateDirReadScript  = `IFS= read -r line < "$1" && printf '%s' "$line"`
)

// otherFirmlinkSpelling returns p in its other firmlink spelling: without the
// /private prefix when it has one, with it otherwise.
func otherFirmlinkSpelling(p string) string {
	if rest, ok := strings.CutPrefix(p, "/private/"); ok {
		return "/" + rest
	}
	return "/private" + p
}

// TestStateDirEnforcedUnderACustomLeaf is the kernel's verdict on the custom-leaf
// deny, through the sandbox-exec the DataRoot enforced cases use: with DataRoot
// alone a secret in <data root>/cp is readable through an ancestor grant (the
// defect), and with StateDir set it is neither readable nor writable, through
// the spelling the posture names and through its other firmlink spelling. Each
// row writes the posture in one spelling: the resolved /private one the k3sm
// caller hands over, and the /var one a work-dir under /var/lib is written in.
func TestStateDirEnforcedUnderACustomLeaf(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	for name, tc := range map[string]struct {
		tmp     string
		private bool
	}{
		"private spelling under /tmp": {"/tmp", true},
		"var spelling under /var/tmp": {"/var/tmp", false},
	} {
		t.Run(name, func(t *testing.T) {
			tr := newStateDirTree(t, tc.tmp, tc.private, "cp")
			rootOnly := Posture{WorkDir: tr.pods, DataRoot: tr.data}
			withState := Posture{WorkDir: tr.pods, DataRoot: tr.data, StateDir: tr.stateDir}

			// The controls: the grant reaches the sibling with the field set, and
			// the secret itself with DataRoot alone, so a refusal below is this deny.
			if out, prof, err := tr.run(t, withState, stateDirReadScript, tr.sibling); err != nil || string(out) != "private-key" {
				t.Fatalf("the ancestor grant did not read %s, so the deny is unproven: %v\n%s\n--- profile ---\n%s", tr.sibling, err, out, prof)
			}
			if out, prof, err := tr.run(t, rootOnly, stateDirReadScript, tr.secret); err != nil || string(out) != "private-key" {
				t.Fatalf("with DataRoot alone the custom-leaf secret was not readable, so this case proves nothing: %v\n%s\n--- profile ---\n%s", err, out, prof)
			}

			for _, target := range []string{tr.secret, otherFirmlinkSpelling(tr.secret)} {
				if out, prof, err := tr.run(t, withState, stateDirReadScript, target); err == nil || strings.Contains(string(out), "private-key") {
					t.Errorf("read of %s succeeded under the generated profile: %q\n--- profile ---\n%s", target, out, prof)
				}
			}
			newFile := filepath.Join(tr.stateDir, "new.key")
			for _, target := range []string{tr.secret, newFile, otherFirmlinkSpelling(newFile)} {
				if out, prof, err := tr.run(t, withState, stateDirWriteScript, target); err == nil {
					t.Errorf("write to %s succeeded under the generated profile: %s\n--- profile ---\n%s", target, out, prof)
				}
			}
			if got, err := os.ReadFile(tr.secret); err != nil || string(got) != stateDirSecret {
				t.Errorf("secret after the attempts = %q, %v; want %q", got, err, stateDirSecret)
			}
			if _, err := os.Stat(newFile); err == nil {
				t.Errorf("a new file landed in %s", tr.stateDir)
			}
		})
	}
}

// TestStateDirEnforcedAcrossCaseAndNormalization proves the state-dir deny is not
// a byte match the filesystem can step around. The default macOS volume is
// case-insensitive and normalization-insensitive APFS, so <data>/CPÉ and the NFD
// spelling of <data>/cpé open the same directory as the NFC <data>/cpé the
// posture names. Each spelling the temp volume resolves to the state dir must be
// denied in both firmlink spellings; one the volume keeps distinct is skipped
// with the reason, since there it is another directory and nothing to deny.
func TestStateDirEnforcedAcrossCaseAndNormalization(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	const leaf = "cp\u00e9" // NFC: c, p, U+00E9
	tr := newStateDirTree(t, "/var/tmp", false, leaf)
	rootOnly := Posture{WorkDir: tr.pods, DataRoot: tr.data}
	withState := Posture{WorkDir: tr.pods, DataRoot: tr.data, StateDir: tr.stateDir}
	if out, prof, err := tr.run(t, withState, stateDirReadScript, tr.sibling); err != nil || string(out) != "private-key" {
		t.Fatalf("the ancestor grant did not read %s, so the deny is unproven: %v\n%s\n--- profile ---\n%s", tr.sibling, err, out, prof)
	}
	want, err := os.Stat(tr.secret)
	if err != nil {
		t.Fatal(err)
	}
	for name, variant := range map[string]string{
		"upper case":     "CP\u00c9",  // C, P, U+00C9
		"mixed case":     "Cp\u00e9",  // C, p, U+00E9
		"NFD":            "cpe\u0301", // c, p, e, U+0301 combining acute
		"upper-case NFD": "CPE\u0301",
	} {
		t.Run(name, func(t *testing.T) {
			secret := filepath.Join(tr.data, variant, "server-ca.key")
			if got, err := os.Stat(secret); err != nil || !os.SameFile(want, got) {
				t.Skipf("the temp volume keeps %q distinct from %q (stat: %v), so it is another directory and nothing to deny", variant, leaf, err)
			}
			// The control: the variant reaches the secret with DataRoot alone, so
			// the refusal below is the state-dir deny and not a missing file.
			if out, prof, err := tr.run(t, rootOnly, stateDirReadScript, secret); err != nil || string(out) != "private-key" {
				t.Fatalf("with DataRoot alone %s was not readable, so this case proves nothing: %v\n%s\n--- profile ---\n%s", secret, err, out, prof)
			}
			for _, target := range []string{secret, otherFirmlinkSpelling(secret)} {
				if out, prof, err := tr.run(t, withState, stateDirReadScript, target); err == nil || strings.Contains(string(out), "private-key") {
					t.Errorf("read of %s succeeded under the generated profile: %q\n--- profile ---\n%s", target, out, prof)
				}
				if out, prof, err := tr.run(t, withState, stateDirWriteScript, target); err == nil {
					t.Errorf("write to %s succeeded under the generated profile: %s\n--- profile ---\n%s", target, out, prof)
				}
			}
		})
	}
	if got, err := os.ReadFile(tr.secret); err != nil || string(got) != stateDirSecret {
		t.Errorf("secret after the attempts = %q, %v; want %q", got, err, stateDirSecret)
	}
}
