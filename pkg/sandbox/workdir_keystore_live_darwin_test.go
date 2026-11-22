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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestWorkDirKeystoreDenyHidesExistence applies a real pod profile, and the
// shim profile built on it, to a probe and measures whether a pod can tell
// a keystore name in the role's work dir (Posture.StateDir) exists. The
// whole-tree state-dir deny refuses a present name with EPERM but lets an
// absent one answer ENOENT, which is an existence oracle; the keystore
// stanza's file-test-existence deny, emitted for the work dir too, answers
// EPERM either way.
//
// For a missing keystore-x and an existing keystore-y, every attempt must
// answer exactly DENIED:EPERM, the same for both names: read, stat, the
// access(2) F_OK test, open(O_CREAT|O_WRONLY), unlink, rename onto and away
// from the name, a hard link from and onto it, a symlink at it and readlink.
// Read, stat and the F_OK test also run on the folded spellings KEYSTORE-,
// Keystore- and the Kelvin sign for k. Each runs in every spelling of the
// work dir, for a work dir with the default server leaf and one with another
// leaf, under the pod and the shim profile, and after each one the files are
// checked unchanged from outside the sandbox.
//
// Unsandboxed, read, stat and the F_OK test answer ENOENT for keystore-x and
// OK for keystore-y in every folded spelling: the control that the two names
// do differ, that the folds name the real file, and that only the deny makes
// them look alike.
func TestWorkDirKeystoreDenyHidesExistence(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available to build the probe")
	}
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "main.go"), []byte(keystoreProbeGo), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "probe")
	build := exec.Command(goTool, "build", "-o", bin, filepath.Join(binDir, "main.go"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}

	base := filepath.Join("/private/tmp", "k3sm-wks-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	work, data := filepath.Join(base, "w"), filepath.Join(base, "d")
	dataVol := filepath.Join(work, "pods", "p1", "rootfs")
	if err := os.MkdirAll(dataVol, 0o755); err != nil {
		t.Fatal(err)
	}

	rootSpellings := map[string]func(string) string{
		"as created":           func(r string) string { return r },
		"/tmp":                 func(r string) string { return strings.TrimPrefix(r, "/private") },
		"/System/Volumes/Data": func(r string) string { return dataVolumeAlias + r },
	}
	probe := func(sb string, args ...string) string {
		cmd := exec.Command(bin, args...)
		if sb != "" {
			cmd = exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb, bin}, args...)...)
		}
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	for _, leaf := range []string{ServerSubdir, "cp"} {
		stateDir := filepath.Join(data, leaf)
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, "keystore-y"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		// Unsandboxed control: the absent name and the present one answer
		// differently, so a sandboxed answer that is the same for both is
		// the deny's doing.
		for rname, rootOf := range rootSpellings {
			r := rootOf(stateDir)
			for _, op := range []string{"read", "stat", "exists"} {
				if got := probe("", op, filepath.Join(r, "keystore-x")); !strings.HasPrefix(got, "ERR:ENOENT") {
					t.Errorf("unsandboxed, leaf %s, root %s: %s keystore-x = %s, want ERR:ENOENT", leaf, rname, op, got)
				}
				for _, name := range []string{"keystore-y", "KEYSTORE-y", "Keystore-y", "\u212Aeystore-y"} {
					if got := probe("", op, filepath.Join(r, name)); got != "OK" {
						t.Errorf("unsandboxed, leaf %s, root %s: %s %s = %s, want OK (the volume does not fold this spelling)", leaf, rname, op, name, got)
					}
				}
			}
		}

		pod, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: dataVol,
			ExtraReadPaths: []string{binDir},
		}, GenerateOptions{Posture: Posture{WorkDir: work, DataRoot: data, StateDir: stateDir}})
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		shim, err := ShimProfile(pod, ShimGrant{Dir: filepath.Join(ShimRoot(work), "0a1b2c3d")})
		if err != nil {
			t.Fatalf("ShimProfile: %v", err)
		}
		// unchanged is the unsandboxed control after each sandboxed attempt:
		// keystore-x is still absent, keystore-y still holds what it was
		// written with, and no folded spelling of either was made.
		unchanged := func(t *testing.T, after []string) {
			t.Helper()
			if got := probe("", "stat", filepath.Join(stateDir, "keystore-x")); !strings.HasPrefix(got, "ERR:ENOENT") {
				t.Errorf("after %q: unsandboxed stat keystore-x = %s, want ERR:ENOENT", after, got)
			}
			if b, err := os.ReadFile(filepath.Join(stateDir, "keystore-y")); err != nil || string(b) != "{}" {
				t.Errorf("after %q: keystore-y = %q, %v, want it unchanged", after, b, err)
			}
			if ents, err := os.ReadDir(stateDir); err != nil {
				t.Fatal(err)
			} else if len(ents) != 1 {
				t.Errorf("after %q: state dir holds %d entries, want keystore-y alone", after, len(ents))
			}
		}
		for which, prof := range map[string]string{"pod": pod, "shim": shim} {
			t.Run(leaf+"/"+which, func(t *testing.T) {
				sb := filepath.Join(base, leaf+"-"+which+".sb")
				if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
					t.Fatal(err)
				}
				n := 0
				fresh := func(stem string) string {
					n++
					return filepath.Join(dataVol, leaf+"-"+which+"-"+stem+strconv.Itoa(n))
				}
				// sibling makes a file in the pod's writable rootfs, outside
				// the sandbox, for a rename or link onto a keystore name.
				sibling := func() string {
					p := fresh("s")
					if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
						t.Fatal(err)
					}
					return p
				}
				for rname, rootOf := range rootSpellings {
					r := rootOf(stateDir)
					var attempts [][]string
					for _, name := range []string{"keystore-x", "keystore-y"} {
						p := filepath.Join(r, name)
						attempts = append(attempts,
							[]string{"read", p},
							[]string{"stat", p},
							[]string{"exists", p},
							[]string{"open", p},
							[]string{"unlink", p},
							[]string{"rename", sibling(), p},
							[]string{"rename", p, fresh("r")},
							[]string{"link", p, fresh("h")},
							[]string{"link", sibling(), p},
							[]string{"symlink", p, "/etc/hosts"},
							[]string{"readlink", p},
						)
					}
					// The folds the stanza's regex matches: letter case and
					// the Kelvin sign (U+212A) for k.
					for _, name := range []string{"KEYSTORE-", "Keystore-", "\u212Aeystore-"} {
						for _, leafName := range []string{name + "x", name + "y"} {
							p := filepath.Join(r, leafName)
							attempts = append(attempts, []string{"read", p}, []string{"stat", p}, []string{"exists", p})
						}
					}
					for _, a := range attempts {
						got := probe(sb, a...)
						t.Logf("%s / root %s: %s %q: %s", which, rname, a[0], a[1:], got)
						if got != keystoreDenied {
							t.Errorf("root %s: %s %q = %s, want %s", rname, a[0], a[1:], got, keystoreDenied)
						}
						unchanged(t, a)
					}
				}
			})
		}
	}
}
