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
// For a missing keystore-x and an existing keystore-y, read, stat and the
// access(2) F_OK test must each answer exactly DENIED:EPERM, in every
// spelling of the work dir, for a work dir with the default server leaf and
// one with another leaf. Unsandboxed, the same probes answer ENOENT for
// keystore-x and OK for keystore-y: the control that the two names do differ
// and only the deny makes them look alike.
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
				if got := probe("", op, filepath.Join(r, "keystore-y")); got != "OK" {
					t.Errorf("unsandboxed, leaf %s, root %s: %s keystore-y = %s, want OK", leaf, rname, op, got)
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
		for which, prof := range map[string]string{"pod": pod, "shim": shim} {
			t.Run(leaf+"/"+which, func(t *testing.T) {
				sb := filepath.Join(base, leaf+"-"+which+".sb")
				if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
					t.Fatal(err)
				}
				for rname, rootOf := range rootSpellings {
					r := rootOf(stateDir)
					for _, name := range []string{"keystore-x", "keystore-y"} {
						for _, op := range []string{"read", "stat", "exists"} {
							p := filepath.Join(r, name)
							if got := probe(sb, op, p); got != keystoreDenied {
								t.Errorf("root %s: %s %s = %s, want %s", rname, op, p, got, keystoreDenied)
							}
						}
					}
				}
			})
		}
	}
}
