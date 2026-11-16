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
	"strconv"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestExposeProfileDeniesRootAllowsLeaf pins the rule order: every profile
// denies the exposures root (under the work dir and under a distinct data
// root) in the protected tier, and a pod's own leaf is re-allowed only after
// that deny, so last-match-wins gives the pod its leaf and nothing beside it.
func TestExposeProfileDeniesRootAllowsLeaf(t *testing.T) {
	const (
		leafA = "/var/lib/k3sm/expose/yurei-system/pod-a/sockets"
		leafB = "/var/lib/k3sm/expose/yurei-system/pod-b/sockets"
	)
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/pod-a/rootfs"}
	for _, tc := range []struct {
		name   string
		leaves []string
	}{
		{"no exposure", nil},
		{"leaf A", []string{leafA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Generate(sp, GenerateOptions{
				Posture:     Posture{DataRoot: "/opt/k3sm-data"},
				ExposePaths: tc.leaves,
			})
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			deny := strings.Index(got, `  (subpath "/private/var/lib/k3sm/expose")`)
			if deny < 0 || !strings.Contains(got, `  (subpath "/var/lib/k3sm/expose")`) || !strings.Contains(got, `  (subpath "/opt/k3sm-data/expose")`) {
				t.Fatalf("the exposures roots are not denied:\n%s", got)
			}
			if strings.Contains(got, leafB) {
				t.Errorf("sibling leaf %s is named in the profile", leafB)
			}
			allow := strings.Index(got, `  (subpath "`+leafA+`")`)
			if tc.leaves == nil {
				if allow >= 0 {
					t.Errorf("a pod with no exposure is granted %s", leafA)
				}
				return
			}
			if allow < deny {
				t.Errorf("leaf A allow (at %d) is not after the exposures-root deny (at %d)", allow, deny)
			}
			if !strings.Contains(got, `  (subpath "/private`+leafA+`")`) {
				t.Errorf("leaf A lacks its /private form")
			}
		})
	}
}

func TestExposeProfileRefusesBadLeaf(t *testing.T) {
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/pod-a/rootfs"}
	for _, p := range []string{
		"/var/lib/k3sm/expose",
		"/var/lib/k3sm/expose/ns",
		"/var/lib/k3sm/expose/ns/pod",
		"/var/lib/k3sm/expose/ns/pod/vol/deeper",
		"/var/lib/k3sm/expose/ns/../pod/vol",
		"/var/lib/k3sm/storage/ns/pod/vol",
		"relative/ns/pod/vol",
	} {
		t.Run(p, func(t *testing.T) {
			_, err := Generate(sp, GenerateOptions{ExposePaths: []string{p}})
			if !errors.Is(err, ErrInvalidExposePath) {
				t.Errorf("Generate with exposure %q: err = %v, want ErrInvalidExposePath", p, err)
			}
		})
	}
	// A leaf may not ride in as a plain write grant: the root is protected.
	_, err := Generate(sp, GenerateOptions{WritePaths: []string{"/var/lib/k3sm/expose/ns/pod/vol"}})
	if !errors.Is(err, ErrProtectedPath) {
		t.Errorf("an exposure leaf as a WritePath: err = %v, want ErrProtectedPath", err)
	}
}

// TestExposeProfileEnforcedOnDarwin runs the generated profile through
// libsandbox: with a read grant on the whole work dir (the widest a caller
// may name), a pod with leaf A reads and writes A and reaches neither sibling
// leaf B nor anything else under the exposures root.
func TestExposeProfileEnforcedOnDarwin(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/tmp", "k3sm-expose-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { _ = os.RemoveAll("/private" + base) })
	dataVol := filepath.Join(base, "pods", "pod-a", "rootfs")
	leafA := filepath.Join(base, ExposeSubdir, "ns", "pod-a", "vol")
	leafB := filepath.Join(base, ExposeSubdir, "ns", "pod-b", "vol")
	// leafE is an empty leaf of pod-a, leafM one runtimed has not made yet:
	// the pod may neither remove the first nor create the second.
	leafE := filepath.Join(base, ExposeSubdir, "ns", "pod-a", "empty")
	leafM := filepath.Join(base, ExposeSubdir, "ns", "pod-a", "missing")
	stray := filepath.Join(base, ExposeSubdir, "stray")
	for _, d := range []string{dataVol, leafA, leafB, leafE} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(leafA, "f"), filepath.Join(leafB, "f"), stray} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol, ExtraReadPaths: []string{base}}, GenerateOptions{
		Posture:     Posture{WorkDir: base},
		ExposePaths: []string{leafA, leafE, leafM},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "expose.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) error {
		return exec.Command("/usr/bin/sandbox-exec", append([]string{"-f", sb}, argv...)...).Run()
	}
	for _, c := range []struct {
		name  string
		argv  []string
		allow bool
	}{
		{"read own leaf", []string{"/bin/cat", filepath.Join(leafA, "f")}, true},
		{"write own leaf", []string{"/usr/bin/touch", filepath.Join(leafA, "new")}, true},
		{"read sibling leaf", []string{"/bin/cat", filepath.Join(leafB, "f")}, false},
		{"write sibling leaf", []string{"/usr/bin/touch", filepath.Join(leafB, "new")}, false},
		{"read the exposures root", []string{"/bin/cat", stray}, false},
		{"list the exposures root", []string{"/bin/ls", filepath.Join(base, ExposeSubdir)}, false},
		{"chmod a file in own leaf", []string{"/bin/chmod", "0666", filepath.Join(leafA, "f")}, true},
		{"chmod own leaf itself", []string{"/bin/chmod", "0777", leafA}, false},
		{"add an ACL entry to own leaf", []string{"/bin/chmod", "+a", "everyone allow list,search", leafA}, false},
		{"set a flag on own leaf", []string{"/usr/bin/chflags", "uchg", leafA}, false},
		{"remove own empty leaf", []string{"/bin/rmdir", leafE}, false},
		{"rename own leaf away", []string{"/bin/mv", leafE, leafE + ".x"}, false},
		{"create a missing leaf", []string{"/bin/mkdir", leafM}, false},
		{"plant a symlink at a missing leaf", []string{"/bin/ln", "-s", "/tmp", leafM}, false},
		{"make a directory in own leaf", []string{"/bin/mkdir", filepath.Join(leafA, "d")}, true},
		{"remove a file in own leaf", []string{"/bin/rm", filepath.Join(leafA, "new")}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := run(c.argv...); (err == nil) != c.allow {
				t.Errorf("%v under the profile: err = %v, want allowed=%v\n--- profile ---\n%s", c.argv, err, c.allow, prof)
			}
		})
	}
}
