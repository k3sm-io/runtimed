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
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestDataVolumePathRejectsProtectedTree is B142's sink-side gate: the data
// volume must be a proper descendant of <Posture.WorkDir>/pods, so a hostile
// SandboxProfile.data_volume_path can no longer clobber the protected deny-set.
//
// Why the table is shaped this way — three traps it is built to avoid:
//
//   - A protected-prefix MEMBERSHIP test would pass every row that matters. The
//     damaging values ("/", "/var/lib", the work-dir itself, the pods root
//     itself) are ANCESTORS of every protected prefix and are under none of
//     them, yet each emits one (allow file-read* file-write* (subpath …)) after
//     the denies and takes pods/podreap/server/agent/run/blobs with it. So the
//     assertion is positive containment, and the rows are chosen to be exactly
//     the ancestors a deny-list cannot express.
//   - The work-dir is a t.TempDir(), so a hard-coded /var/lib/k3sm cannot make
//     any row pass.
//   - An error-only gate cannot tell "hostile values rejected" from "every pod
//     broken" — the failure mode that would take down every pod on the node.
//     The positive control therefore drives a LEGITIMATE data volume all the way
//     through and asserts the re-allow is still emitted, in both firmlink forms,
//     and still lands after the deny block.
func TestDataVolumePathRejectsProtectedTree(t *testing.T) {
	workDir := t.TempDir()
	posture := Posture{WorkDir: workDir}
	podsRoot := filepath.Join(workDir, "pods")

	reject := []struct {
		name    string
		dataVol string
	}{
		{"filesystem-root", "/"},
		{"user-homes", "/Users"},
		{"the work-dir itself", workDir},
		{"the pods root itself", podsRoot},
		{"a system state ancestor", "/var/lib"},
		{"relative", "pods/p1/rootfs"},
		{"the control-plane state dir", filepath.Join(workDir, ServerSubdir)},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			_, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: tc.dataVol}, GenerateOptions{Posture: posture})
			if !errors.Is(err, ErrDataVolumeUnbounded) {
				t.Fatalf("Generate(data_volume_path=%q) err = %v, want ErrDataVolumeUnbounded", tc.dataVol, err)
			}
		})
	}

	// A hostile data volume must ALSO not disarm the extra-path validator, which
	// carves out everything under it: before the bound, one hostile value made
	// every other path in the same box unvalidated. Assert the box is refused
	// even when it carries an extra path that only the carve-out could have
	// admitted.
	t.Run("reject/does not disarm the extra-path carve-out", func(t *testing.T) {
		_, err := Generate(&runtimev1.SandboxProfile{
			DataVolumePath: workDir,
			ExtraReadPaths: []string{filepath.Join(workDir, ServerSubdir, "cred", "server-ca.key")},
		}, GenerateOptions{Posture: posture})
		if !errors.Is(err, ErrDataVolumeUnbounded) {
			t.Fatalf("err = %v, want ErrDataVolumeUnbounded (the carve-out base must be bounded first)", err)
		}
	})

	// positive CONTROL. Without it this gate cannot distinguish "hostile values
	// rejected" from "every pod broken".
	t.Run("positive/a legitimate pod data volume still generates", func(t *testing.T) {
		dataVol := filepath.Join(podsRoot, "pod-abc123", "rootfs")
		out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{Posture: posture})
		if err != nil {
			t.Fatalf("Generate(%q): %v", dataVol, err)
		}

		// The re-allow survives in both firmlink forms: a t.TempDir() lives under
		// /var on macOS, and libsandbox matches the SYMLINK-RESOLVED path, so an
		// allow written only against the /var spelling fails closed — the pod
		// cannot read its own volume.
		forms := firmlinkForms(dataVol)
		if len(forms) < 2 {
			t.Logf("work-dir %q is not under a firmlink; only one form asserted", workDir)
		}
		reallow := "(allow file-read* file-write*\n"
		for _, form := range forms {
			reallow += "  (subpath \"" + form + "\")\n"
		}
		iReallow := strings.Index(out, reallow)
		if iReallow < 0 {
			t.Fatalf("the pod's own data-volume re-allow is missing (or lost a firmlink form):\nwant:\n%s\ngot:\n%s", reallow, out)
		}

		// Ordering, house index style: the re-allow must come after the deny
		// block (it lives under the denied pods root), while NO allow naming the
		// work-dir or the control-plane state dir may appear after it — that is
		// the shape a hostile value used to produce.
		iDeny := strings.Index(out, "(deny file-read* file-write*\n  (subpath \""+podsRoot+"\")")
		if iDeny < 0 {
			t.Fatalf("pods-root deny stanza missing:\n%s", out)
		}
		if iDeny >= iReallow {
			t.Errorf("pods-root deny (%d) must precede the data-volume re-allow (%d)", iDeny, iReallow)
		}
		for _, wide := range []string{workDir, filepath.Join(workDir, ServerSubdir)} {
			for _, form := range firmlinkForms(wide) {
				frag := "(subpath \"" + form + "\")"
				for i := iDeny; ; {
					j := strings.Index(out[i:], frag)
					if j < 0 {
						break
					}
					at := i + j
					if isAllowStanza(out[:at]) {
						t.Errorf("an allow naming %q is emitted at %d, after the deny block (%d) — it would override every protected deny:\n%s", form, at, iDeny, out)
					}
					i = at + len(frag)
				}
			}
		}
	})

	// The isUnder/strictlyUnder asymmetry, pinned rather than commented: the one
	// case that separates them IS the pods root itself, which isUnder accepts and
	// the bound must refuse.
	t.Run("predicate/strictlyUnder excludes equality", func(t *testing.T) {
		child := filepath.Join(podsRoot, "pod-abc123", "rootfs")
		cases := []struct {
			name            string
			path            string
			under, strictly bool
		}{
			{"the pods root itself", podsRoot, true, false},
			{"a pod dir under it", child, true, true},
			{"an ancestor", workDir, false, false},
			{"a name-prefix sibling", podsRoot + "-evil", false, false},
			{"a relative path", "pods/p1/rootfs", false, false},
			// strictlyUnder CLEANS its own operands; isUnder does not. This is the
			// one row where the two deliberately disagree, and it is the reason the
			// sink predicate does not inherit a precondition from the caller it
			// exists to distrust: uncleaned, a raw prefix test says "under".
			{"an uncleaned traversal out of the pods root", podsRoot + "/../../../etc", true, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := isUnder(tc.path, podsRoot); got != tc.under {
					t.Errorf("isUnder(%q, %q) = %v, want %v", tc.path, podsRoot, got, tc.under)
				}
				if got := strictlyUnder(tc.path, podsRoot); got != tc.strictly {
					t.Errorf("strictlyUnder(%q, %q) = %v, want %v", tc.path, podsRoot, got, tc.strictly)
				}
			})
		}

		// The root prefix, which the sibling copies special-case too.
		for _, tc := range []struct {
			path string
			want bool
		}{{"/etc", true}, {"/", false}, {"etc", false}} {
			if got := strictlyUnder(tc.path, "/"); got != tc.want {
				t.Errorf("strictlyUnder(%q, \"/\") = %v, want %v", tc.path, got, tc.want)
			}
		}
	})
}

// isAllowStanza reports whether the SBPL text ending at the caller's cursor is
// inside an (allow …) stanza rather than a (deny …) one: it looks back for the
// nearest stanza opener. The generator emits one filter per line inside a stanza
// opened by "(allow …" or "(deny …", so the nearest opener decides.
func isAllowStanza(before string) bool {
	iAllow := strings.LastIndex(before, "\n(allow ")
	iDeny := strings.LastIndex(before, "\n(deny ")
	return iAllow > iDeny
}
