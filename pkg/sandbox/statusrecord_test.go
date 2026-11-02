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
