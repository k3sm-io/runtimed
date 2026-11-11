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

package runtime

import (
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestCompiledProfileNeverGrantsWriteOnThePodDir pins the invariant that a
// native pod's Seatbelt profile grants write on the pod's ROOTFS and never on
// the pod directory above it, even when the incoming box names the pod
// directory as its data volume (which the shipped provider does). Nothing a pod
// needs lives above <podDir>/rootfs, so a write grant there would only widen
// the blast radius.
func TestCompiledProfileNeverGrantsWriteOnThePodDir(t *testing.T) {
	rt := newTestRuntime(t, Deps{Spawner: &fakeSpawner{}, Waiter: newBlockingWaiter()})
	id := mustPodID(t, "pod-scope")
	podDir, rootfs := rt.cache.PodDir(id), rt.cache.PodRootfs(id)

	for name, dataVol := range map[string]string{"pod-dir": podDir, "rootfs": rootfs} {
		t.Run(name, func(t *testing.T) {
			box := &runtimev1.PodBox{
				PodId:          "pod-scope",
				SandboxProfile: &runtimev1.SandboxProfile{DataVolumePath: dataVol},
			}
			profile, err := rt.compileProfile(box, rootfs, "", nil, nil, nil, nil)
			if err != nil {
				t.Fatalf("compileProfile: %v", err)
			}

			// Ancestors of the rootfs (the pod dir included) that must never be
			// named by a write-granting allow rule.
			var forbidden []string
			for p := podDir; len(p) > 1; p = p[:strings.LastIndex(p, "/")] {
				forbidden = append(forbidden, p)
			}

			sawRootfs := false
			for _, rule := range allowRules(profile) {
				if !strings.Contains(rule, "file-write") {
					continue
				}
				if strings.Contains(rule, `(subpath "`+rootfs+`")`) {
					sawRootfs = true
				}
				for _, anc := range forbidden {
					for _, kind := range []string{"subpath", "literal"} {
						if strings.Contains(rule, "("+kind+` "`+anc+`")`) {
							t.Errorf("write-granting rule names %s %q:\n%s", kind, anc, rule)
						}
					}
				}
			}
			if !sawRootfs {
				t.Errorf("no allow file-write* rule with subpath %q in profile:\n%s", rootfs, profile)
			}
		})
	}
}

// allowRules splits SBPL text into its top-level "(allow ...)" forms by
// paren matching, ignoring parens inside string literals and ;; comments.
func allowRules(profile string) []string {
	var rules []string
	depth, start := 0, -1
	inStr := false
	for i := 0; i < len(profile); i++ {
		c := profile[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == ';':
			for i < len(profile) && profile[i] != '\n' {
				i++
			}
		case c == '(':
			if depth == 0 {
				start = i
			}
			depth++
		case c == ')':
			depth--
			if depth == 0 && strings.HasPrefix(profile[start:], "(allow") {
				rules = append(rules, profile[start:i+1])
			}
		}
	}
	return rules
}
