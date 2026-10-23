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
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// sbplStanza is one top-level form of a rendered profile: its head line (the
// action and operations) and the path filters it names.
type sbplStanza struct {
	head  string
	paths []sbplFilter
}

// sbplFilter is one path filter: kind is subpath, literal or prefix.
type sbplFilter struct {
	kind, path string
}

var sbplPath = regexp.MustCompile(`\((subpath|literal|prefix) "([^"]+)"\)`)

// parseStanzas splits a rendered profile into its top-level forms: each starts
// on a line whose first character is "(".
func parseStanzas(profile string) []sbplStanza {
	var out []sbplStanza
	for _, line := range strings.Split(profile, "\n") {
		if strings.HasPrefix(line, "(") {
			out = append(out, sbplStanza{head: line})
		}
		if len(out) == 0 {
			continue
		}
		for _, m := range sbplPath.FindAllStringSubmatch(line, -1) {
			out[len(out)-1].paths = append(out[len(out)-1].paths, sbplFilter{kind: m[1], path: m[2]})
		}
	}
	return out
}

// reaches reports whether a grant through filter f covers target or anything
// inside it: f names target or a path inside it, or f is a subpath/prefix of
// one of target's ancestors. A literal on an ancestor (the traversal metadata
// grants) names that directory alone and reaches nothing below it.
func reaches(f sbplFilter, target string) bool {
	p, target := filepath.Clean(f.path), filepath.Clean(target)
	if p == target || strings.HasPrefix(p, target+"/") {
		return true
	}
	return f.kind != "literal" && (p == "/" || strings.HasPrefix(target, p+"/"))
}

// TestPodProfileDeniesTheReapStore asserts, on the profile the runtime actually
// renders for a pod, the defense the reap records rely on: the records drive
// root kills (the group kill and, a per-pid kill of each recorded
// survivor), so a confined pod must not be able to read or forge them. The
// store (<root>/podreap, sandbox.PodReapSubdir) must sit in a read+write deny
// in both firmlink spellings, and no allow after that deny may reach the store,
// its parent (the runtime root), or any other ancestor, which by last-match-wins
// would reopen it. A pod that asks for write on the store's parent is either
// refused or rendered with the same guarantee.
func TestPodProfileDeniesTheReapStore(t *testing.T) {
	for _, tc := range []struct {
		name        string
		extraParent bool
	}{
		{name: "default pod"},
		{name: "pod asking to write the store's parent", extraParent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newBlockingWaiter()
			rt := newTestRuntime(t, Deps{Waiter: w})
			defer w.release(1001)
			store := rt.podReapRoot()
			if filepath.Base(store) != sandbox.PodReapSubdir || filepath.Dir(store) != rt.cfg.Root {
				t.Fatalf("reap store %q is not <root>/%s (root %q)", store, sandbox.PodReapSubdir, rt.cfg.Root)
			}
			box := hostBinBox(rt, "pod-reapdeny")
			if tc.extraParent {
				box.SandboxProfile.ExtraWritePaths = []string{rt.cfg.Root}
			}
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil || resp.GetError() != nil {
				if tc.extraParent {
					t.Logf("refused: %v %v", err, resp.GetError())
					return // refused: the parent grant never reaches a profile
				}
				t.Fatalf("CreatePod: %v %v", err, resp.GetError())
			}
			rt.mu.Lock()
			profile := rt.pods["pod-reapdeny"].profile
			rt.mu.Unlock()

			stanzas := parseStanzas(profile)
			targets := []string{store, "/private" + store}
			denyAt := -1
			for i, s := range stanzas {
				if !strings.HasPrefix(s.head, "(deny file-read* file-write*") {
					continue
				}
				found := 0
				for _, f := range s.paths {
					for _, tg := range targets {
						if f.kind == "subpath" && f.path == tg {
							found++
						}
					}
				}
				if found == len(targets) {
					denyAt = i
				}
			}
			if denyAt < 0 {
				t.Fatalf("no read+write deny names the reap store in both spellings %v:\n%s", targets, profile)
			}
			for _, s := range stanzas[denyAt+1:] {
				if !strings.HasPrefix(s.head, "(allow") || !(strings.Contains(s.head, "file-write") || strings.Contains(s.head, "file-read")) {
					continue
				}
				for _, f := range s.paths {
					for _, tg := range targets {
						if reaches(f, tg) {
							t.Errorf("allow %q on %s %q after the reap-store deny reopens %q:\n%s", s.head, f.kind, f.path, tg, profile)
						}
					}
				}
			}
		})
	}
}
