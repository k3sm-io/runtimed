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

// metadataStanzaHeader is the one line the ancestor grant is emitted under. The
// tests below locate the stanza by it, so a rename of the rule is as red as a
// removal.
const metadataStanzaHeader = "(allow file-read-metadata\n"

// sbplStanza is one rendered rule: its head line (e.g. `(allow file-read*`) and
// the filter lines under it, each trimmed.
type sbplStanza struct {
	head    string
	filters []string
}

// parseStanzas splits a rendered profile into its rules, ignoring comments. A
// stanza opens on a line starting with "(" that is not self-contained and closes
// on the ")" line; a single-line rule is a stanza with no filters. It is
// deliberately shape-aware rather than a substring scan: "is this path allowed"
// cannot be answered by grep — the same literal appears under an allow and a deny
// in the same profile, and only the enclosing head says which.
func parseStanzas(profile string) []sbplStanza {
	var out []sbplStanza
	var cur *sbplStanza
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if cur == nil {
			if !strings.HasPrefix(line, "(") {
				continue
			}
			head := line
			// A rule that closes on its own line (balanced parens) carries its
			// filters inline; record them as filters of a one-line stanza.
			if strings.Count(line, "(") == strings.Count(line, ")") {
				out = append(out, sbplStanza{head: head})
				continue
			}
			cur = &sbplStanza{head: head}
			continue
		}
		if line == ")" || line == "))" {
			out = append(out, *cur)
			cur = nil
			continue
		}
		f := strings.TrimSuffix(line, ")")
		cur.filters = append(cur.filters, f)
		if strings.HasSuffix(line, "))") || (strings.Count(line, "(") < strings.Count(line, ")")) {
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// metadataLiterals returns the literal paths of the profile's single ancestor
// metadata stanza, and how many such stanzas the profile carries.
func metadataLiterals(profile string) (paths []string, stanzas int) {
	for _, st := range parseStanzas(profile) {
		if st.head != strings.TrimSpace(metadataStanzaHeader) {
			continue
		}
		stanzas++
		for _, f := range st.filters {
			if p, ok := literalPath(f); ok {
				paths = append(paths, p)
			}
		}
	}
	return paths, stanzas
}

// literalPath extracts P from a `(literal "P")` filter line.
func literalPath(filter string) (string, bool) {
	const pre = `(literal "`
	if !strings.HasPrefix(filter, pre) {
		return "", false
	}
	rest := strings.TrimPrefix(filter, pre)
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// allowsPath reports whether any ALLOW stanza in the profile names path with the
// given filter kind ("subpath" or "literal").
func allowsPath(profile, kind, path string) bool {
	want := "(" + kind + " " + strconv.Quote(path) + ")"
	for _, st := range parseStanzas(profile) {
		if !strings.HasPrefix(st.head, "(allow ") {
			continue
		}
		for _, f := range st.filters {
			if f == want {
				return true
			}
		}
	}
	return false
}

// TestGenerateAncestorMetadataLiterals is the B277 shape pin: the strict
// ancestors of the data volume get file-read-metadata — in BOTH firmlink forms,
// so the bare /private node a resolved stat-walk hits first is granted — in ONE
// stanza emitted after the pods-root deny, and they get nothing else. A
// swift-driver canonicalizing its cwd stats every one of them; before this grant
// the walk died at /private and the compile failed with "unable to set working
// directory".
func TestGenerateAncestorMetadataLiterals(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	const podsRoot = "/var/lib/k3sm/pods"

	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	want := []string{
		"/var", "/var/lib", "/var/lib/k3sm", "/var/lib/k3sm/pods", "/var/lib/k3sm/pods/p1",
		"/private", "/private/var", "/private/var/lib", "/private/var/lib/k3sm",
		"/private/var/lib/k3sm/pods", "/private/var/lib/k3sm/pods/p1",
	}
	got, stanzas := metadataLiterals(out)
	if stanzas != 1 {
		t.Fatalf("want exactly 1 %q stanza, got %d:\n%s", strings.TrimSpace(metadataStanzaHeader), stanzas, out)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ancestor metadata literals mismatch\n got: %v\nwant: %v\n--- profile ---\n%s", got, want, out)
	}

	// Order: the stanza must sit AFTER the protected deny naming the pods root,
	// or last-match-wins erases it (the ancestors are inside that deny's subpath).
	iDeny := strings.Index(out, "(deny file-read* file-write*\n  (subpath \""+podsRoot+"\")")
	iMeta := strings.Index(out, metadataStanzaHeader)
	if iDeny < 0 || iMeta < 0 {
		t.Fatalf("pods-root deny (%d) or metadata stanza (%d) missing:\n%s", iDeny, iMeta, out)
	}
	if iDeny >= iMeta {
		t.Errorf("pods-root deny (%d) must precede the ancestor metadata stanza (%d)", iDeny, iMeta)
	}

	// Narrowness: no ancestor is ever handed out as a subpath (that would reach
	// every sibling pod) and none is granted read* / read-data (no listing, no
	// opening — stat only).
	for _, p := range []string{podsRoot, podsRoot + "/p1", "/private" + podsRoot, "/private" + podsRoot + "/p1"} {
		if allowsPath(out, "subpath", p) {
			t.Errorf("profile allows (subpath %q) — the ancestor grant must be literal-only:\n%s", p, out)
		}
	}
	for _, st := range parseStanzas(out) {
		if !strings.HasPrefix(st.head, "(allow file-read*") && !strings.HasPrefix(st.head, "(allow file-read-data") {
			continue
		}
		for _, f := range st.filters {
			p, ok := literalPath(f)
			if !ok {
				continue
			}
			for _, anc := range want {
				if p == anc {
					t.Errorf("ancestor %q is granted by %q — ancestors get file-read-metadata only:\n%s", p, st.head, out)
				}
			}
		}
	}
}

// TestGenerateAncestorMetadataUnderUsersPosture pins the grant for the
// unprivileged user-space posture, where the walk crosses the fixed /Users deny:
// /Users and the daemon home are stat-able (the pod must be able to descend to
// its own volume) while /Users stays denied as a subtree, and the grant is
// emitted after that deny so it survives last-match-wins.
func TestGenerateAncestorMetadataUnderUsersPosture(t *testing.T) {
	const home = "/Users/_k3sm"
	const workDir = home + "/Library/k3sm"
	const dataVol = workDir + "/pods/pod-abc/rootfs"

	out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture: Posture{WorkDir: workDir, Home: home},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	got, stanzas := metadataLiterals(out)
	if stanzas != 1 {
		t.Fatalf("want exactly 1 metadata stanza, got %d:\n%s", stanzas, out)
	}
	for _, p := range []string{"/Users", home, workDir, workDir + "/pods", workDir + "/pods/pod-abc"} {
		if !contains(got, p) {
			t.Errorf("ancestor %q missing from the metadata stanza %v:\n%s", p, got, out)
		}
	}
	// /Users is stat-able, never readable: the subtree deny stands.
	if allowsPath(out, "subpath", "/Users") {
		t.Errorf("profile allows (subpath \"/Users\") — only a literal metadata grant is intended:\n%s", out)
	}
	iDeny := strings.Index(out, "(deny file-read* file-write*\n  (subpath \"/Users\"))")
	iMeta := strings.Index(out, metadataStanzaHeader)
	if iDeny < 0 || iMeta < 0 {
		t.Fatalf("/Users deny (%d) or metadata stanza (%d) missing:\n%s", iDeny, iMeta, out)
	}
	if iDeny >= iMeta {
		t.Errorf("/Users deny (%d) must precede the ancestor metadata stanza (%d)", iDeny, iMeta)
	}
}

// TestGenerateAncestorMetadataCoversPVRoots pins the second reason the grant
// iterates a set rather than the data volume alone: a persistent-volume mount
// root lives OUTSIDE the pod's volume (on the storage root, so it survives
// teardown), and a pod that cannot stat-walk to it cannot chdir into it either.
func TestGenerateAncestorMetadataCoversPVRoots(t *testing.T) {
	const dataVol = "/var/lib/k3sm/pods/p1/rootfs"
	cases := []struct {
		name string
		opts GenerateOptions
		want []string
	}{
		{
			name: "read-write-pv",
			opts: GenerateOptions{WritePaths: []string{"/var/lib/k3sm/storage/pv-1"}},
			want: []string{"/private/var/lib/k3sm/storage", "/var/lib/k3sm/storage"},
		},
		{
			name: "read-only-pv",
			opts: GenerateOptions{ReadPaths: []string{"/var/lib/k3sm/storage/pv-ro"}},
			want: []string{"/private/var/lib/k3sm/storage", "/var/lib/k3sm/storage"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, tc.opts)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			got, stanzas := metadataLiterals(out)
			if stanzas != 1 {
				t.Fatalf("want exactly 1 metadata stanza, got %d:\n%s", stanzas, out)
			}
			for _, p := range tc.want {
				if !contains(got, p) {
					t.Errorf("PV ancestor %q missing from the metadata stanza %v:\n%s", p, got, out)
				}
			}
			// One line per distinct path: a duplicated ancestor would mean the
			// dedupe across roots and forms had stopped working.
			seen := map[string]int{}
			for _, p := range got {
				seen[p]++
				if seen[p] > 1 {
					t.Errorf("ancestor %q emitted %d times:\n%s", p, seen[p], out)
				}
			}
		})
	}
}

// TestAncestorMetadataGrantsStatNotList is the execution pin: under the REAL
// libsandbox the generated profile lets a process stat the denied pods root
// (the walk down to the pod's own volume) and still refuses to list it. The
// shape assertions above cannot show this — only a run can tell
// file-read-metadata from file-read-data.
//
// Sited under /tmp (like TestGeneratedProfileAllowsRebasedFileRead) so it needs
// no root, and skipped where sandbox-exec is absent.
func TestAncestorMetadataGrantsStatNotList(t *testing.T) {
	if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not present")
	}
	base := filepath.Join("/tmp", "k3sm-anc-"+strconv.Itoa(os.Getpid()))
	podsRoot := filepath.Join(base, "pods")
	dataVol := filepath.Join(podsRoot, "pod-anc", "rootfs")
	// The OS lands the tree under the /private-resolved form, which is what
	// libsandbox matches; the pod addresses the /tmp firmlink alias.
	if err := os.MkdirAll("/private"+dataVol, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll("/private" + base)
	// A sibling pod's dir: what listing the pods root would disclose.
	if err := os.MkdirAll("/private"+filepath.Join(podsRoot, "pod-sibling"), 0o755); err != nil {
		t.Fatal(err)
	}

	prof, err := Generate(&runtimev1.SandboxProfile{DataVolumePath: dataVol}, GenerateOptions{
		Posture: Posture{WorkDir: base},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sb := filepath.Join(t.TempDir(), "anc.sb")
	if err := os.WriteFile(sb, []byte(prof), 0o644); err != nil {
		t.Fatal(err)
	}

	// stat(2) of the denied pods root: allowed (file-read-metadata).
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/test", "-e", podsRoot).CombinedOutput(); err != nil {
		t.Fatalf("stat of the pods root %s was DENIED under the generated profile: %v\n%s\n--- profile ---\n%s", podsRoot, err, out, prof)
	}
	// readdir(3) of the same directory: still denied (no file-read-data).
	out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sb, "/bin/ls", podsRoot).CombinedOutput()
	if err == nil {
		t.Fatalf("listing the pods root %s SUCCEEDED — the ancestor grant must not confer read-data:\n%s\n--- profile ---\n%s", podsRoot, out, prof)
	}
	if strings.Contains(string(out), "pod-sibling") {
		t.Fatalf("listing the pods root disclosed a sibling pod:\n%s", out)
	}
	if !strings.Contains(string(out), "Operation not permitted") {
		t.Fatalf("the listing failed, but not on the sandbox deny (want EPERM): %v\n%s", err, out)
	}

	// Ablation: the stanza IS the reason the stat succeeds. Cut it from the
	// rendered profile (it is emitted last for a profile with no credential
	// sub-scope) and the same stat is denied — without this the assertion above
	// would also pass if some other rule had quietly granted the walk.
	i := strings.Index(prof, metadataStanzaHeader)
	if i < 0 {
		t.Fatalf("metadata stanza missing from the rendered profile:\n%s", prof)
	}
	ablated := prof[:strings.LastIndex(prof[:i], ";; existence only")]
	sbAblated := filepath.Join(t.TempDir(), "anc-ablated.sb")
	if err := os.WriteFile(sbAblated, []byte(ablated), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", sbAblated, "/bin/test", "-e", podsRoot).CombinedOutput(); err == nil {
		t.Fatalf("stat of the pods root succeeded WITHOUT the ancestor grant — this test proves nothing:\n%s\n--- profile ---\n%s", out, ablated)
	}
}
