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

// TestPosixSemPrefix pins the derivation: fixed length, separator-terminated,
// lowercase hex from the pod UID alone, deterministic, and distinct per UID.
func TestPosixSemPrefix(t *testing.T) {
	a, err := PosixSemPrefix("8f3c1d2e-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != PosixSemPrefixLen || !posixSemPrefixRE.MatchString(a) {
		t.Fatalf("prefix %q is not /k3sm.<8 hex>.", a)
	}
	again, _ := PosixSemPrefix("8f3c1d2e-0000-4000-8000-000000000001")
	if again != a {
		t.Errorf("not deterministic: %q then %q", a, again)
	}
	b, _ := PosixSemPrefix("8f3c1d2e-0000-4000-8000-000000000002")
	if b == a {
		t.Errorf("two UIDs share prefix %q", a)
	}
	if _, err := PosixSemPrefix(""); !errors.Is(err, ErrInvalidPodUID) {
		t.Errorf("empty uid: err = %v, want ErrInvalidPodUID", err)
	}
	// A UID carrying SBPL syntax still yields only hex: it never reaches the profile.
	c, err := PosixSemPrefix(`x")) (allow default) ;`)
	if err != nil || !posixSemPrefixRE.MatchString(c) {
		t.Errorf("hostile uid: prefix %q err %v", c, err)
	}
}

// TestPosixSemStanzaRefusesMalformedPrefix pins the splice guard: only the
// validated shape is rendered into SBPL.
func TestPosixSemStanzaRefusesMalformedPrefix(t *testing.T) {
	for _, p := range []string{
		"",
		"/",
		"/k3sm.",
		"/k3sm.0123abcd",        // no separator
		"k3sm.0123abcd.",        // no leading slash: matches nothing
		"/k3sm.0123ABCD.",       // uppercase
		"/k3sm.0123abcde.",      // too long
		"/k3sm.0123abc\")) (a.", // breaks out of the literal
	} {
		if _, err := PosixSemStanza(p); !errors.Is(err, errPosixSemPrefixShape) {
			t.Errorf("PosixSemStanza(%q): err = %v, want errPosixSemPrefixShape", p, err)
		}
	}
	got, err := PosixSemStanza("/k3sm.0123abcd.")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `(allow ipc-posix-sem (ipc-posix-name-prefix "/k3sm.0123abcd."))`) {
		t.Errorf("stanza:\n%s", got)
	}
}

// TestGenerateSemaphoreGrant pins when Generate emits the grant: exactly one
// prefix-filtered allow when a pod UID is given and the grammar compiles, none
// without a UID, none when the host grammar rejects it, and never a bare allow.
func TestGenerateSemaphoreGrant(t *testing.T) {
	sp := &runtimev1.SandboxProfile{DataVolumePath: "/var/lib/k3sm/pods/p/rootfs"}
	const uid = "8f3c1d2e-0000-4000-8000-000000000001"
	prefix, _ := PosixSemPrefix(uid)
	want := `(allow ipc-posix-sem (ipc-posix-name-prefix "` + prefix + `"))`

	saved := posixSemGrammarAccepted
	t.Cleanup(func() { posixSemGrammarAccepted = saved })

	cases := []struct {
		name    string
		uid     string
		grammar bool
		grant   bool
	}{
		{"uid-and-grammar", uid, true, true},
		{"no-uid", "", true, false},
		{"grammar-rejected", uid, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			posixSemGrammarAccepted = func() bool { return tc.grammar }
			prof, err := Generate(sp, GenerateOptions{PodUID: tc.uid})
			if err != nil {
				t.Fatal(err)
			}
			rules := ruleLines(prof)
			if got := strings.Count(rules, "ipc-posix-sem"); got != map[bool]int{true: 1, false: 0}[tc.grant] {
				t.Fatalf("ipc-posix-sem rules = %d, grant=%v:\n%s", got, tc.grant, prof)
			}
			if tc.grant && !strings.Contains(rules, want) {
				t.Errorf("missing %s", want)
			}
			if strings.Contains(rules, "(allow ipc-posix-sem)") {
				t.Error("bare (allow ipc-posix-sem) emitted")
			}
			if err := Validate(prof); err != nil {
				t.Error(err)
			}
		})
	}
}
