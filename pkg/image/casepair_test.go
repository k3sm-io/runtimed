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

package image

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// outsideDir is a directory outside any tree, holding one file whose bytes must
// survive whatever a layer does.
func outsideDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sentinel"), []byte("intact"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// assertOutsideIntact proves nothing was written into, or removed from, dir.
func assertOutsideIntact(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "sentinel" {
		t.Errorf("the outside directory holds %v, want only sentinel", ents)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "sentinel")); err != nil || string(got) != "intact" {
		t.Errorf("sentinel = %q, %v, want it intact", got, err)
	}
}

// TestCaseOnlyPairCannotEscapeOrOverwrite pins that admitting a case-only pair
// gave a layer no new write. It runs each attack under the case-sensitive verdict
// on whatever the temp directory is, so on a stock host it is also the worst case:
// the verdict says two names and the filesystem merges them, and the os.Root
// anchor and the entry checks are all that stand in the way.
func TestCaseOnlyPairCannotEscapeOrOverwrite(t *testing.T) {
	t.Run("a symlink cannot carry the other spelling's write out of the tree", func(t *testing.T) {
		outside := outsideDir(t)
		for _, target := range []string{outside, "../../../../../../../../../../../.." + outside} {
			// The apply may refuse or may build a real directory, depending on the
			// volume. What it may not do is write through the link.
			_, _, _ = applyIntoDest(t, true, []tarSpec{
				{name: "Out", typ: tar.TypeSymlink, link: target},
				{name: "out/pwn", mode: 0o644, data: "pwned"},
			})
			assertOutsideIntact(t, outside)
		}
	})

	t.Run("a hard link in one spelling cannot reach out of the tree", func(t *testing.T) {
		outside := outsideDir(t)
		_, _, err := applyIntoDest(t, true, []tarSpec{
			{name: "Link", typ: tar.TypeLink, link: "../../../../../../../../../../../.." + outside + "/sentinel"},
			{name: "link", mode: 0o644, data: "pwned"},
		})
		if err == nil {
			t.Error("a hard link out of the tree was admitted")
		}
		assertOutsideIntact(t, outside)
	})

	t.Run("a traversal in either spelling is still refused", func(t *testing.T) {
		for _, name := range []string{"Foo/../../x", "foo/../../x", "../FOO", "/../foo"} {
			if _, _, err := applyIntoDest(t, true, []tarSpec{{name: name, mode: 0o644, data: "x"}}); err == nil {
				t.Errorf("entry %q was admitted", name)
			}
		}
	})

	t.Run("a refusal lands before the second spelling writes a byte", func(t *testing.T) {
		tree, _, err := applyIntoDest(t, false, []tarSpec{
			{name: "Secret", mode: 0o644, data: "first"},
			{name: "secret", mode: 0o644, data: "second"},
		})
		if !errors.Is(err, ErrPathCollision) {
			t.Fatalf("apply error = %v, want ErrPathCollision", err)
		}
		if got, err := os.ReadFile(filepath.Join(tree, "Secret")); err != nil || string(got) != "first" {
			t.Errorf("Secret = %q, %v, want the first entry's bytes", got, err)
		}
	})

	t.Run("each spelling keeps its own ownership record and no setuid reaches the host", func(t *testing.T) {
		tree, a, err := applyIntoDest(t, true, []tarSpec{
			{name: "Tool", mode: 0o4755, data: "setuid"},
			{name: "tool", mode: 0o644, data: "plain"},
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		own := ownershipByPath(a.Ownership())
		if own["Tool"].Mode != 0o4755 || own["tool"].Mode != 0o644 {
			t.Errorf("recorded modes = %#o, %#o, want 04755, 0644", own["Tool"].Mode, own["tool"].Mode)
		}
		ents, err := os.ReadDir(tree)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSetuid != 0 {
				t.Errorf("%s carries a setuid bit on the host", e.Name())
			}
		}
	})

	t.Run("on a case-sensitive volume neither spelling touches the other", func(t *testing.T) {
		if !hostTempIsCaseSensitive(t) {
			t.Skip("needs a case-sensitive temp directory (TMPDIR on a case-sensitive volume); this one merges case")
		}
		outside := outsideDir(t)
		tree, _, err := applyIntoDest(t, true,
			[]tarSpec{
				{name: "Secret", mode: 0o644, data: "first"},
				{name: "secret", mode: 0o644, data: "second"},
				{name: "Keep", mode: 0o644, data: "keep"},
				{name: "Out", typ: tar.TypeSymlink, link: outside},
				{name: "out", mode: 0o644, data: "own file"},
			},
			[]tarSpec{{name: ".wh.keep", mode: 0o644}, {name: ".wh.SECRET", mode: 0o644}},
		)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		for p, want := range map[string]string{"Secret": "first", "secret": "second", "Keep": "keep", "out": "own file"} {
			if got, err := os.ReadFile(filepath.Join(tree, p)); err != nil || string(got) != want {
				t.Errorf("%s = %q, %v, want %q", p, got, err, want)
			}
		}
		assertOutsideIntact(t, outside)
	})
}
