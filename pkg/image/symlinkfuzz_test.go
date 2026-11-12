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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz input bounds. They keep one iteration cheap enough for the fuzzer to
// explore, and are far above what any seed needs.
const (
	fuzzMaxEntries = 32
	fuzzMaxNameLen = 256
	// fuzzMaxLayers bounds the "--"-separated layers in one script.
	fuzzMaxLayers = 8
	// fuzzHopCap bounds the symlink expansions resolveFromTree performs for
	// one link. A chain longer than this is a loop (the kernel gives ELOOP at
	// 32 on darwin), so stopping there is not an escape.
	fuzzHopCap = 64
)

// FuzzSymlinkTargetContained checks the string half of the containment
// control against an independent, PESSIMISTIC model of resolution: every
// component the target descends into may be a link to the tree root, so after
// it the climb budget is zero. An accepted relative target must stay inside
// the tree under that model — which is exactly the guarantee that lets
// containment compose along a chain of links.
func FuzzSymlinkTargetContained(f *testing.F) {
	f.Add("a/b/l", "../..", false)
	f.Add("x/e", "../a/b/l/../..", false)
	f.Add("a/b/l/x/y", "../../../..", false)
	f.Add("usr/bin/sh", "../lib/busybox", false)
	f.Add("usr/bin/sh", "/bin/busybox", true)
	f.Add("a/l", "./..//x/", false)
	f.Fuzz(func(t *testing.T, rawName, target string, linux bool) {
		name, err := layerEntryPath(rawName)
		if err != nil {
			return
		}
		if symlinkTargetContained(name, target, linux) != nil {
			return
		}
		if path.IsAbs(target) {
			if !linux {
				t.Fatalf("native dialect accepted the absolute target %q for %q", target, name)
			}
			return
		}
		depth := pathDepth(path.Dir(name))
		for _, comp := range strings.Split(target, "/") {
			switch comp {
			case "", ".":
			case "..":
				depth--
				if depth < 0 {
					t.Fatalf("accepted %q -> %q, which can resolve above the tree", name, target)
				}
			default:
				depth = 0
			}
		}
	})
}

// FuzzApplyLayer applies a scripted layer and then resolves every symlink the
// tree holds against the tree itself, one component at a time, following each
// link it meets. The property: whatever the applier accepted, no link in the
// tree resolves above the tree root.
//
// The script is one entry per line: "L <name> <target>" for a symlink,
// "H <name> <target>" for a hardlink, "D <name>" for a directory, "F <name>"
// for a regular file, "W <name>" for a whiteout of name (the ".wh." marker
// beside it), "O <dir>" for an opaque marker in dir, and "--" to end one
// layer and start the next. Unknown lines are skipped. A refused entry ends
// that layer and the apply, exactly as in production; what was written before
// it stays and is checked. The oracle holds for every entry kind: hardlinks
// and markers create no symlink, and a sentinel directory beside the tree
// must survive every iteration unchanged, so a removal or write that escapes
// the tree is caught as well as a link that resolves above it.
func FuzzApplyLayer(f *testing.F) {
	f.Add("L a/b/l ../..\nL x/e ../a/b/l/../..", false)
	f.Add("L a/b/l ../..\nL a/b/l/x/y ../../../..", false)
	f.Add("D usr/lib\nL lib usr/lib\nF usr/lib/libc.so.6\nL lib/libc.so libc.so.6", false)
	f.Add("L bin usr/bin\nL usr/bin/sh /bin/busybox", true)
	f.Add("D d\nF d/c\n--\nL d e\n--\nL d/x ../..", true)
	f.Add("L d ../outside\nL e .\n--\nW e/d\nO e\nH h e/d", true)
	f.Fuzz(func(t *testing.T, script string, linux bool) {
		layers, ok := fuzzLayers(script)
		if !ok {
			return
		}
		base := t.TempDir()
		tree := filepath.Join(base, "rootfs")
		if err := os.Mkdir(tree, 0o755); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(base, "outside", "keep")
		if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sentinel, []byte("host"), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		policy := NativeUnpackPolicy()
		if linux {
			policy = LinuxUnpackPolicy()
		}
		a, err := NewLayerApplier(root, policy, ApplyLimits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, layer := range layers {
			if a.Apply(context.Background(), bytes.NewReader(layer)) != nil {
				break // a refusal is a valid outcome; the tree is checked either way
			}
		}
		if b, err := os.ReadFile(sentinel); err != nil || string(b) != "host" {
			t.Errorf("the sentinel outside the tree changed: %q (%v)\nscript:\n%s", b, err, script)
		}
		if ents, err := os.ReadDir(base); err != nil || len(ents) != 2 {
			t.Errorf("the tree's parent holds %d entries (%v), want rootfs and outside\nscript:\n%s", len(ents), err, script)
		}
		if ents, err := os.ReadDir(filepath.Dir(sentinel)); err != nil || len(ents) != 1 {
			t.Errorf("the sentinel directory holds %d entries (%v), want 1\nscript:\n%s", len(ents), err, script)
		}

		werr := filepath.WalkDir(tree, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink == 0 {
				return nil
			}
			rel, err := filepath.Rel(tree, p)
			if err != nil {
				return err
			}
			if why := resolveFromTree(tree, filepath.ToSlash(rel), linux); why != "" {
				t.Errorf("tree holds %s, which %s\nscript:\n%s", rel, why, script)
			}
			return nil
		})
		if werr != nil {
			t.Fatalf("walk tree: %v", werr)
		}
	})
}

// fuzzLayers renders a FuzzApplyLayer script as uncompressed tars, one per
// "--"-separated layer. fuzzMaxEntries bounds the entries across ALL layers
// and fuzzMaxLayers the layer count. It reports false for a script the tar
// writer cannot encode, which is a fuzz input to skip rather than a finding.
func fuzzLayers(script string) ([][]byte, bool) {
	var out [][]byte
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	flush := func() bool {
		if err := tw.Close(); err != nil {
			return false
		}
		out = append(out, append([]byte(nil), buf.Bytes()...))
		buf.Reset()
		tw = tar.NewWriter(&buf)
		return true
	}
	n := 0
	for _, line := range strings.Split(script, "\n") {
		f := strings.Fields(line)
		if len(f) == 1 && f[0] == "--" {
			if len(out)+1 >= fuzzMaxLayers {
				break
			}
			if !flush() {
				return nil, false
			}
			continue
		}
		if len(f) < 2 || len(f[1]) > fuzzMaxNameLen {
			continue
		}
		hdr := &tar.Header{Name: f[1], Mode: 0o755}
		switch {
		case f[0] == "L" && len(f) == 3 && len(f[2]) <= fuzzMaxNameLen:
			hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, f[2]
		case f[0] == "H" && len(f) == 3 && len(f[2]) <= fuzzMaxNameLen:
			hdr.Typeflag, hdr.Linkname = tar.TypeLink, f[2]
		case f[0] == "D" && len(f) == 2:
			hdr.Typeflag = tar.TypeDir
		case f[0] == "F" && len(f) == 2:
			hdr.Typeflag, hdr.Mode = tar.TypeReg, 0o644
		case f[0] == "W" && len(f) == 2:
			hdr.Typeflag, hdr.Mode = tar.TypeReg, 0o644
			hdr.Name = path.Join(path.Dir(f[1]), ".wh."+path.Base(f[1]))
		case f[0] == "O" && len(f) == 2:
			hdr.Typeflag, hdr.Mode = tar.TypeReg, 0o644
			hdr.Name = path.Join(f[1], ".wh..wh..opq")
		default:
			continue
		}
		if n++; n > fuzzMaxEntries {
			break
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, false
		}
	}
	if !flush() {
		return nil, false
	}
	return out, true
}

// resolveFromTree resolves the symlink at the tree-relative path rel the way
// the kernel does — component by component, following every link it meets
// before applying the ".." after it — and returns a description of the escape,
// or "" when resolution stays inside the tree (or stops: a missing component,
// a non-directory, or more than fuzzHopCap expansions).
//
// An absolute target resets to the tree root under the linux dialect (the
// guest chroots into this tree, so from then on a ".." at the root stays at
// the root, as the kernel clamps it) and is itself an escape natively, where
// no chroot exists. A missing component is resolved lexically from there on, so
// a ".." beyond it is still judged.
func resolveFromTree(tree, rel string, linux bool) string {
	var stack []string
	if dir := path.Dir(rel); dir != "." {
		stack = strings.Split(dir, "/")
	}
	queue := []string{path.Base(rel)}
	hops := 0
	missing, chrooted := false, false
	for len(queue) > 0 {
		comp := queue[0]
		queue = queue[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(stack) == 0 {
				if chrooted {
					continue
				}
				return "resolves above the tree root"
			}
			stack = stack[:len(stack)-1]
			continue
		}
		stack = append(stack, comp)
		if missing {
			continue
		}
		p := filepath.Join(append([]string{tree}, stack...)...)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			missing = true
			continue
		}
		if err != nil {
			return ""
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			if !fi.IsDir() && len(queue) > 0 {
				return ""
			}
			continue
		}
		if hops++; hops > fuzzHopCap {
			return ""
		}
		target, err := os.Readlink(p)
		if err != nil {
			return ""
		}
		stack = stack[:len(stack)-1]
		if path.IsAbs(target) {
			if !linux {
				return "follows the absolute target " + target + " with no chroot"
			}
			stack, chrooted = nil, true
		}
		queue = append(strings.Split(target, "/"), queue...)
	}
	return ""
}
