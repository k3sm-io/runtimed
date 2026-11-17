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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// entrypointShape is one way an image can name its program: what the tree holds
// besides the real Mach-O at /python/bin/python3.13, and the name the image's
// ENTRYPOINT uses.
type entrypointShape struct {
	name  string
	argv0 string
	build func(t *testing.T, root string, macho []byte)
	// want is the root-relative file the resolution must reach; "" means the
	// shape is refused with wantErr.
	want    string
	wantErr error
}

func entrypointShapes() []entrypointShape {
	mkLink := func(target, at string) func(t *testing.T, root string, _ []byte) {
		return func(t *testing.T, root string, _ []byte) {
			t.Helper()
			p := filepath.Join(root, filepath.FromSlash(at))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Only relative links: the native unpacker refuses an absolute link target
	// (symlinkTargetContained), because a pod has no chroot and the link would
	// resolve on the host. TestNativeUnpackRefusesAnAbsoluteEntrypointLink pins it.
	return []entrypointShape{
		{name: "regular file", argv0: "python/bin/python3.13", build: func(*testing.T, string, []byte) {}, want: "python/bin/python3.13"},
		{name: "relative in-root link", argv0: "python/bin/python3", build: mkLink("python3.13", "python/bin/python3"), want: "python/bin/python3.13"},
		{name: "relative in-root directory link", argv0: "usr/local/bin/python3.13", build: mkLink("../../python/bin", "usr/local/bin"), want: "python/bin/python3.13"},
		{name: "/bin/sh the image carries", argv0: "bin/sh", build: func(t *testing.T, root string, macho []byte) {
			t.Helper()
			if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "bin", "sh"), macho, 0o755); err != nil {
				t.Fatal(err)
			}
		}, want: "bin/sh"},
		{name: "/bin/sh the image lacks", argv0: "bin/sh", build: func(*testing.T, string, []byte) {}, wantErr: ErrEntrypointNotInImage},
		{name: "dangling link", argv0: "python/bin/python3", build: mkLink("python3.99", "python/bin/python3"), wantErr: ErrEntrypointNotInImage},
		{name: "link that leaves the root", argv0: "python/bin/python3", build: mkLink("../../../../../../../../bin/ls", "python/bin/python3"), wantErr: ErrSignTarget},
	}
}

// newEntrypointRoot lays out an image rootfs holding macho at
// /python/bin/python3.13 plus the shape's own entries.
func newEntrypointRoot(t *testing.T, s entrypointShape, macho []byte) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(root, "python", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "python", "bin", "python3.13"), macho, 0o755); err != nil {
		t.Fatal(err)
	}
	s.build(t, root, macho)
	return root
}

// TestNativeUnpackRefusesAnAbsoluteEntrypointLink pins why no entrypoint shape
// above is an absolute link: the native layer applier refuses one at unpack,
// with a message naming the link and its target, before any signing. A
// relative link to the same file is admitted. Under the Linux dialect the guest
// chroots into the tree, so there it is admitted.
func TestNativeUnpackRefusesAnAbsoluteEntrypointLink(t *testing.T) {
	err := symlinkTargetContained("python/bin/python3", "/python/bin/python3.13", false)
	if !errors.Is(err, ErrLayerEscapes) || !strings.Contains(err.Error(), "targets the absolute path") {
		t.Errorf("native absolute link: err = %v, want ErrLayerEscapes naming the absolute target", err)
	}
	if err := symlinkTargetContained("python/bin/python3", "python3.13", false); err != nil {
		t.Errorf("native relative link: %v", err)
	}
	if err := symlinkTargetContained("python/bin/python3", "/python/bin/python3.13", true); err != nil {
		t.Errorf("linux absolute link: %v", err)
	}
}

// TestSignByReplaceSaysWhenTheEntrypointIsNotInTheImage runs every entrypoint
// shape through signByReplace with a stub signer, so the split between "not in
// the image" and every other refusal is pinned without codesign: an absent name
// and a dangling link carry ErrEntrypointNotInImage, a chain that leaves the
// root carries ErrSignTarget alone, and every admitted shape signs the regular
// in-image file the name reaches.
func TestSignByReplaceSaysWhenTheEntrypointIsNotInTheImage(t *testing.T) {
	for _, s := range entrypointShapes() {
		t.Run(s.name, func(t *testing.T) {
			root := newEntrypointRoot(t, s, []byte("not a Mach-O"))
			staging := filepath.Join(filepath.Dir(root), "ingest", "sign")
			if err := os.MkdirAll(staging, 0o700); err != nil {
				t.Fatal(err)
			}
			var signed []string
			sign := func(_ context.Context, p, _ string) error { signed = append(signed, p); return nil }
			var resolved string
			err := signByReplace(context.Background(), staging, root, filepath.Join(root, filepath.FromSlash(s.argv0)), sign,
				func(r string) { resolved = r })
			if s.wantErr != nil {
				if !errors.Is(err, s.wantErr) {
					t.Fatalf("err = %v, want %v", err, s.wantErr)
				}
				if notIn := errors.Is(err, ErrEntrypointNotInImage); notIn != (s.wantErr == ErrEntrypointNotInImage) {
					t.Errorf("ErrEntrypointNotInImage = %v for %v", notIn, err)
				}
				if len(signed) != 0 {
					t.Errorf("signed %v on a refusal", signed)
				}
				return
			}
			if err != nil {
				t.Fatalf("signByReplace: %v", err)
			}
			if want := filepath.Join(root, filepath.FromSlash(s.want)); resolved != want {
				t.Errorf("resolved %s, want the in-image file %s", resolved, want)
			}
			if len(signed) != 1 {
				t.Errorf("signed %v, want one staged copy", signed)
			}
		})
	}
}
