//go:build darwin

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
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// commitFromHostileSource commits content from a store file prepared by
// prepare (which may change its mode, flags or xattrs) and returns the cache
// and the committed blob's path.
func commitFromHostileSource(t *testing.T, content []byte, prepare func(path string)) (*Cache, string) {
	t.Helper()
	root := t.TempDir()
	cache, err := NewCache(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Digest(content)
	srcPath := writeStoreFile(t, root, "store-blob", content)
	prepare(srcPath)
	t.Cleanup(func() { _ = unix.Chflags(srcPath, 0) })
	store := &fakeLocalStore{files: map[string]string{digest: srcPath}}
	wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
	if err != nil || !wrote {
		t.Fatalf("CommitFromLocal = (%v, %v), want (true, nil)", wrote, err)
	}
	p, err := cache.BlobPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	if temps := blobTemps(t, cache); len(temps) != 0 {
		t.Errorf("temp clones left behind: %v", temps)
	}
	return cache, p
}

// TestCommitFromLocalHostileSourceAttributes: whatever mode, flags or xattrs
// the source's owner puts on its file, the committed blob is a private 0600
// file owned by this process with no flags and no xattrs, made in a 0700
// staging directory.
func TestCommitFromLocalHostileSourceAttributes(t *testing.T) {
	content := []byte("layer bytes the source's owner dressed up")
	cases := []struct {
		name    string
		prepare func(t *testing.T, path string)
	}{
		{"world-writable source", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"source with a user xattr", func(t *testing.T, path string) {
			if err := unix.Setxattr(path, "user.planted", []byte("v"), 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"source with nodump flag", func(t *testing.T, path string) {
			if err := unix.Chflags(path, unix.UF_NODUMP); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, blob := commitFromHostileSource(t, content, func(p string) { tc.prepare(t, p) })

			var st unix.Stat_t
			if err := unix.Lstat(blob, &st); err != nil {
				t.Fatal(err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 {
				t.Errorf("blob mode = %o, want a regular 0600 file", st.Mode)
			}
			if int(st.Uid) != os.Geteuid() {
				t.Errorf("blob owner = %d, want euid %d", st.Uid, os.Geteuid())
			}
			if st.Flags != 0 {
				t.Errorf("blob flags = %#x, want 0", st.Flags)
			}
			if sz, err := unix.Listxattr(blob, nil); err != nil || sz != 0 {
				t.Errorf("blob xattr list size = %d (%v), want 0", sz, err)
			}

			fi, err := os.Lstat(filepath.Join(cache.Root(), localStageDir))
			if err != nil {
				t.Fatal(err)
			}
			if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Errorf("staging dir mode = %s, want drwx------", fi.Mode())
			}
			if uid := fi.Sys().(*syscall.Stat_t).Uid; int(uid) != os.Geteuid() {
				t.Errorf("staging dir owner = %d, want euid %d", uid, os.Geteuid())
			}
		})
	}
}

// TestCommitFromLocalRefusesUnsafeStagingDir: a staging directory that is a
// symlink or that others can traverse is refused, never used or repaired.
func TestCommitFromLocalRefusesUnsafeStagingDir(t *testing.T) {
	content := []byte("layer")
	cases := []struct {
		name  string
		plant func(t *testing.T, stage, elsewhere string)
	}{
		{"symlink", func(t *testing.T, stage, elsewhere string) {
			if err := os.Symlink(elsewhere, stage); err != nil {
				t.Fatal(err)
			}
		}},
		{"traversable", func(t *testing.T, stage, _ string) {
			if err := os.Mkdir(stage, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(stage, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cache, err := NewCache(filepath.Join(root, "cache"))
			if err != nil {
				t.Fatal(err)
			}
			elsewhere := filepath.Join(root, "elsewhere")
			if err := os.Mkdir(elsewhere, 0o700); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, filepath.Join(cache.Root(), localStageDir), elsewhere)
			digest := sha256Digest(content)
			store := &fakeLocalStore{files: map[string]string{digest: writeStoreFile(t, root, "store-blob", content)}}
			wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
			if err == nil || wrote || errors.Is(err, ErrBlobNotLocal) {
				t.Fatalf("CommitFromLocal = (%v, %v), want a refusal that is not ErrBlobNotLocal", wrote, err)
			}
			if cache.Has(digest) {
				t.Error("blob committed through an unsafe staging dir")
			}
		})
	}
}
