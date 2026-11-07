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
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

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

// setUchg sets UF_IMMUTABLE on path, skipping the test where the owner may
// not, and clears it at cleanup so the temp dir can be removed.
func setUchg(t *testing.T, path string) {
	t.Helper()
	if err := unix.Chflags(path, unix.UF_IMMUTABLE); err != nil {
		t.Skipf("chflags uchg not permitted: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(path, 0) })
}

// addACL gives path an ACL entry, skipping the test where chmod +a fails.
func addACL(t *testing.T, path string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
		t.Skipf("chmod +a not available: %v: %s", err, out)
	}
}

// TestCommitFromLocalImmutableSourceLeavesNoClone: a source carrying
// UF_IMMUTABLE hands its clone the flag; the clone is committed when it
// matches, and removed when it does not — never left undeletable.
func TestCommitFromLocalImmutableSourceLeavesNoClone(t *testing.T) {
	content := []byte("immutable layer")
	t.Run("matching", func(t *testing.T) {
		_, blob := commitFromHostileSource(t, content, func(p string) { setUchg(t, p) })
		var st unix.Stat_t
		if err := unix.Lstat(blob, &st); err != nil {
			t.Fatal(err)
		}
		if st.Flags != 0 {
			t.Errorf("blob flags = %#x, want 0", st.Flags)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		root := t.TempDir()
		cache, err := NewCache(filepath.Join(root, "cache"))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256Digest(content)
		src := writeStoreFile(t, root, "store-blob", []byte("immutable LAYER"))
		setUchg(t, src)
		store := &fakeLocalStore{files: map[string]string{digest: src}}
		wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
		if !errors.Is(err, ErrDigestMismatch) || wrote {
			t.Fatalf("CommitFromLocal = (%v, %v), want ErrDigestMismatch", wrote, err)
		}
		if temps := blobTemps(t, cache); len(temps) != 0 {
			t.Errorf("immutable clone left behind: %v", temps)
		}
	})
}

// TestCommitFromLocalSweepsStaleClones: a clone a crash left in the staging
// directory — even an immutable one — is removed by a later call once it is
// older than staleStageAge.
func TestCommitFromLocalSweepsStaleClones(t *testing.T) {
	root := t.TempDir()
	cache, err := NewCache(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(cache.Root(), localStageDir)
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	debris := filepath.Join(stage, ".blob-crashed")
	if err := os.WriteFile(debris, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setUchg(t, debris)
	fresh := filepath.Join(stage, ".blob-inflight")
	if err := os.WriteFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	content := []byte("layer")
	digest := sha256Digest(content)
	store := &fakeLocalStore{files: map[string]string{digest: writeStoreFile(t, root, "store-blob", content)}}

	// Not yet stale: both survive.
	if _, err := cache.CommitFromLocal(digest, int64(len(content)), store); err != nil {
		t.Fatalf("CommitFromLocal: %v", err)
	}
	for _, p := range []string{debris, fresh} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s swept before it was stale: %v", p, err)
		}
	}

	// Past the age: the sweep on the next call removes both.
	cache.now = func() time.Time { return time.Now().Add(2 * staleStageAge) }
	other := []byte("another layer")
	otherDigest := sha256Digest(other)
	store.files[otherDigest] = writeStoreFile(t, root, "store-blob-2", other)
	if _, err := cache.CommitFromLocal(otherDigest, int64(len(other)), store); err != nil {
		t.Fatalf("CommitFromLocal: %v", err)
	}
	if temps := blobTemps(t, cache); len(temps) != 0 {
		t.Errorf("stale clones not swept: %v", temps)
	}
}

// TestCommitFromLocalACL: a staging directory carrying an ACL is refused, and
// a source's ACL never reaches the committed blob (the clone is made without
// CLONE_ACL, and a clone that carried one would be refused).
func TestCommitFromLocalACL(t *testing.T) {
	content := []byte("acl layer")
	digest := sha256Digest(content)

	t.Run("probe sees an ACL", func(t *testing.T) {
		p := writeStoreFile(t, t.TempDir(), "f", content)
		addACL(t, p)
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if got, err := hasACL(f); err != nil || !got {
			t.Fatalf("hasACL = (%v, %v), want (true, nil)", got, err)
		}
	})

	t.Run("staging dir with an ACL is refused", func(t *testing.T) {
		root := t.TempDir()
		cache, err := NewCache(filepath.Join(root, "cache"))
		if err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(cache.Root(), localStageDir)
		if err := os.Mkdir(stage, 0o700); err != nil {
			t.Fatal(err)
		}
		addACL(t, stage)
		store := &fakeLocalStore{files: map[string]string{digest: writeStoreFile(t, root, "store-blob", content)}}
		wrote, err := cache.CommitFromLocal(digest, int64(len(content)), store)
		if err == nil || wrote || errors.Is(err, ErrBlobNotLocal) {
			t.Fatalf("CommitFromLocal = (%v, %v), want a refusal that is not ErrBlobNotLocal", wrote, err)
		}
		if cache.Has(digest) {
			t.Error("blob committed through a staging dir with an ACL")
		}
	})

	t.Run("source ACL does not reach the blob", func(t *testing.T) {
		_, blob := commitFromHostileSource(t, content, func(p string) { addACL(t, p) })
		f, err := os.Open(blob)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if got, err := hasACL(f); err != nil || got {
			t.Fatalf("committed blob hasACL = (%v, %v), want (false, nil)", got, err)
		}
	})
}

// preopenedSource hands out a file it opened before its mode was changed.
type preopenedSource struct {
	digest string
	f      *os.File
	size   int64
}

func (s *preopenedSource) OpenBlob(digest string) (*os.File, int64, error) {
	if digest != s.digest || s.f == nil {
		return nil, 0, ErrBlobNotLocal
	}
	f := s.f
	s.f = nil
	return f, s.size, nil
}

// TestCommitFromLocalUnreadableCloneFallsBack: a source whose file is mode
// 0000 or 0200 cannot be cloned or read by this process; that is
// ErrBlobNotLocal (pull normally), and the clone is removed.
func TestCommitFromLocalUnreadableCloneFallsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any mode")
	}
	content := []byte("unreadable layer")
	digest := sha256Digest(content)
	for _, mode := range []os.FileMode{0o000, 0o200} {
		t.Run(mode.String(), func(t *testing.T) {
			root := t.TempDir()
			cache, err := NewCache(filepath.Join(root, "cache"))
			if err != nil {
				t.Fatal(err)
			}
			p := writeStoreFile(t, root, "store-blob", content)
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, mode); err != nil {
				t.Fatal(err)
			}
			src := &preopenedSource{digest: digest, f: f, size: int64(len(content))}
			wrote, err := cache.CommitFromLocal(digest, int64(len(content)), src)
			if !errors.Is(err, ErrBlobNotLocal) || wrote {
				t.Fatalf("CommitFromLocal = (%v, %v), want ErrBlobNotLocal", wrote, err)
			}
			if cache.Has(digest) {
				t.Error("blob committed from an unreadable clone")
			}
			if temps := blobTemps(t, cache); len(temps) != 0 {
				t.Errorf("unreadable clone left behind: %v", temps)
			}
		})
	}
}
