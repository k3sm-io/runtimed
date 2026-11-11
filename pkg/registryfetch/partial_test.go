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

package registryfetch

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureDirCreatesPrivateDir(t *testing.T) {
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	if err := s.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(s.Dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir = %v %v, want a 0700 directory", fi, err)
	}
}

func TestEnsureDirRefusesNonPrivate(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, dir string){
		"file": func(t *testing.T, dir string) {
			if err := os.WriteFile(dir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), "elsewhere")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable": func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o770); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "partial")
			setup(t, dir)
			err := (&PartialStore{Dir: dir}).EnsureDir()
			var pe *PartialDirError
			if !errors.Is(err, ErrPartialDir) || !errors.As(err, &pe) || pe.Detail == "" {
				t.Fatalf("err = %v, want ErrPartialDir", err)
			}
		})
	}
}

func noTransfer(t *testing.T) func(*os.File, int64) error {
	return func(*os.File, int64) error {
		t.Error("Transfer ran for a complete partial")
		return nil
	}
}

func TestResumeRefusesSymlinkedPartial(t *testing.T) {
	data, digest := blobData(100)
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	if err := s.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.path(digest)); err != nil {
		t.Fatal(err)
	}
	var got []byte
	err := s.Resume(Fill{Digest: digest, Size: 100, Transfer: noTransfer(t), Commit: verifyCommit(digest, 100, &got)})
	if err == nil {
		t.Fatal("Resume followed a symlinked partial")
	}
}

func TestResumeRemovesPoisonedPartial(t *testing.T) {
	data, digest := blobData(100)
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	if err := s.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(data)
	bad[0] ^= 1
	if err := os.WriteFile(s.path(digest), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	errPoison := errors.New("digest mismatch")
	var got []byte
	commit := verifyCommit(digest, 100, &got)
	err := s.Resume(Fill{
		Digest: digest, Size: 100, Transfer: noTransfer(t),
		Commit: func(replay func(io.Writer) error) error {
			if err := commit(replay); err != nil {
				return errors.Join(errPoison, err)
			}
			return nil
		},
		Poisoned: func(err error) bool { return errors.Is(err, errPoison) },
	})
	if !errors.Is(err, errPoison) {
		t.Fatalf("err = %v, want the commit error", err)
	}
	if _, err := os.Lstat(s.path(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("poisoned partial survived: %v", err)
	}
}

func TestResumeKeepsPartialOnUnpoisonedCommitError(t *testing.T) {
	data, digest := blobData(100)
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	if err := s.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(digest), data, 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.Resume(Fill{
		Digest: digest, Size: 100, Transfer: noTransfer(t),
		Commit:   func(func(io.Writer) error) error { return errors.New("disk full") },
		Poisoned: func(error) bool { return false },
	})
	if err == nil {
		t.Fatal("commit error swallowed")
	}
	if got := s.Bytes(digest, 100); got != 100 {
		t.Fatalf("partial holds %d bytes, want it kept at 100", got)
	}
}

func TestResumeRestartsOverlongPartial(t *testing.T) {
	data, digest := blobData(100)
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	if err := s.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(digest), append(bytes.Clone(data), 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := s.Bytes(digest, 100); got != 0 {
		t.Fatalf("overlong partial counts %d bytes, want 0", got)
	}
	var from int64 = -1
	var got []byte
	err := s.Resume(Fill{
		Digest: digest, Size: 100,
		Transfer: func(f *os.File, have int64) error {
			from = have
			_, err := f.WriteAt(data, 0)
			return err
		},
		Commit: verifyCommit(digest, 100, &got),
	})
	if err != nil || from != 0 {
		t.Fatalf("Resume = %v, transfer from %d; want success from 0", err, from)
	}
}

func TestResumeRefusesUnsafeDigest(t *testing.T) {
	s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
	err := s.Resume(Fill{Digest: "sha256:../../etc/passwd", Size: 1})
	if !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("err = %v, want ErrInvalidDigest", err)
	}
	if got := s.Bytes("sha256:../x", 1); got != 0 {
		t.Fatalf("Bytes of an unsafe digest = %d, want 0", got)
	}
}
