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
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func testDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func TestClaim(t *testing.T) {
	a, b := testDigest('a'), testDigest('b')
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, s *PartialStore)
	}{
		{"second claim refused as claimed", func(t *testing.T, s *PartialStore) {
			rel, err := s.Claim(a)
			if err != nil {
				t.Fatalf("first claim refused: %v", err)
			}
			defer rel()
			rel2, err := s.Claim(a)
			rel2()
			if !errors.Is(err, ErrPartialClaimed) || errors.Is(err, ErrInvalidDigest) {
				t.Fatalf("second claim of a held digest = %v, want ErrPartialClaimed only", err)
			}
		}},
		{"other digest free", func(t *testing.T, s *PartialStore) {
			rel, _ := s.Claim(a)
			defer rel()
			relB, err := s.Claim(b)
			if err != nil {
				t.Fatalf("claim of an unrelated digest refused: %v", err)
			}
			relB()
		}},
		{"release frees and is idempotent", func(t *testing.T, s *PartialStore) {
			rel, _ := s.Claim(a)
			rel()
			rel2, err := s.Claim(a)
			if err != nil {
				t.Fatalf("claim after release refused: %v", err)
			}
			rel() // a stale release must not end the new claim
			if _, err := s.Claim(a); !errors.Is(err, ErrPartialClaimed) {
				t.Fatalf("repeated release ended a later claim: %v", err)
			}
			rel2()
		}},
		{"invalid digest refused as invalid", func(t *testing.T, s *PartialStore) {
			for _, d := range []string{"sha256:../x", "", testDigest('A'), "sha512:" + strings.Repeat("a", 64)} {
				rel, err := s.Claim(d)
				rel()
				if !errors.Is(err, ErrInvalidDigest) || errors.Is(err, ErrPartialClaimed) {
					t.Fatalf("Claim(%q) = %v, want ErrInvalidDigest only", d, err)
				}
			}
		}},
		{"contention grants exactly one", func(t *testing.T, s *PartialStore) {
			for range 50 {
				var wins atomic.Int32
				var wg sync.WaitGroup
				start := make(chan struct{})
				rels := make(chan func(), 16)
				for range 16 {
					wg.Go(func() {
						<-start
						rel, err := s.Claim(a)
						switch {
						case err == nil:
							wins.Add(1)
							rels <- rel
						case !errors.Is(err, ErrPartialClaimed):
							t.Errorf("contended claim = %v, want ErrPartialClaimed", err)
						}
					})
				}
				close(start)
				wg.Wait()
				close(rels)
				if n := wins.Load(); n != 1 {
					t.Fatalf("%d concurrent claims granted, want 1", n)
				}
				for rel := range rels {
					rel()
					rel()
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, &PartialStore{Dir: t.TempDir()}) })
	}
}

func TestAdmit(t *testing.T) {
	own, other := testDigest('a'), testDigest('b')
	for _, tc := range []struct {
		name    string
		max     int64
		want    int64
		setup   func(t *testing.T, s *PartialStore)
		wantErr error
	}{
		{name: "no cap", max: 0, want: 1 << 40},
		{name: "empty at boundary", max: 100, want: 100},
		{name: "empty over boundary", max: 100, want: 101, wantErr: ErrPartialBudget},
		{name: "others at boundary", max: 100, want: 40, setup: writeSized(other, 60)},
		{name: "others over boundary", max: 100, want: 41, setup: writeSized(other, 60), wantErr: ErrPartialBudget},
		{name: "own size not counted", max: 100, want: 100, setup: writeSized(own, 90)},
		{name: "foreign regular file counted", max: 100, want: 50, setup: writeNamed("stray", 51), wantErr: ErrPartialBudget},
		{name: "symlink not followed", max: 100, want: 100, setup: func(t *testing.T, s *PartialStore) {
			big := filepath.Join(t.TempDir(), "big")
			if err := os.WriteFile(big, make([]byte, 1000), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(big, s.path(other)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "negative want", max: 100, want: -1, wantErr: ErrPartialBudget},
		{name: "want MaxInt64 wraps with one other byte", max: 100, want: math.MaxInt64, setup: writeSized(other, 1), wantErr: ErrPartialBudget},
		{name: "want MaxInt64 alone", max: 100, want: math.MaxInt64, wantErr: ErrPartialBudget},
		{name: "want just over cap", max: 100, want: 101, setup: writeSized(own, 10), wantErr: ErrPartialBudget},
		{name: "sizes sum exactly to cap", max: 100, want: 30, setup: func(t *testing.T, s *PartialStore) {
			writeSized(other, 50)(t, s)
			writeNamed("stray", 20)(t, s)
		}},
		{name: "sizes sum one past cap", max: 100, want: 31, setup: func(t *testing.T, s *PartialStore) {
			writeSized(other, 50)(t, s)
			writeNamed("stray", 20)(t, s)
		}, wantErr: ErrPartialBudget},
		{name: "cap MaxInt64 with others", max: math.MaxInt64, want: math.MaxInt64, setup: writeSized(other, 1), wantErr: ErrPartialBudget},
		{name: "missing dir", max: 100, want: 100, setup: func(t *testing.T, s *PartialStore) { s.Dir = filepath.Join(s.Dir, "absent") }},
		{name: "negative cap", max: -1, want: 0, wantErr: ErrPartialCap},
		{name: "cap MinInt64", max: math.MinInt64, want: 1, wantErr: ErrPartialCap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &PartialStore{Dir: t.TempDir(), MaxBytes: tc.max}
			if tc.setup != nil {
				tc.setup(t, s)
			}
			err := s.Admit(own, tc.want)
			if tc.wantErr == nil && err != nil || tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Admit(%d) under %d = %v, want %v", tc.want, tc.max, err, tc.wantErr)
			}
		})
	}
	if err := (&PartialStore{Dir: t.TempDir(), MaxBytes: 1}).Admit("sha256:../x", 0); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("Admit of an unsafe digest = %v, want ErrInvalidDigest", err)
	}
}

func writeSized(digest string, n int) func(*testing.T, *PartialStore) {
	return func(t *testing.T, s *PartialStore) { writeNamed(filepath.Base(s.path(digest)), n)(t, s) }
}

func writeNamed(name string, n int) func(*testing.T, *PartialStore) {
	return func(t *testing.T, s *PartialStore) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(s.Dir, name), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSweep(t *testing.T) {
	now := time.Now()
	old, young := now.Add(-2*time.Hour), now.Add(-time.Minute)
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(victim, old, old); err != nil {
		t.Fatal(err)
	}
	type entry struct {
		name    string
		kind    string // file, symlink, dir
		mtime   time.Time
		claimed bool
		gone    bool
	}
	name := func(c byte) string { return "sha256-" + strings.Repeat(string(c), 64) + ".partial" }
	entries := []entry{
		{name: name('a'), kind: "file", mtime: old, gone: true},
		{name: name('b'), kind: "file", mtime: young},
		{name: name('c'), kind: "file", mtime: old, claimed: true},
		{name: name('d'), kind: "symlink", mtime: old},
		{name: name('e'), kind: "dir", mtime: old},
		{name: "sha256-" + strings.Repeat("f", 63) + ".partial", kind: "file", mtime: old},
		{name: "stray.txt", kind: "file", mtime: old},
		{name: name('F'), kind: "file", mtime: old}, // uppercase hex: not the grammar
		{name: name('g'), kind: "file", mtime: old}, // not hex
		{name: name('9'), kind: "file", mtime: old, gone: true},
	}
	s := &PartialStore{Dir: t.TempDir()}
	for _, e := range entries {
		p := filepath.Join(s.Dir, e.name)
		switch e.kind {
		case "file":
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(p, e.mtime, e.mtime); err != nil {
				t.Fatal(err)
			}
		case "symlink":
			if err := os.Symlink(victim, p); err != nil {
				t.Fatal(err)
			}
		case "dir":
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(p, e.mtime, e.mtime); err != nil {
				t.Fatal(err)
			}
		}
		if e.claimed {
			digest := strings.Replace(strings.TrimSuffix(e.name, ".partial"), "-", ":", 1)
			rel, err := s.Claim(digest)
			if err != nil {
				t.Fatal(err)
			}
			defer rel()
		}
	}
	removed, err := s.Sweep(now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoved := 0
	for _, e := range entries {
		t.Run(e.name, func(t *testing.T) {
			_, err := os.Lstat(filepath.Join(s.Dir, e.name))
			if gone := errors.Is(err, os.ErrNotExist); gone != e.gone {
				t.Fatalf("%s %s (claimed %v): removed = %v, want %v", e.kind, e.name, e.claimed, gone, e.gone)
			}
		})
		if e.gone {
			wantRemoved++
		}
	}
	if removed != wantRemoved {
		t.Fatalf("Sweep removed %d, want %d", removed, wantRemoved)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "keep" {
		t.Fatalf("symlink target touched: %q %v", b, err)
	}
}

func TestSweepRefusesSymlinkedDir(t *testing.T) {
	real := t.TempDir()
	p := filepath.Join(real, "sha256-"+strings.Repeat("a", 64)+".partial")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "partial")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	removed, err := (&PartialStore{Dir: link}).Sweep(time.Now(), time.Hour)
	if !errors.Is(err, ErrPartialDir) || removed != 0 {
		t.Fatalf("Sweep through a symlinked dir = %d, %v; want 0, ErrPartialDir", removed, err)
	}
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("partial behind a symlinked dir removed: %v", err)
	}
	if n, err := (&PartialStore{Dir: filepath.Join(real, "absent")}).Sweep(time.Now(), time.Hour); n != 0 || err != nil {
		t.Fatalf("Sweep of a missing dir = %d, %v; want 0, nil", n, err)
	}
}

// TestResumeChecksLengthAfterTransfer: Resume hands Transfer a file positioned
// at have and, after a nil Transfer, refuses a file of the wrong length: a
// short one is kept for the next Resume, a long one is cut to Size.
func TestResumeChecksLengthAfterTransfer(t *testing.T) {
	data, digest := blobData(100)
	for _, tc := range []struct {
		name     string
		have     int    // bytes already in the partial
		write    []byte // what Transfer writes at the current position
		wantErr  bool   // Resume fails
		wantSize int64  // file length afterwards (-1: removed)
		wantPos  int64  // the position Transfer saw
	}{
		{name: "exact", have: 40, write: data[40:], wantSize: -1, wantPos: 40},
		{name: "short", have: 40, write: data[40:90], wantErr: true, wantSize: 90, wantPos: 40},
		{name: "long", have: 40, write: append(bytes.Clone(data[40:]), "extra"...), wantErr: true, wantSize: 100, wantPos: 40},
		{name: "empty-start", have: 0, write: data, wantSize: -1, wantPos: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
			if err := s.EnsureDir(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.path(digest), data[:tc.have], 0o600); err != nil {
				t.Fatal(err)
			}
			pos := int64(-1)
			var got []byte
			err := s.Resume(Fill{
				Digest: digest, Size: 100,
				Transfer: func(f *os.File, have int64) error {
					// Move away first: Resume must not rely on where the
					// file was left by an earlier open.
					pos, _ = f.Seek(0, io.SeekCurrent)
					_, err := f.Write(tc.write)
					return err
				},
				Commit:   verifyCommit(digest, 100, &got),
				Poisoned: func(error) bool { return false },
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resume = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrPartialLength) {
				t.Fatalf("err = %v, want ErrPartialLength", err)
			}
			if pos != tc.wantPos {
				t.Fatalf("Transfer saw position %d, want %d", pos, tc.wantPos)
			}
			fi, statErr := os.Lstat(s.path(digest))
			switch {
			case tc.wantSize < 0 && !errors.Is(statErr, os.ErrNotExist):
				t.Fatalf("partial still present after commit: %v", statErr)
			case tc.wantSize >= 0 && (statErr != nil || fi.Size() != tc.wantSize):
				t.Fatalf("partial = %v %v, want %d bytes", fi, statErr, tc.wantSize)
			}
			if !tc.wantErr && !bytes.Equal(got, data) {
				t.Fatal("committed bytes differ from the blob")
			}
		})
	}
}

// TestResumeRangeAnsweredWith200: with have > 0 the server answers the Range
// with the whole blob. Transfer is the one that learns start, so it truncates;
// one that appends anyway ends as prefix+blob, which Resume refuses and cuts
// to Size, never committing it.
func TestResumeRangeAnsweredWith200(t *testing.T) {
	const size, have = 1000, 300
	data, digest := blobData(size)
	for _, tc := range []struct {
		name     string
		truncate bool
		wantErr  bool
	}{
		{name: "transfer-truncates", truncate: true},
		{name: "transfer-appends", truncate: false, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg, ref := serve(t, &fakeRegistry{data: data, rangeStatus: http.StatusOK})
			s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
			if err := s.EnsureDir(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.path(digest), data[:have], 0o600); err != nil {
				t.Fatal(err)
			}
			committed := false
			var got []byte
			commit := verifyCommit(digest, size, &got)
			err := s.Resume(Fill{
				Digest: digest, Size: size,
				Transfer: func(f *os.File, have int64) error {
					body, start, err := reg.Blob(context.Background(), ref, nil, digest, size, have)
					if err != nil {
						return err
					}
					defer body.Close()
					if start != have && tc.truncate {
						if err := f.Truncate(start); err != nil {
							return err
						}
						if _, err := f.Seek(start, io.SeekStart); err != nil {
							return err
						}
					}
					_, err = io.Copy(f, body)
					return err
				},
				Commit: func(replay func(io.Writer) error) error {
					committed = true
					return commit(replay)
				},
				Poisoned: func(error) bool { return true },
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resume = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				if committed || !errors.Is(err, ErrPartialLength) {
					t.Fatalf("err = %v committed=%v, want ErrPartialLength before Commit", err, committed)
				}
				if fi, err := os.Lstat(s.path(digest)); err != nil || fi.Size() > size {
					t.Fatalf("partial = %v %v, want at most %d bytes", fi, err, size)
				}
				return
			}
			if !bytes.Equal(got, data) {
				t.Fatal("committed bytes are not exactly the blob")
			}
		})
	}
}

// TestResumeNilPoisonedRemovesPartial: with no Poisoned callback every Commit
// error condemns the partial.
func TestResumeNilPoisonedRemovesPartial(t *testing.T) {
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
		Commit: func(func(io.Writer) error) error { return errors.New("any failure") },
	})
	if err == nil {
		t.Fatal("commit error swallowed")
	}
	if _, err := os.Lstat(s.path(digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial survived a commit error with nil Poisoned: %v", err)
	}
}

// TestEnsureDirRequiresOwner: Dir must be owned by the effective uid. Tests
// cannot chown, so the comparison is driven through the effectiveUID seam.
func TestEnsureDirRequiresOwner(t *testing.T) {
	euid := os.Geteuid()
	for _, tc := range []struct {
		name    string
		uid     int
		existed bool
		wantErr bool
	}{
		{name: "owner-existing", uid: euid, existed: true},
		{name: "owner-created", uid: euid},
		{name: "other-existing", uid: euid + 1, existed: true, wantErr: true},
		{name: "other-created", uid: euid + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func(old func() int) { effectiveUID = old }(effectiveUID)
			effectiveUID = func() int { return tc.uid }
			dir := filepath.Join(t.TempDir(), "partial")
			if tc.existed {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := (&PartialStore{Dir: dir}).EnsureDir()
			if (err != nil) != tc.wantErr {
				t.Fatalf("EnsureDir = %v, wantErr %v", err, tc.wantErr)
			}
			var pe *PartialDirError
			if tc.wantErr && (!errors.Is(err, ErrPartialDir) || !errors.As(err, &pe) || !strings.Contains(pe.Detail, "owned by uid")) {
				t.Fatalf("err = %v, want an owner ErrPartialDir", err)
			}
		})
	}
}

// TestResumeRefusesNonRegularPartial: a FIFO or a directory in the partial's
// place is refused, and promptly: opening a FIFO must not wait for a peer.
func TestResumeRefusesNonRegularPartial(t *testing.T) {
	_, digest := blobData(100)
	for name, plant := range map[string]func(path string) error{
		"fifo":      func(p string) error { return unix.Mkfifo(p, 0o600) },
		"directory": func(p string) error { return os.Mkdir(p, 0o700) },
	} {
		t.Run(name, func(t *testing.T) {
			s := &PartialStore{Dir: filepath.Join(t.TempDir(), "partial")}
			if err := s.EnsureDir(); err != nil {
				t.Fatal(err)
			}
			if err := plant(s.path(digest)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var got []byte
				done <- s.Resume(Fill{
					Digest: digest, Size: 100,
					Transfer: func(*os.File, int64) error { return errors.New("Transfer ran on a non-regular partial") },
					Commit:   verifyCommit(digest, 100, &got),
				})
			}()
			select {
			case err := <-done:
				if !errors.Is(err, ErrPartialFile) {
					t.Fatalf("err = %v, want ErrPartialFile", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Resume blocked on a non-regular partial")
			}
		})
	}
}
