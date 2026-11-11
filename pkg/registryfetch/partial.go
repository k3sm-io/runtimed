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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	// ErrPartialDir reports a partial dir that is not a private directory.
	ErrPartialDir = errors.New("registryfetch: partial dir is not private")
	// ErrInvalidDigest reports a digest that is not sha256:<64 hex>, which
	// would not be a path-safe file name.
	ErrInvalidDigest = errors.New("registryfetch: digest is not sha256:<64 hex>")
)

// PartialDirError is the error for a partial dir that is not a private
// directory. It matches ErrPartialDir under errors.Is; Detail names the dir
// and what is wrong with it.
type PartialDirError struct{ Detail string }

func (e *PartialDirError) Error() string { return ErrPartialDir.Error() + ": " + e.Detail }

// Is reports target == ErrPartialDir.
func (e *PartialDirError) Is(target error) bool { return target == ErrPartialDir }

var sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// PartialStore keeps resumable partial blobs, one file per digest, in Dir.
// The caller makes sure one digest's partial has one writer at a time.
type PartialStore struct {
	// Dir holds the partials. EnsureDir creates it 0700 when absent.
	Dir string
	// Log receives the warning for a committed partial that would not go
	// away. Nil discards it.
	Log *slog.Logger
}

// path is where the partial of digest lives. digest has passed the sha256
// pattern, so the name is a fixed, path-safe token.
func (s *PartialStore) path(digest string) string {
	return filepath.Join(s.Dir, strings.Replace(digest, ":", "-", 1)+".partial")
}

// EnsureDir creates Dir (0700) when absent and refuses one that is not a
// directory (a file, a symlink planted in its place) or is writable by group
// or other: a partial dir another principal can write lets it choose the
// bytes a resume continues from.
func (s *PartialStore) EnsureDir() error {
	dir := s.Dir
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create partial dir: %w", err)
		}
		fi, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("stat partial dir: %w", err)
	}
	if !fi.IsDir() {
		return &PartialDirError{Detail: fmt.Sprintf("%s is not a directory (mode %v)", dir, fi.Mode().Type())}
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return &PartialDirError{Detail: fmt.Sprintf("%s is writable by group or other (mode %v)", dir, fi.Mode().Perm())}
	}
	return nil
}

// Bytes is how much of a size-byte blob is already in digest's partial (never
// more than size: an overlong partial is restarted, so it counts as nothing).
func (s *PartialStore) Bytes(digest string, size int64) int64 {
	if !sha256Digest.MatchString(digest) {
		return 0
	}
	fi, err := os.Lstat(s.path(digest))
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > size {
		return 0
	}
	return fi.Size()
}

// Fill is one Resume of a partial.
type Fill struct {
	// Digest and Size name the blob.
	Digest string
	Size   int64
	// Transfer appends the rest of the blob to f from offset have; it runs
	// only when the partial is short. A failure must leave what arrived in f
	// for the next Resume.
	Transfer func(f *os.File, have int64) error
	// Commit consumes the complete partial: replay writes all of it, from
	// byte 0, to w. Commit is where the whole file is re-hashed.
	Commit func(replay func(w io.Writer) error) error
	// Poisoned reports a Commit error that condemns the partial's bytes (a
	// digest mismatch, an overrun); the partial is then removed.
	Poisoned func(error) bool
}

// Resume brings one blob through its partial: ensure Dir, open the partial
// (O_NOFOLLOW), restart an overlong one, let Transfer complete a short one,
// then hand the whole file to Commit. A poisoned partial is removed so it is
// never resumed; a committed one is removed.
func (s *PartialStore) Resume(fl Fill) error {
	if !sha256Digest.MatchString(fl.Digest) {
		return fmt.Errorf("partial %s: %w", quoteBounded(fl.Digest, 128), ErrInvalidDigest)
	}
	if err := s.EnsureDir(); err != nil {
		return err
	}
	path := s.path(fl.Digest)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open partial %s: %w", fl.Digest, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat partial %s: %w", fl.Digest, err)
	}
	have := fi.Size()
	if have > fl.Size {
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("reset partial %s: %w", fl.Digest, err)
		}
		have = 0
	}
	if have < fl.Size {
		if err := fl.Transfer(f, have); err != nil {
			return err
		}
	}
	err = fl.Commit(func(w io.Writer) error {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		_, err := io.Copy(w, struct{ io.Reader }{f})
		return err
	})
	if err != nil {
		if fl.Poisoned != nil && fl.Poisoned(err) {
			// A poisoned partial must not survive to be resumed.
			_ = os.Remove(path) // the commit error is the one reported
		}
		return fmt.Errorf("commit %s: %w", fl.Digest, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && s.Log != nil {
		s.Log.Warn("artifact pull: remove committed partial", "digest", fl.Digest, "err", err)
	}
	return nil
}
