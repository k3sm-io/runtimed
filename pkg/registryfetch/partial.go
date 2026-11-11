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
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// ErrPartialDir reports a partial dir that is not a private directory.
	ErrPartialDir = errors.New("registryfetch: partial dir is not private")
	// ErrInvalidDigest reports a digest that is not sha256:<64 hex>, which
	// would not be a path-safe file name.
	ErrInvalidDigest = errors.New("registryfetch: digest is not sha256:<64 hex>")
	// ErrPartialBudget reports that growing a partial would take the store's
	// regular files past MaxBytes.
	ErrPartialBudget = errors.New("registryfetch: partial store over its byte budget")
)

// PartialDirError is the error for a partial dir that is not a private
// directory. It matches ErrPartialDir under errors.Is; Detail names the dir
// and what is wrong with it.
type PartialDirError struct{ Detail string }

func (e *PartialDirError) Error() string { return ErrPartialDir.Error() + ": " + e.Detail }

// Is reports target == ErrPartialDir.
func (e *PartialDirError) Is(target error) bool { return target == ErrPartialDir }

var (
	sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	// partialName is the file-name grammar path produces; Sweep touches
	// nothing else.
	partialName = regexp.MustCompile(`^sha256-[a-f0-9]{64}\.partial$`)
)

// PartialStore keeps resumable partial blobs, one file per digest, in Dir.
// The caller makes sure one digest's partial has one writer at a time,
// either by its own means or with Claim. A PartialStore must not be copied
// after first use.
//
// Locking: mu guards claimed and nothing else. Claim and its release take it
// for a map update; Sweep holds it across the claimed check and the unlink of
// each one entry, so a Claim cannot land between the two. No method calls out
// to caller code while holding it.
type PartialStore struct {
	// Dir holds the partials. EnsureDir creates it 0700 when absent.
	Dir string
	// Log receives the warning for a committed partial that would not go
	// away. Nil discards it.
	Log *slog.Logger
	// MaxBytes caps the summed size of the regular files in Dir, enforced by
	// Admit. Zero means no cap.
	MaxBytes int64

	mu      sync.Mutex
	claimed map[string]struct{} // digests with a live Claim
}

// Claim makes the caller the one writer of digest's partial within this
// store. It never blocks: ok is false when the digest is already claimed (or
// is not sha256:<64 hex>), and release is then a no-op. release ends the
// claim and is idempotent.
func (s *PartialStore) Claim(digest string) (release func(), ok bool) {
	if !sha256Digest.MatchString(digest) {
		return func() {}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, held := s.claimed[digest]; held {
		return func() {}, false
	}
	if s.claimed == nil {
		s.claimed = make(map[string]struct{})
	}
	s.claimed[digest] = struct{}{}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.claimed, digest)
			s.mu.Unlock()
		})
	}, true
}

// Admit reports whether digest's partial may grow to want bytes: the sizes of
// every other regular file in Dir (Lstat, links never followed) plus want must
// not exceed MaxBytes, else the error matches ErrPartialBudget. Digest's own
// current partial is left out of the sum, since want replaces it. A zero
// MaxBytes admits everything; a missing Dir counts as empty.
func (s *PartialStore) Admit(digest string, want int64) error {
	if !sha256Digest.MatchString(digest) {
		return fmt.Errorf("partial %s: %w", quoteBounded(digest, 128), ErrInvalidDigest)
	}
	if s.MaxBytes <= 0 {
		return nil
	}
	own := filepath.Base(s.path(digest))
	total := want
	err := s.eachEntry(func(fd int, name string, st *unix.Stat_t) error {
		if name != own && st.Mode&unix.S_IFMT == unix.S_IFREG {
			total += st.Size
		}
		return nil
	})
	if err != nil {
		return err
	}
	if want < 0 || total > s.MaxBytes {
		return fmt.Errorf("partial %s wants %d bytes, store would hold %d of %d: %w",
			digest, want, total, s.MaxBytes, ErrPartialBudget)
	}
	return nil
}

// Sweep removes the partials whose mtime is older than maxAge at now and
// whose digest is not claimed. Only regular files named by the store's own
// grammar (sha256-<64 hex>.partial) are candidates; a symlink, a directory
// or a foreign name is left alone. Dir is opened O_NOFOLLOW and every entry
// is stat'ed and unlinked relative to that descriptor (fstatat
// AT_SYMLINK_NOFOLLOW, unlinkat without AT_REMOVEDIR), so neither a swapped
// path component nor a link in an entry's place redirects a removal. A
// missing Dir sweeps nothing. Per-entry failures are joined; the sweep goes
// on past them.
func (s *PartialStore) Sweep(now time.Time, maxAge time.Duration) (removed int, err error) {
	cutoff := now.Add(-maxAge)
	var errs []error
	err = s.eachEntry(func(fd int, name string, st *unix.Stat_t) error {
		if !partialName.MatchString(name) || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil
		}
		if !time.Unix(st.Mtim.Unix()).Before(cutoff) {
			return nil
		}
		digest := strings.Replace(strings.TrimSuffix(name, ".partial"), "-", ":", 1)
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, held := s.claimed[digest]; held {
			return nil
		}
		if err := unix.Unlinkat(fd, name, 0); err != nil {
			if !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("sweep partial %s: %w", name, err))
			}
			return nil
		}
		removed++
		return nil
	})
	if err != nil {
		return removed, err
	}
	return removed, errors.Join(errs...)
}

// eachEntry opens Dir O_NOFOLLOW and calls fn with the directory descriptor,
// each entry's name and its fstatat (AT_SYMLINK_NOFOLLOW) result. Entries
// that vanish between the listing and the stat are skipped. A missing Dir
// visits nothing; a Dir that is a symlink or not a directory is an error.
func (s *PartialStore) eachEntry(fn func(fd int, name string, st *unix.Stat_t) error) error {
	d, err := os.OpenFile(s.Dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &PartialDirError{Detail: fmt.Sprintf("open %s: %v", s.Dir, err)}
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("list partial dir: %w", err)
	}
	rc, err := d.SyscallConn()
	if err != nil {
		return fmt.Errorf("partial dir descriptor: %w", err)
	}
	var walkErr error
	if err := rc.Control(func(fd uintptr) {
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(int(fd), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				walkErr = fmt.Errorf("stat partial %s: %w", name, err)
				return
			}
			if err := fn(int(fd), name, &st); err != nil {
				walkErr = err
				return
			}
		}
	}); err != nil {
		return fmt.Errorf("partial dir descriptor: %w", err)
	}
	return walkErr
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
