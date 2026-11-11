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
	// ErrPartialCap reports a negative MaxBytes, a misconfigured store that
	// Admit refuses rather than treat as uncapped.
	ErrPartialCap = errors.New("registryfetch: partial store MaxBytes is negative")
	// ErrPartialClaimed reports a Claim of a digest another claim holds; it
	// is transient, unlike ErrInvalidDigest.
	ErrPartialClaimed = errors.New("registryfetch: partial already claimed")
	// ErrPartialLength reports a partial whose length after a Transfer that
	// returned nil is not the blob's Size.
	ErrPartialLength = errors.New("registryfetch: partial length is not the blob size")
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
// Sweep protects only claimed digests, so every Resume caller that shares a
// store with a Sweep must hold the digest's Claim for the whole Resume. Admit
// is advisory (two concurrent Admits can both pass) and counts every regular
// file in Dir by apparent size.
//
// Trust: Dir's parent path is trusted, i.e. root-owned or otherwise writable
// only by this principal. O_NOFOLLOW and the descriptor-relative operations
// cover only Dir's last component and its entries; a writable ancestor could
// swap the path above Dir.
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
	// Admit. Zero means no cap; a negative value is a misconfiguration that
	// Admit refuses with ErrPartialCap, never read as no cap.
	MaxBytes int64

	mu      sync.Mutex
	claimed map[string]struct{} // digests with a live Claim
}

// Claim makes the caller the one writer of digest's partial within this
// store. It never blocks. The error tells the two refusals apart: one
// matching ErrPartialClaimed means the digest is held by another claim and a
// later retry can succeed; one matching ErrInvalidDigest means the digest is
// not sha256:<64 hex> and no retry ever will. On error release is a no-op,
// never nil. release ends the claim and is idempotent.
func (s *PartialStore) Claim(digest string) (release func(), err error) {
	if !sha256Digest.MatchString(digest) {
		return func() {}, fmt.Errorf("claim %s: %w", quoteBounded(digest, 128), ErrInvalidDigest)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, held := s.claimed[digest]; held {
		return func() {}, fmt.Errorf("claim %s: %w", digest, ErrPartialClaimed)
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
	}, nil
}

// Admit reports whether digest's partial may grow to want bytes: the sizes of
// every other regular file in Dir plus want must not exceed MaxBytes, else the
// error matches ErrPartialBudget. Every regular file in Dir counts, whatever
// its name, by its apparent size (st_size from fstatat AT_SYMLINK_NOFOLLOW,
// not allocated blocks); links are never followed and other kinds of entry
// are not counted. Digest's own current partial is left out of the sum, since
// want replaces it. A zero MaxBytes admits everything; a negative MaxBytes
// admits nothing and the error matches ErrPartialCap; a missing Dir counts as
// empty.
//
// With a cap set Admit fails closed: want is a registry-supplied size, so a
// negative want or one past MaxBytes is refused before Dir is read, and the
// sum is compared without overflow, so no size wraps it negative.
//
// Admit is advisory: it reads Dir and decides, holding nothing, so two
// concurrent Admits for different digests can both pass and together take
// the store past MaxBytes. A caller that needs a hard bound serializes its
// Admit-then-grow sequences itself.
func (s *PartialStore) Admit(digest string, want int64) error {
	if !sha256Digest.MatchString(digest) {
		return fmt.Errorf("partial %s: %w", quoteBounded(digest, 128), ErrInvalidDigest)
	}
	if s.MaxBytes < 0 {
		return fmt.Errorf("partial %s: cap %d: %w", digest, s.MaxBytes, ErrPartialCap)
	}
	if s.MaxBytes == 0 {
		return nil
	}
	if want < 0 || want > s.MaxBytes {
		return fmt.Errorf("partial %s wants %d bytes, cap is %d: %w",
			digest, want, s.MaxBytes, ErrPartialBudget)
	}
	own := filepath.Base(s.path(digest))
	total := want // invariant: 0 <= total <= s.MaxBytes
	err := s.eachEntry(func(fd int, name string, st *unix.Stat_t) error {
		if name == own || st.Mode&unix.S_IFMT != unix.S_IFREG {
			return nil
		}
		if st.Size < 0 || st.Size > s.MaxBytes-total {
			return fmt.Errorf("partial %s wants %d bytes, other files exceed the %d left of %d: %w",
				digest, want, s.MaxBytes-want, s.MaxBytes, ErrPartialBudget)
		}
		total += st.Size
		return nil
	})
	return err
}

// Sweep removes the partials whose mtime is older than maxAge at now and
// whose digest is not claimed. Only regular files named by the store's own
// grammar (sha256-<64 hex>.partial) are candidates; a symlink, a directory
// or a foreign name is left alone. Dir is opened O_NOFOLLOW and every entry
// is stat'ed and unlinked relative to that descriptor (fstatat
// AT_SYMLINK_NOFOLLOW, unlinkat without AT_REMOVEDIR), so neither a swapped
// entry nor a link in an entry's place redirects a removal. A missing Dir
// sweeps nothing. Per-entry failures are joined; the sweep goes on past them.
//
// Sweep protects only claimed digests: it does not know about a Resume in
// progress, so it can unlink the partial of an unclaimed one out from under
// it. Every Resume caller that shares a store with a Sweep must therefore
// hold the digest's Claim for the whole Resume.
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
	// Transfer appends the rest of the blob to f, which Resume hands over
	// positioned at offset have; it runs only when the partial is short. A
	// failure must leave what arrived in f for the next Resume.
	//
	// Transfer owns restarting: when the source answers from an offset other
	// than have (a 200 to a Range request starts at 0), Transfer is the only
	// party that knows it, so Transfer truncates f to that offset and seeks
	// there before writing. Resume does not guess; after a nil Transfer it
	// checks that f is exactly Size bytes (see Resume), so a Transfer that
	// appends a whole blob to a prefix fails rather than commits.
	Transfer func(f *os.File, have int64) error
	// Commit consumes the complete partial: replay writes all of it, from
	// byte 0, to w. Commit is where the whole file is re-hashed.
	Commit func(replay func(w io.Writer) error) error
	// Poisoned reports a Commit error that condemns the partial's bytes (a
	// digest mismatch, an overrun); the partial is then removed.
	Poisoned func(error) bool
}

// Resume brings one blob through its partial: ensure Dir, open the partial
// (O_NOFOLLOW), restart an overlong one, let Transfer complete a short one
// from its current length, then hand the whole file to Commit. A poisoned
// partial is removed so it is never resumed; a committed one is removed.
//
// After a Transfer that returns nil the file must be exactly Size bytes, else
// the error matches ErrPartialLength and Commit does not run: a short file is
// kept as it is for the next Resume; a long one is truncated to Size, so the
// store never holds more than Size bytes for the digest (its prefix is then
// re-hashed, and refused, by the next Commit).
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
		if _, err := f.Seek(have, io.SeekStart); err != nil {
			return fmt.Errorf("seek partial %s: %w", fl.Digest, err)
		}
		if err := fl.Transfer(f, have); err != nil {
			return err
		}
		if err := checkLength(f, fl.Digest, fl.Size); err != nil {
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

// checkLength refuses a partial that is not size bytes after a transfer,
// truncating a long one to size.
func checkLength(f *os.File, digest string, size int64) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat partial %s: %w", digest, err)
	}
	switch n := fi.Size(); {
	case n < size:
		return fmt.Errorf("partial %s holds %d of %d bytes after transfer: %w", digest, n, size, ErrPartialLength)
	case n > size:
		if err := f.Truncate(size); err != nil {
			return fmt.Errorf("partial %s holds %d of %d bytes after transfer: %w (truncate: %w)",
				digest, n, size, ErrPartialLength, err)
		}
		return fmt.Errorf("partial %s held %d of %d bytes after transfer, cut to %d: %w",
			digest, n, size, size, ErrPartialLength)
	}
	return nil
}
