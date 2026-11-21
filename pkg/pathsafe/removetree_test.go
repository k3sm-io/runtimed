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

package pathsafe

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// openFDs counts the descriptors this process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents) - 1 // the one ReadDir itself held
}

// withFDLimit runs fn with the soft RLIMIT_NOFILE at the descriptors open now
// plus spare, so fn fails with EMFILE if it ever holds more than spare more.
func withFDLimit(t *testing.T, spare int, fn func()) {
	t.Helper()
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	lim := old
	lim.Cur = uint64(openFDs(t) + spare)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &old); err != nil {
			t.Fatal(err)
		}
	}()
	fn()
}

// plantChain makes name under dir and depth-1 directories "d" nested below
// it, through descriptors (the chain is longer than PATH_MAX).
func plantChain(t *testing.T, dir, name string, depth int) {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < depth; i++ {
		n := "d"
		if i == 0 {
			n = name
		}
		if err := unix.Mkdirat(fd, n, 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		unix.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	unix.Close(fd)
}

// plantWide makes name under dir holding n files.
func plantWide(t *testing.T, dir, name string, n int) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, name, strconv.Itoa(i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRemoveTreeAtHoldsConstantDescriptors: a tree far deeper than the
// descriptors it is allowed is still removed, because RemoveTreeAt re-opens
// its way down from dirfd rather than holding one descriptor per level, and
// it leaves none open.
func TestRemoveTreeAtHoldsConstantDescriptors(t *testing.T) {
	base := t.TempDir()
	const depth, spare = 200, 16
	plantChain(t, base, "deep", depth)
	dfd, err := unix.Open(base, DirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd)
	before := openFDs(t)
	withFDLimit(t, spare, func() {
		err = RemoveTreeAt(dfd, "deep", TreeBounds{Depth: depth + 1})
	})
	after := openFDs(t)
	t.Logf("a %d-deep chain under a limit of %d spare descriptors: err=%v, open descriptors %d before, %d after", depth, spare, err, before, after)
	if err != nil {
		t.Fatalf("RemoveTreeAt = %v, want the chain removed", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "deep")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("deep is still there (lstat err %v)", err)
	}
	if after != before {
		t.Errorf("open descriptors went from %d to %d", before, after)
	}
}

// TestRemoveTreeAtStopsAtItsBounds: a tree deeper or wider than its bounds
// stops the removal with ErrTreeTooLarge and is left on disk, partly.
func TestRemoveTreeAtStopsAtItsBounds(t *testing.T) {
	base := t.TempDir()
	plantChain(t, base, "deep", 100)
	plantWide(t, base, "wide", 1000)
	dfd, err := unix.Open(base, DirFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd)
	if err := RemoveTreeAt(dfd, "deep", TreeBounds{Depth: 50}); !errors.Is(err, ErrTreeTooLarge) {
		t.Errorf("deep: RemoveTreeAt = %v, want ErrTreeTooLarge", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "deep")); err != nil {
		t.Errorf("deep was removed past its bound: %v", err)
	}
	if err := RemoveTreeAt(dfd, "wide", TreeBounds{Depth: 2, Entries: 100}); !errors.Is(err, ErrTreeTooLarge) {
		t.Errorf("wide: RemoveTreeAt = %v, want ErrTreeTooLarge", err)
	}
	if ents, err := os.ReadDir(filepath.Join(base, "wide")); err != nil || len(ents) < 900 {
		t.Errorf("wide holds %d entries (err %v), want at least 900 left", len(ents), err)
	}
	if err := RemoveTreeAt(dfd, "wide", TreeBounds{}); err == nil {
		t.Error("RemoveTreeAt with no depth bound succeeded")
	}
}
