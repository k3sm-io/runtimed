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

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// RootLockName is the lock file New creates under Config.Root. Its flock marks
// the root as owned by one live Runtime; its content is the holder's pid, for
// the refusal message only (the flock, not the content, is the lock).
const RootLockName = "runtimed.lock"

// DefaultRootLockWait bounds how long New waits for another Runtime to release
// the root before it fails with ErrRootInUse.
//
// The wait exists for a launchd `kickstart -k`: launchd starts the new instance
// once the old one is gone, but the old daemon (or the k3sm process embedding
// it) may still be finishing its exit when the new one reaches New, and the
// flock is released only when the old process's descriptor closes. That overlap
// is the old process's last moments, normally well under a second; 15 seconds
// covers a slow exit on a loaded node (the runtime's own Close is bounded by
// defaultCloseGrace, 2 s) with room to spare, and is still short enough that a
// hand-started second daemon on a live root is refused promptly rather than
// hanging.
const DefaultRootLockWait = 15 * time.Second

// rootLockPoll is the retry cadence while waiting for the root lock. flock has
// no timed form, so the wait is a non-blocking attempt per tick.
const rootLockPoll = 50 * time.Millisecond

// ErrRootInUse reports that another live Runtime holds the root's lock and did
// not release it within the wait. The wrapping error names the lock file and
// the holder's pid as recorded in it.
var ErrRootInUse = errors.New("runtime root is in use by another runtime")

// rootLock is the exclusive flock on <root>/RootLockName that New takes and the
// Runtime holds for its life. Two Runtimes over one root race on the same
// on-disk records (the podreap store, the image index, pod dirs), so the second
// must not start at all.
//
// The descriptor is opened O_CLOEXEC, so no pod process, shim or vm helper the
// daemon spawns inherits it; those outlive the daemon by design and would
// otherwise keep the root locked after it exits.
//
// Concurrency: mu guards f; release is idempotent.
type rootLock struct {
	mu sync.Mutex
	f  *os.File
}

// acquireRootLock opens (creating 0600 if absent) <root>/RootLockName without
// following a symlink, takes an exclusive flock on it, waiting up to wait for a
// current holder to let go, and records this process's pid in it. A wait of 0
// or less selects DefaultRootLockWait. onBusy, when non-nil, is called after
// each refused attempt that will be retried (the Deps.rootLockBusy test seam).
// flock, when non-nil, replaces unix.Flock; it is a test seam for the errors a
// real filesystem rarely returns (ENOTSUP on a volume without flock support),
// and New always passes nil.
func acquireRootLock(root string, wait time.Duration, onBusy func(), flock func(fd, how int) error) (*rootLock, error) {
	if wait <= 0 {
		wait = DefaultRootLockWait
	}
	if flock == nil {
		flock = unix.Flock
	}
	path := filepath.Join(root, RootLockName)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("open runtime root lock %s: refusing a symlink: %w", path, err)
		}
		return nil, fmt.Errorf("open runtime root lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close() // the stat error is the one reported
		return nil, fmt.Errorf("stat runtime root lock %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = f.Close() // the refusal is the one reported
		return nil, fmt.Errorf("runtime root lock %s is not a regular file", path)
	}

	deadline := time.Now().Add(wait)
	for {
		err := flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close() // the flock error is the one reported
			return nil, fmt.Errorf("lock runtime root %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			holder := lockHolder(fd)
			_ = f.Close() // the refusal is the one reported
			return nil, fmt.Errorf("%w: %s is held by pid %s (waited %s)", ErrRootInUse, path, holder, wait)
		}
		if onBusy != nil {
			onBusy()
		}
		time.Sleep(rootLockPoll)
	}

	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	if err := unix.Ftruncate(fd, 0); err != nil {
		_ = f.Close() // closing releases the flock; the truncate error is reported
		return nil, fmt.Errorf("record pid in runtime root lock %s: %w", path, err)
	}
	if _, err := unix.Pwrite(fd, pid, 0); err != nil {
		_ = f.Close() // closing releases the flock; the write error is reported
		return nil, fmt.Errorf("record pid in runtime root lock %s: %w", path, err)
	}
	return &rootLock{f: f}, nil
}

// lockHolder reads the pid the current holder recorded, or "unknown" when the
// file holds none (a holder between its flock and its write).
func lockHolder(fd int) string {
	buf := make([]byte, 32)
	n, err := unix.Pread(fd, buf, 0)
	if err != nil || n <= 0 {
		return "unknown"
	}
	s := strings.TrimSpace(string(buf[:n]))
	if _, err := strconv.Atoi(s); err != nil {
		return "unknown"
	}
	return s
}

// release clears the recorded pid and drops the flock by closing the
// descriptor. Its caller owes the contract that nothing this Runtime started can
// still write under the root: New's failure paths hold no supervision yet, and
// Close calls it only after supervision has confirmed stopped, otherwise leaving
// the flock for the kernel to drop at process death. The file itself is left in
// place on purpose: unlinking a lock file another New already has open would let
// a third New create a fresh inode and lock it while the second holds the old
// one, so two Runtimes would each believe they own the root.
func (l *rootLock) release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	_ = unix.Ftruncate(int(f.Fd()), 0) // best effort: a stale pid only affects a message
	if err := f.Close(); err != nil {
		return fmt.Errorf("release runtime root lock: %w", err)
	}
	return nil
}
