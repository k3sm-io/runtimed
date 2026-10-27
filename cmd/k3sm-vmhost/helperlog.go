//go:build darwin && cgo

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

package main

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// helperLog is the helper's own output file, kept under a size cap by the one
// process that writes it.
//
// The daemon opens the file (truncated, with its old rotation removed, before
// the helper exists) and hands it to the helper as fd 1 and fd 2. After the
// spawn it never truncates it, because a daemon may not be there (the helper
// outlives it) and a reader that truncates races the writer. So the WRITER bounds it:
// before a write that would take the file past max, the file is renamed to
// path.1 (replacing the previous rotation) and a fresh path is opened and
// dup2'd onto every descriptor in fds, so later writes — this writer's and any
// raw write to fd 1 or 2 — land in the new file. The daemon's tail read takes
// the current file and, when that is short, the rotation.
//
// It rotates only while out is still the file at path (same inode): a helper
// whose output was pointed elsewhere must not rename a file it does not write.
// A rotation that fails is skipped and the write goes ahead: losing the bound
// for a while is better than losing the line.
//
// Bounded is this writer's traffic, which is everything the helper logs. A raw
// write the Go runtime or a framework makes to fd 2 is not checked, but lands
// in whichever file is current.
type helperLog struct {
	mu   sync.Mutex
	path string
	max  int64
	out  *os.File
	fds  []int
}

// newHelperLog returns the bounded writer over out, the descriptor open on path.
func newHelperLog(path string, max int64, out *os.File, fds []int) *helperLog {
	return &helperLog{path: path, max: max, out: out, fds: fds}
}

// Write rotates first if p would take the file past the cap, then writes p.
func (h *helperLog) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fi, err := h.out.Stat(); err == nil && fi.Size() > 0 && fi.Size()+int64(len(p)) > h.max {
		if onDisk, err := os.Lstat(h.path); err == nil && os.SameFile(fi, onDisk) {
			_ = h.rotate()
		}
	}
	return h.out.Write(p)
}

// rotate moves the current file to path.1 and points every descriptor in fds
// at a fresh, owner-only file at path.
func (h *helperLog) rotate() error {
	if err := os.Rename(h.path, h.path+".1"); err != nil {
		return err
	}
	f, err := os.OpenFile(h.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	for _, fd := range h.fds {
		if err := unix.Dup2(int(f.Fd()), fd); err != nil {
			return err
		}
	}
	return nil
}
