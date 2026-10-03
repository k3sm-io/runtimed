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

package supervisor

// Restricted-child reports: which platform binaries a container ran without
// the pod shim.
//
// The path-rebase shim (shim/pathrebase_shim.c) keeps a pod's absolute mount
// paths pointing at the materialized volumes, but only in processes it is
// loaded into. A platform binary a pod process spawns (/bin/cat from a shell)
// has DYLD_* scrubbed by dyld, so it reads the host path instead and fails.
// ClassifyShimLoad answers for the container's MAIN process only; the child's
// loss is otherwise silent. It cannot be caught from outside: such a child
// commonly lives for about a millisecond, less than a fork notification plus
// a code-signing read takes. So the shim decides before the exec, from the
// SIP SF_RESTRICTED file flag of the file the kernel will run, and appends
// that path to a per-container file in the pod data volume. This file is the
// reader.
//
// The file is pod-controlled and runtimed reads it as root, so the reader is
// hardened against everything the pod can put there: the data volume is
// opened O_DIRECTORY|O_NOFOLLOW and the report openat'd O_NOFOLLOW|O_NONBLOCK
// (a symlink is refused, a FIFO cannot block the daemon); only a regular file
// with one link is read (a hard link to some other file is refused); at most
// childReportReadCap bytes are read per poll from a kept offset; only complete
// lines are consumed. Every reported name is UNTRUSTED: it must pass a strict
// character, shape and prefix allowlist and then name, by stat (never open),
// a regular file that itself carries SF_RESTRICTED, which the pod cannot
// create. A lookalike the pod built is therefore rejected.
//
// The report is ADVISORY: the pod can forge or delete it, so it only ever
// feeds a warning (and a pod forging one only warns about itself), never a
// decision.

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ChildReportEnv is the environment variable the path shim reads (once, at
// load) for the file it appends restricted-child reports to. It is
// runtime-owned: the runtime drops a value a container spec sets.
const ChildReportEnv = "K3SM_SHIM_REPORT"

// childReportPrefix is the fixed first part of a container's report file name
// in the pod data volume; the container name completes it.
const childReportPrefix = ".k3sm-shim-report-"

// ChildReportMaxNames bounds how many distinct names one reader keeps: enough
// to tell an operator what failed, too few for a pod to grow the message.
const ChildReportMaxNames = 8

// childReportReadCap bounds one poll's read of the pod-controlled file.
const childReportReadCap = 64 << 10

// childReportMaxNameLen bounds one reported name.
const childReportMaxNameLen = 1024

// dnsLabel is a Kubernetes container name (an RFC 1123 label).
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ChildReportName returns the single-component file name, inside the pod data
// volume, of container's restricted-child report. container must be a DNS
// label (what the API server admits), so the name can never carry a '/'.
func ChildReportName(container string) (string, error) {
	if len(container) > 63 || !dnsLabel.MatchString(container) {
		return "", fmt.Errorf("container name %q is not a DNS label", container)
	}
	return childReportPrefix + container, nil
}

// reportedPrefixes are the trees a platform binary can live in. A name
// outside them is never a binary dyld scrubs, so it is not even stat'ed.
var reportedPrefixes = []string{"/bin/", "/sbin/", "/usr/", "/System/"}

// validReportedName reports whether s has the shape of a platform binary's
// path: absolute, already clean, a strict character set (no space, comma,
// control character or NUL, so it renders safely in a comma-separated
// message), bounded length, and under one of reportedPrefixes. Shape only:
// the caller still requires the file to carry SF_RESTRICTED.
func validReportedName(s string) bool {
	if s == "" || len(s) > childReportMaxNameLen || s[0] != '/' || filepath.Clean(s) != s {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/', c == '.', c == '_', c == '-', c == '+', c == '@':
		default:
			return false
		}
	}
	for _, p := range reportedPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// parseChildReport consumes the complete lines of buf and returns how many
// bytes it consumed and the names it accepted, in order. A line is accepted
// when it passes validReportedName, restricted says it is a restricted
// platform file, and it is not already in seen or earlier in this call; at
// most room names are accepted. A trailing partial line is not consumed, so
// it is read again, whole, on a later poll, unless buf is a full read (full)
// with no newline at all: then the whole buffer is consumed, because a line
// longer than one read can never complete and must not wedge the reader.
func parseChildReport(buf []byte, full bool, seen []string, room int, restricted func(string) bool) (int, []string) {
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		if full {
			return len(buf), nil
		}
		return 0, nil
	}
	var names []string
	for _, line := range bytes.Split(buf[:last], []byte{'\n'}) {
		if len(names) >= room {
			break
		}
		s := string(line)
		if !validReportedName(s) || contains(seen, s) || contains(names, s) || !restricted(s) {
			continue
		}
		names = append(names, s)
	}
	return last + 1, names
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ChildReport reads one container's restricted-child report incrementally.
// Poll may be called concurrently (a periodic tick and the container's exit);
// mu serializes the reads and guards the offset and the names seen.
type ChildReport struct {
	dir        string
	name       string
	restricted func(string) bool

	mu   sync.Mutex
	off  int64
	dev  uint64
	ino  uint64
	seen []string
}

// NewChildReport returns a reader for the report file name (from
// ChildReportName) inside the pod data volume dir. dir must be runtime-derived,
// never taken from the pod. restricted decides whether a reported path is a
// restricted platform file; nil selects RestrictedPlatformFile.
func NewChildReport(dir, name string, restricted func(string) bool) *ChildReport {
	if restricted == nil {
		restricted = RestrictedPlatformFile
	}
	return &ChildReport{dir: dir, name: name, restricted: restricted}
}

// errChildReportNotRegular reports a report path that is not a regular file
// with exactly one link (a FIFO, a device, a directory, a hard link).
var errChildReportNotRegular = errors.New("child report is not a regular single-link file")

// Poll reads what was appended since the last poll and returns the names not
// returned before. A missing file is no report (nil, nil). A file shorter
// than the kept offset, or a different file at the path, is read again from
// the start; names already returned are not returned twice. Once
// ChildReportMaxNames names were returned, Poll reads nothing more.
func (c *ChildReport) Poll() ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) >= ChildReportMaxNames {
		return nil, nil
	}
	dfd, err := unix.Open(c.dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("open pod data volume %s: %w", c.dir, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	fd, err := unix.Openat(dfd, c.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, fmt.Errorf("open child report %s: %w", c.name, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat child report %s: %w", c.name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, fmt.Errorf("%s: %w", c.name, errChildReportNotRegular)
	}
	dev, ino := uint64(st.Dev), st.Ino
	if st.Size < c.off || dev != c.dev || ino != c.ino {
		c.off = 0 // truncated or replaced: start over
	}
	c.dev, c.ino = dev, ino
	n := st.Size - c.off
	if n <= 0 {
		return nil, nil
	}
	full := false
	if n >= childReportReadCap {
		n, full = childReportReadCap, true
	}
	buf := make([]byte, n)
	got, err := unix.Pread(fd, buf, c.off)
	if err != nil {
		return nil, fmt.Errorf("read child report %s: %w", c.name, err)
	}
	buf = buf[:got]
	consumed, names := parseChildReport(buf, full && got == len(buf), c.seen, ChildReportMaxNames-len(c.seen), c.restricted)
	c.off += int64(consumed)
	c.seen = append(c.seen, names...)
	return names, nil
}

// RemoveChildReport removes a stale report file name (from ChildReportName)
// from the pod data volume dir before a container instance starts, so the new
// instance is not charged with its predecessor's report. The volume is opened
// O_NOFOLLOW and the name unlinked relative to it (unlink never follows a
// symlink). A missing file is not an error.
func RemoveChildReport(dir, name string) error {
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open pod data volume %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	if err := unix.Unlinkat(dfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove child report %s: %w", name, err)
	}
	return nil
}
