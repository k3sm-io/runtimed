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

package guestartifacts

import (
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"k3sm.io/runtimed/pkg/guestinit"
)

// The newc (SVR4) cpio format, as the Linux initramfs unpacker reads it.
const (
	// newcMagic selects the no-CRC variant. The CRC variant ("070702") would
	// require a checksum in c_check that the kernel does not verify anyway.
	newcMagic = "070701"

	// newcHeaderSize is the fixed ASCII header: the 6-byte magic plus thirteen
	// 8-byte hexadecimal fields.
	newcHeaderSize = 6 + 13*8

	// trailerName ends the stream. The unpacker stops at this name; anything
	// after it is not read.
	trailerName = "TRAILER!!!"
)

// File type bits of st_mode, restated rather than taken from io/fs or
// golang.org/x/sys/unix. These are Linux ABI values written into the archive,
// not properties of the host composing it — deriving them from the host's
// fs.FileMode would make the output depend on the platform running the build.
const (
	modeTypeDir  uint32 = 0o040000
	modeTypeFile uint32 = 0o100000
)

// dirMode is the permission every directory entry carries. It matches the
// 0o755 the guest init's own MkdirAll uses for the same paths, so a mount
// point that already exists and one the init creates are indistinguishable.
const dirMode uint32 = 0o755

// initMode is /init's permission. PID 1 must be executable by root; nothing
// else in the guest ever opens it.
const initMode uint32 = 0o755

// ErrEmptyInit is returned when the caller supplies no /init payload. An
// initramfs whose /init is a zero-byte file is a guaranteed kernel panic at
// exec, reported to the host as an opaque VM death, so it is refused at
// compose time where the cause is still legible.
var ErrEmptyInit = errors.New("guestartifacts: empty /init payload")

// mountPoints are the guest paths ComposeInitramfs materialises as directory
// entries, beyond the ancestors it derives from them.
//
// The guest scratch root comes from guestinit rather than a literal: the init
// mounts its spec share underneath it as its first act, and a divergence
// between the two packages would present as a boot that cannot find its own
// spec.
func mountPoints() []string {
	return []string{"/dev", "/proc", "/sys", guestinit.GuestRoot}
}

// entry is one archive member.
type entry struct {
	// name is the archive-relative path, with no leading slash. The kernel
	// unpacks relative to /, so "dev" and "/dev" address the same place;
	// omitting the slash matches what cpio(1) emits from a relative find.
	name string

	// mode is the full st_mode, file-type bits included.
	mode uint32

	// nlink is 2 for a directory (itself and its "." entry) and 1 for a file.
	// The unpacker only reads it to detect hard links, which this archive has
	// none of.
	nlink uint32

	// data is the member's content; nil for a directory.
	data []byte
}

// ComposeInitramfs writes a newc cpio archive containing initBinary as /init
// plus the guest's mount-point directories.
//
// The output is a pure function of initBinary: two calls with equal input
// produce byte-identical archives. See the package doc for why that is the
// requirement rather than a nicety.
func ComposeInitramfs(w io.Writer, initBinary []byte) error {
	if len(initBinary) == 0 {
		return ErrEmptyInit
	}

	entries := composeEntries(initBinary)
	for i, e := range entries {
		// Inodes are the entry's 1-based position. Any injective numbering
		// would do; a sequential one is the only choice that cannot smuggle a
		// host inode number into the archive.
		if err := writeEntry(w, e, uint32(i+1)); err != nil {
			return fmt.Errorf("write %q: %w", e.name, err)
		}
	}
	trailer := entry{name: trailerName, nlink: 1}
	if err := writeEntry(w, trailer, 0); err != nil {
		return fmt.Errorf("write cpio trailer: %w", err)
	}
	// Deliberately no trailing block padding. cpio(1) pads the stream out to
	// its block size, which makes the archive's length depend on a tool
	// setting rather than on its content; the kernel stops at the trailer.
	return nil
}

// composeEntries builds the full member list in archive order.
//
// Order is a plain lexicographic sort of the names, which is also a valid
// unpack order: a directory is a proper string prefix of everything beneath
// it, so a parent always sorts ahead of its children.
func composeEntries(initBinary []byte) []entry {
	dirs := map[string]bool{}
	for _, p := range mountPoints() {
		for _, d := range ancestors(p) {
			dirs[d] = true
		}
	}
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	names = append(names, "init")
	sort.Strings(names)

	out := make([]entry, 0, len(names))
	for _, n := range names {
		if n == "init" {
			out = append(out, entry{name: n, mode: modeTypeFile | initMode, nlink: 1, data: initBinary})
			continue
		}
		out = append(out, entry{name: n, mode: modeTypeDir | dirMode, nlink: 2})
	}
	return out
}

// ancestors expands an absolute guest path into every directory that must
// exist for it, shallowest first, as archive-relative names. "/run/k3sm"
// yields "run" and "run/k3sm": cpio has no MkdirAll, so an entry whose parent
// was never written is an unpack error.
func ancestors(p string) []string {
	rel := strings.TrimPrefix(path.Clean(p), "/")
	if rel == "" || rel == "." {
		return nil
	}
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[:i+1], "/"))
	}
	return out
}

// writeEntry emits one member: header, NUL-terminated name, padding, data,
// padding. Both paddings align to a 4-byte boundary measured from the start of
// the stream, which the fixed 110-byte header makes a local computation.
func writeEntry(w io.Writer, e entry, ino uint32) error {
	nameSize := len(e.name) + 1 // the trailing NUL is counted

	buf := make([]byte, 0, newcHeaderSize+nameSize+3)
	buf = append(buf, newcMagic...)
	for _, f := range [13]uint32{
		ino,
		e.mode,
		0, // c_uid:  the archive is unpacked as root and owns nothing else
		0, // c_gid
		e.nlink,
		0, // c_mtime: pinned, or the build clock would leak into the digest
		uint32(len(e.data)),
		0, // c_devmajor
		0, // c_devminor
		0, // c_rdevmajor  (no device nodes: devtmpfs populates /dev)
		0, // c_rdevminor
		uint32(nameSize),
		0, // c_check: always zero for the "070701" no-CRC variant
	} {
		buf = appendHex8(buf, f)
	}
	buf = append(buf, e.name...)
	buf = append(buf, 0)
	buf = appendPad(buf, newcHeaderSize+nameSize)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if len(e.data) == 0 {
		return nil
	}
	if _, err := w.Write(e.data); err != nil {
		return err
	}
	if pad := padLen(len(e.data)); pad > 0 {
		if _, err := w.Write(make([]byte, pad)); err != nil {
			return err
		}
	}
	return nil
}

// appendHex8 appends one header field as 8 uppercase hexadecimal digits, the
// width every newc field has.
func appendHex8(dst []byte, v uint32) []byte {
	const digits = "0123456789ABCDEF"
	var f [8]byte
	for i := 7; i >= 0; i-- {
		f[i] = digits[v&0xF]
		v >>= 4
	}
	return append(dst, f[:]...)
}

// appendPad appends the NUL bytes that round n up to a 4-byte boundary.
func appendPad(dst []byte, n int) []byte {
	if pad := padLen(n); pad > 0 {
		return append(dst, make([]byte, pad)...)
	}
	return dst
}

// padLen is the number of bytes needed to round n up to a multiple of 4.
func padLen(n int) int { return (4 - n%4) % 4 }
