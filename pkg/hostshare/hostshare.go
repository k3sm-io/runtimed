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

package hostshare

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// DefaultFile is where the node reads its allowlist. It sits beside the
// install directory, not inside it, so a reinstall that replaces
// /Library/k3sm keeps the shares, and under /Library, which only root can
// write. `sudo k3sm share` is the one writer.
const DefaultFile = "/Library/k3sm.host-shares"

// Limits on the file and on each entry. The file is root-written, but it is
// parsed by an unprivileged daemon on every pod create, so it is bounded like
// any other input.
const (
	maxFileBytes = 64 << 10
	maxEntries   = 256
	maxPathBytes = 1024
)

// Mode is what an entry lets a pod do with the paths it covers.
type Mode string

const (
	// ModeReadWrite covers a directory and everything under it, read and write.
	ModeReadWrite Mode = "rw"
	// ModeReadOnly covers a directory and everything under it, read only. A
	// pod must mount it readOnly.
	ModeReadOnly Mode = "ro"
	// ModeSocket covers exactly one Unix socket, which a pod may connect to.
	ModeSocket Mode = "socket"
)

// Entry is one line of the allowlist.
type Entry struct {
	Mode Mode
	Path string
}

// String renders e as its file line.
func (e Entry) String() string { return string(e.Mode) + " " + e.Path }

// Grant is one hostPath volume a pod is allowed to mount, as the sandbox
// renders it: the path, and whether it is read-only or a socket.
type Grant struct {
	// Volume is the pod's own volume name.
	Volume string
	// Path is the host path, which is also the only mount path allowed.
	Path string
	// ReadOnly grants read access only.
	ReadOnly bool
	// Socket grants connect(2) to the one socket at Path, and nothing else.
	Socket bool
	// Entry is the allowlist entry that admitted it.
	Entry Entry
}

// ErrInvalidEntry reports an allowlist entry that can never be shared.
var ErrInvalidEntry = errors.New("hostshare: invalid entry")

// ErrUnsafeFile reports an allowlist file that is not a regular file owned by
// root and writable by root alone. The node then shares nothing.
var ErrUnsafeFile = errors.New("hostshare: allowlist file is not root-owned and root-only-writable")

// ErrNotShared reports a hostPath volume the allowlist does not admit, or that
// a pod mounts in a way a share cannot be used.
var ErrNotShared = errors.New("hostshare: hostPath volume is not shared by this node")

// refusedRoots are trees no entry may name, cover or sit under: the system,
// the node's own state and binaries, and the secrets store. pkg/sandbox
// refuses a grant into the node's configured work dir again, whatever its path.
var refusedRoots = []string{
	"/System",
	"/usr",
	"/bin",
	"/sbin",
	"/dev",
	"/etc",
	"/private/etc",
	"/var",
	"/private/var",
	"/Library/k3sm",
	DefaultFile,
	DefaultFile + ".d",
	"/Library/Keychains",
	"/Library/LaunchDaemons",
	"/Library/LaunchAgents",
}

// refusedHomeChildren are the children of a home directory no entry may name
// or sit under. Dot directories under a home are refused by rule as well.
var refusedHomeChildren = []string{"Library"}

// ValidateEntry reports whether e can be shared at all. It checks the shape
// only; Authorize checks the filesystem when a pod asks.
func ValidateEntry(e Entry) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %q: %s", ErrInvalidEntry, e.Path, fmt.Sprintf(format, a...))
	}
	switch e.Mode {
	case ModeReadWrite, ModeReadOnly, ModeSocket:
	default:
		return fmt.Errorf("%w: mode %q is not rw, ro or socket", ErrInvalidEntry, e.Mode)
	}
	p := e.Path
	if len(p) == 0 || len(p) > maxPathBytes {
		return bad("length must be 1 to %d bytes", maxPathBytes)
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return bad("must be an absolute, clean path other than /")
	}
	for _, r := range p {
		// The path is rendered into a Seatbelt string literal and into the
		// file format, which is line- and space-delimited. ASCII only: APFS
		// and Seatbelt match paths case- and normalization-insensitively, and
		// the refusals below fold ASCII case, so a non-ASCII spelling of a
		// refused name could otherwise slip past them.
		if r < 0x20 || r >= 0x7f || r == '"' || r == '\\' || r == ' ' {
			return bad("contains a non-ASCII or control character, a space, a quote or a backslash")
		}
	}
	// Every comparison below folds case: /users/dev/library is the same
	// directory as /Users/dev/Library to the filesystem and to Seatbelt.
	for _, root := range refusedRoots {
		if atOrUnderFold(p, root) || atOrUnderFold(root, p) {
			return bad("overlaps the protected tree %s", root)
		}
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if strings.EqualFold(parts[0], "Users") {
		// /Users and /Users/<name> are refused: a share is a project tree,
		// never a whole home, which holds the user's keys and credentials.
		if len(parts) < 3 {
			return bad("a share under /Users must be below a home directory, not the home itself")
		}
		for _, c := range parts[2:] {
			if strings.HasPrefix(c, ".") {
				return bad("a share may not name a dot directory under a home")
			}
		}
		if slices.ContainsFunc(refusedHomeChildren, func(c string) bool { return strings.EqualFold(c, parts[2]) }) {
			return bad("a share may not be the home's %s directory or under it", parts[2])
		}
	}
	return nil
}

// Parse reads a list of share entries, the format of a delegated user's file.
// Each line is "<mode> <absolute path>"; blank lines and lines starting with
// '#' are ignored. Any malformed or invalid line fails the whole file, so a
// typo never silently shares something else. A delegate line is refused here:
// only the root-owned node file (ParseFile) may carry one.
func Parse(r io.Reader) ([]Entry, error) {
	f, err := parse(r, false, ValidateEntry)
	return f.Entries, err
}

// ParseFile reads the node's root-owned file: share entries, and the
// delegations that let a named user keep their own entries (see Delegation).
func ParseFile(r io.Reader) (File, error) { return parse(r, true, ValidateEntry) }

// parse takes the entry check as a parameter so a test can read files that
// name temp directories, which sit under the refused /var.
func parse(r io.Reader, delegations bool, validate func(Entry) error) (File, error) {
	var out File
	sc := bufio.NewScanner(io.LimitReader(r, maxFileBytes+1))
	sc.Buffer(make([]byte, 0, 4096), maxPathBytes+256)
	read := 0
	line := 0
	for sc.Scan() {
		line++
		read += len(sc.Bytes()) + 1
		if read > maxFileBytes+1 {
			return File{}, fmt.Errorf("%w: file is over %d bytes", ErrInvalidEntry, maxFileBytes)
		}
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if fields[0] == delegateKeyword {
			if !delegations {
				return File{}, fmt.Errorf("%w: line %d: a delegation may only be set in the root-owned node file", ErrInvalidEntry, line)
			}
			d, err := parseDelegation(fields, validate)
			if err != nil {
				return File{}, fmt.Errorf("line %d: %w", line, err)
			}
			if len(out.Delegations) == maxDelegations {
				return File{}, fmt.Errorf("%w: more than %d delegations", ErrInvalidEntry, maxDelegations)
			}
			out.Delegations = append(out.Delegations, d)
			continue
		}
		if len(fields) != 2 {
			return File{}, fmt.Errorf("%w: line %d: want \"<mode> <path>\"", ErrInvalidEntry, line)
		}
		e := Entry{Mode: Mode(fields[0]), Path: fields[1]}
		if err := validate(e); err != nil {
			return File{}, fmt.Errorf("line %d: %w", line, err)
		}
		if len(out.Entries) == maxEntries {
			return File{}, fmt.Errorf("%w: more than %d entries", ErrInvalidEntry, maxEntries)
		}
		out.Entries = append(out.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return File{}, fmt.Errorf("%w: %v", ErrInvalidEntry, err)
	}
	return out, nil
}

// Format renders entries as the node's file, sorted and de-duplicated, with
// a header saying who writes it.
func Format(entries []Entry) []byte { return FormatFile(File{Entries: entries}) }

// FormatFile renders the node's root-owned file: its entries, then its
// delegations, each sorted and de-duplicated.
func FormatFile(f File) []byte {
	var b bytes.Buffer
	b.WriteString("# k3sm host shares: the host paths native pods may mount with a hostPath volume.\n")
	b.WriteString("# Written by `sudo k3sm share`. One \"<mode> <path>\" per line; mode is rw, ro or socket.\n")
	writeEntries(&b, f.Entries)
	if len(f.Delegations) > 0 {
		b.WriteString("# Delegations: the named user adds shares under the prefix with `k3sm share add`, no sudo.\n")
		ds := slices.Clone(f.Delegations)
		slices.SortFunc(ds, func(a, b Delegation) int {
			if c := strings.Compare(a.Prefix, b.Prefix); c != 0 {
				return c
			}
			return int(a.UID) - int(b.UID)
		})
		ds = slices.CompactFunc(ds, func(a, b Delegation) bool { return a.String() == b.String() })
		for _, d := range ds {
			b.WriteString(d.String())
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// FormatUser renders a delegated user's own file.
func FormatUser(entries []Entry) []byte {
	var b bytes.Buffer
	b.WriteString("# k3sm host shares delegated to this user: written by `k3sm share add|remove`, no sudo.\n")
	b.WriteString("# The node admits a line only under a prefix the root-owned node file delegates to this uid.\n")
	writeEntries(&b, entries)
	return b.Bytes()
}

func writeEntries(b *bytes.Buffer, entries []Entry) {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b Entry) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(string(a.Mode), string(b.Mode))
	})
	sorted = slices.Compact(sorted)
	for _, e := range sorted {
		b.WriteString(e.String())
		b.WriteByte('\n')
	}
}

// LoadFile reads the node's root-owned file at path: its own entries and its
// delegations, and nothing from any delegated user's file. A missing file is
// empty, the default: the node shares nothing. A file that is a symlink, not a
// regular file, not owned by root, or writable by group or other is refused
// (ErrUnsafeFile), because the daemon that reads it runs unprivileged and must
// not trust a list it, or a pod, could have written. `sudo k3sm share` reads
// and rewrites the file through this.
func LoadFile(path string) (File, error) { return defaultLoader().loadFile(path) }

// Load returns every entry the node admits: the root-owned file's own entries
// and, for each delegation in it, the delegated user's entries that still
// pass the delegation's checks now (LoadEffective). It is what the node
// daemon and runtimed decide a pod's hostPath volumes from, on every create.
func Load(path string) ([]Entry, error) {
	eff, err := LoadEffective(path)
	return eff.Entries, err
}

func (l loader) loadFile(path string) (File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return File{}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("%w: open %s: %v", ErrUnsafeFile, path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return File{}, fmt.Errorf("%w: stat %s: %v", ErrUnsafeFile, path, err)
	}
	if err := checkOwnedBy(fi, l.rootUID); err != nil {
		return File{}, fmt.Errorf("%w: %s: %v", ErrUnsafeFile, path, err)
	}
	return parse(f, true, l.validate)
}

// checkOwnedBy is the ownership test every list file passes: a regular file
// owned by uid (root, 0, for the node file) and writable by nobody else. It
// takes a FileInfo so a test can feed it one.
func checkOwnedBy(fi os.FileInfo, uid uint32) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("mode %v is group- or other-writable", fi.Mode().Perm())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no ownership information")
	}
	if st.Uid != uid {
		return fmt.Errorf("owned by uid %d, not %d", st.Uid, uid)
	}
	return nil
}

// fileChecker is the filesystem half of Authorize, a seam for tests.
type fileChecker interface {
	// resolve returns the path with every symlink resolved.
	resolve(p string) (string, error)
	// kind returns "dir", "socket" or "other" for an existing path.
	kind(p string) (string, error)
	// foldsCase reports whether the volume holding p compares names
	// without regard to case.
	foldsCase(p string) bool
}

type osChecker struct{}

func (osChecker) resolve(p string) (string, error) { return filepath.EvalSymlinks(p) }

func (osChecker) foldsCase(p string) bool { return FoldsCase(p) }

func (osChecker) kind(p string) (string, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	switch {
	case fi.IsDir():
		return "dir", nil
	case fi.Mode()&os.ModeSocket != 0:
		return "socket", nil
	}
	return "other", nil
}

// Authorize decides every hostPath volume box mounts against entries and
// returns one Grant per mounted hostPath volume, or an error wrapping
// ErrNotShared that names the volume. A pod with no hostPath volume gets no
// grants and no error. A hostPath volume no container mounts reaches nothing
// and gets no grant.
//
// A volume is granted only when all of these hold:
//   - its path is absolute and clean, and every container that mounts it does
//     so at exactly that path with no subPath (a native pod has no mount
//     namespace, so the share is only ever at its host path);
//   - its type is empty, Directory or Socket, and the path exists as that kind;
//   - the path contains no symlink (it resolves to itself), so a link cannot
//     point an admitted spelling at a tree the admin never named;
//   - the path is on a case-insensitive volume: Seatbelt matches a granted
//     path without regard to case even on a case-sensitive volume, where the
//     grant would also reach differently cased siblings (FoldsCase);
//   - an rw or ro entry covers it (the path is at or under the entry), or a
//     socket entry names exactly it;
//   - a read-only entry is mounted readOnly by every container, and no volume
//     is mounted read-only by one container and read-write by another (the
//     sandbox profile is per pod, so the stricter mount could not hold).
func Authorize(entries []Entry, box *runtimev1.PodBox) ([]Grant, error) {
	return authorize(entries, box, osChecker{})
}

func authorize(entries []Entry, box *runtimev1.PodBox, fs fileChecker) ([]Grant, error) {
	type use struct{ ro, rw bool }
	uses := map[string]*use{}
	var bad error
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				v := findVolume(box, m.GetName())
				if v == nil || v.GetHostPath() == nil {
					continue
				}
				p := v.GetHostPath().GetPath()
				if m.GetSubPath() != "" {
					bad = notShared(v.GetName(), "a host share cannot be mounted with a subPath")
				} else if m.GetMountPath() != p {
					bad = notShared(v.GetName(), "a host share must be mounted at its own host path (mountPath equal to hostPath.path)")
				}
				if bad != nil {
					return nil, bad
				}
				u := uses[v.GetName()]
				if u == nil {
					u = &use{}
					uses[v.GetName()] = u
				}
				if m.GetReadOnly() {
					u.ro = true
				} else {
					u.rw = true
				}
			}
		}
	}
	var out []Grant
	for _, v := range box.GetVolumes() {
		u := uses[v.GetName()]
		if v.GetHostPath() == nil || u == nil {
			continue
		}
		g, err := authorizeOne(entries, v, u.ro, u.rw, fs)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

func authorizeOne(entries []Entry, v *runtimev1.Volume, ro, rw bool, fs fileChecker) (Grant, error) {
	name := v.GetName()
	p := v.GetHostPath().GetPath()
	typ := v.GetHostPath().GetType()
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return Grant{}, notShared(name, "hostPath.path must be absolute and clean")
	}
	if ro && rw {
		return Grant{}, notShared(name, "mounted read-only by one container and read-write by another")
	}
	var want string
	switch typ {
	case "", "Directory":
		want = "dir"
	case "Socket":
		want = "socket"
	default:
		return Grant{}, notShared(name, fmt.Sprintf("hostPath type %q is not shareable (use Directory or Socket)", typ))
	}
	// Match before touching the filesystem: a path no entry covers is
	// refused without the daemon stat-ing it on the pod's behalf.
	entry, ok := match(entries, p, typ)
	if !ok {
		return Grant{}, notShared(name, "no host share entry covers this path; the node admin adds one with `sudo k3sm share add`, or a delegated user with `k3sm share add`")
	}
	if typ == "" {
		want = map[Mode]string{ModeSocket: "socket"}[entry.Mode]
		if want == "" {
			want = "dir"
		}
	}
	resolved, err := fs.resolve(p)
	if err != nil {
		return Grant{}, notShared(name, "the path does not exist on this node")
	}
	if resolved != p {
		return Grant{}, notShared(name, "the path contains a symlink; name the resolved path instead")
	}
	if !fs.foldsCase(p) {
		return Grant{}, notShared(name, "the path is on a case-sensitive volume, where the sandbox's case-insensitive match would also reach other names")
	}
	kind, err := fs.kind(p)
	if err != nil || kind != want {
		return Grant{}, notShared(name, fmt.Sprintf("the path is not a %s", map[string]string{"dir": "directory", "socket": "socket"}[want]))
	}
	g := Grant{Volume: name, Path: p, Entry: entry}
	switch entry.Mode {
	case ModeSocket:
		g.Socket = true
	case ModeReadOnly:
		if rw {
			return Grant{}, notShared(name, "the host share is read-only; mount it with readOnly: true")
		}
		g.ReadOnly = true
	default:
		g.ReadOnly = ro
	}
	return g, nil
}

// match returns the entry that admits p for a volume of hostPath type typ.
// Among directory entries the most specific one wins, so `ro /p/secrets`
// narrows `rw /p`; between two entries for the same path read-write wins.
func match(entries []Entry, p, typ string) (Entry, bool) {
	var found Entry
	ok := false
	for _, e := range entries {
		if ValidateEntry(e) != nil {
			continue
		}
		switch e.Mode {
		case ModeSocket:
			if typ != "Directory" && p == e.Path {
				return e, true
			}
		case ModeReadWrite, ModeReadOnly:
			if typ != "Socket" && atOrUnder(p, e.Path) {
				switch {
				case !ok, len(e.Path) > len(found.Path):
					found, ok = e, true
				case len(e.Path) == len(found.Path) && e.Mode == ModeReadWrite:
					found = e
				}
			}
		}
	}
	return found, ok
}

func notShared(volume, why string) error {
	return fmt.Errorf("%w: volume %q: %s", ErrNotShared, volume, why)
}

func findVolume(box *runtimev1.PodBox, name string) *runtimev1.Volume {
	for _, v := range box.GetVolumes() {
		if v.GetName() == name {
			return v
		}
	}
	return nil
}

// FoldsCase reports whether the volume that holds the existing path p
// compares names without regard to case, as APFS does by default. It looks
// the path up again with the letters of one of its components flipped in
// case: on a case-insensitive volume that names the same file. A path with
// no ASCII letter in any component, or any failure, reports false, so a
// caller refuses rather than guesses.
func FoldsCase(p string) bool {
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	parts := strings.Split(p, "/")
	for i := len(parts) - 1; i >= 1; i-- {
		flipped := flipCase(parts[i])
		if flipped == parts[i] {
			continue
		}
		alt := slices.Clone(parts)
		alt[i] = flipped
		fj, err := os.Lstat(strings.Join(alt, "/"))
		return err == nil && os.SameFile(fi, fj)
	}
	return false
}

func flipCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = c - 'a' + 'A'
		case c >= 'A' && c <= 'Z':
			b[i] = c - 'A' + 'a'
		}
	}
	return string(b)
}

// atOrUnder reports whether p is dir or inside it, by path components.
// atOrUnderFold is atOrUnder with ASCII case folded, the way APFS and
// Seatbelt compare paths.
func atOrUnderFold(p, dir string) bool {
	return atOrUnder(strings.ToLower(p), strings.ToLower(dir))
}

func atOrUnder(p, dir string) bool {
	if p == dir {
		return true
	}
	return strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}
