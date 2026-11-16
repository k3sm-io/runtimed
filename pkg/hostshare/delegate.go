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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// delegateKeyword starts a delegation line in the node's file.
const delegateKeyword = "delegate"

// userFileName is the name of a delegated user's file inside its directory.
const userFileName = "host-shares"

// MinDelegateUID is the lowest uid a prefix may be delegated to. macOS gives
// system and service accounts uids below 500, the node's own _k3sm user among
// them; pods run as that user, so a delegation to it would let a pod write
// its own shares.
const MinDelegateUID = 500

const maxDelegations = 64

// maxUserEntries bounds one delegated user's file. Every line costs the
// node a walk of its path on each create that mounts a hostPath, in two
// daemons, so a user's list is held well below the node file's limit.
const maxUserEntries = 64

var userName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// ErrNotDelegated reports a delegated user's entry the node does not admit:
// it lies outside every prefix delegated to that uid, or no longer passes the
// delegation's checks (ownership, symlinks, the refusal rules).
var ErrNotDelegated = errors.New("hostshare: entry is not admitted by a delegation")

// File is the node's root-owned file: the shares root made, and the
// delegations root granted.
type File struct {
	Entries     []Entry
	Delegations []Delegation
	// Exposes are the exposure grants root made (ExposeGrant).
	Exposes []ExposeGrant
}

// Delegation lets one non-root user add and remove shares under one prefix
// without root. Root records it once (`sudo k3sm share delegate`); the user's
// entries then live in a file the user owns (UserFile), and the node admits
// each of them only while it passes CheckDelegated against this record.
type Delegation struct {
	// UID is the delegated user. Ownership is checked against it, never
	// against the name.
	UID uint32
	// User is the account name at the time of delegation, for display only.
	User string
	// Modes are the share modes the user may add under Prefix.
	Modes []Mode
	// Prefix is the delegated directory, canonical (symlinks resolved) when
	// root recorded it. It passes ValidateEntry as an rw entry.
	Prefix string
}

// String renders d as its line in the node's file.
func (d Delegation) String() string {
	ms := make([]string, len(d.Modes))
	for i, m := range d.Modes {
		ms[i] = string(m)
	}
	return fmt.Sprintf("%s uid=%d user=%s modes=%s %s", delegateKeyword, d.UID, d.User, strings.Join(ms, ","), d.Prefix)
}

// Allows reports whether d lets its user add a share of mode m.
func (d Delegation) Allows(m Mode) bool { return slices.Contains(d.Modes, m) }

// ValidateDelegation checks d's shape: a non-system uid, a plain user name,
// a non-empty set of known modes, and a prefix that could itself be shared
// read-write (so not a system tree, not /Users, not a whole home, not a dot
// directory, not a home's Library, ASCII only).
func ValidateDelegation(d Delegation) error { return validateDelegation(d, ValidateEntry) }

func validateDelegation(d Delegation, validate func(Entry) error) error {
	if d.UID < MinDelegateUID || d.UID > 1<<31-1 {
		return fmt.Errorf("%w: delegation to uid %d: only a user account (uid %d or above) may be delegated", ErrInvalidEntry, d.UID, MinDelegateUID)
	}
	if !userName.MatchString(d.User) {
		return fmt.Errorf("%w: delegation user name %q is not a plain account name", ErrInvalidEntry, d.User)
	}
	if len(d.Modes) == 0 {
		return fmt.Errorf("%w: delegation of %q names no modes", ErrInvalidEntry, d.Prefix)
	}
	seen := map[Mode]bool{}
	for _, m := range d.Modes {
		if m != ModeReadWrite && m != ModeReadOnly && m != ModeSocket {
			return fmt.Errorf("%w: delegation mode %q is not rw, ro or socket", ErrInvalidEntry, m)
		}
		if seen[m] {
			return fmt.Errorf("%w: delegation mode %q is repeated", ErrInvalidEntry, m)
		}
		seen[m] = true
	}
	if err := validate(Entry{Mode: ModeReadWrite, Path: d.Prefix}); err != nil {
		return fmt.Errorf("delegation prefix: %w", err)
	}
	return nil
}

// ParseModes reads a comma-separated mode list ("rw,ro,socket").
func ParseModes(s string) ([]Mode, error) {
	var out []Mode
	for _, f := range strings.Split(s, ",") {
		m := Mode(strings.TrimSpace(f))
		if m != ModeReadWrite && m != ModeReadOnly && m != ModeSocket {
			return nil, fmt.Errorf("%w: mode %q is not rw, ro or socket", ErrInvalidEntry, m)
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

func parseDelegation(fields []string, validate func(Entry) error) (Delegation, error) {
	if len(fields) != 5 {
		return Delegation{}, fmt.Errorf("%w: want \"delegate uid=<n> user=<name> modes=<m,...> <prefix>\"", ErrInvalidEntry)
	}
	kv := func(f, key string) (string, error) {
		v, ok := strings.CutPrefix(f, key+"=")
		if !ok {
			return "", fmt.Errorf("%w: delegation field %q: want %s=", ErrInvalidEntry, f, key)
		}
		return v, nil
	}
	us, err := kv(fields[1], "uid")
	if err != nil {
		return Delegation{}, err
	}
	uid, err := strconv.ParseUint(us, 10, 32)
	if err != nil {
		return Delegation{}, fmt.Errorf("%w: delegation uid %q", ErrInvalidEntry, us)
	}
	user, err := kv(fields[2], "user")
	if err != nil {
		return Delegation{}, err
	}
	ms, err := kv(fields[3], "modes")
	if err != nil {
		return Delegation{}, err
	}
	modes, err := ParseModes(ms)
	if err != nil {
		return Delegation{}, err
	}
	d := Delegation{UID: uint32(uid), User: user, Modes: modes, Prefix: fields[4]}
	return d, validateDelegation(d, validate)
}

// UserDir is the directory that holds a delegated uid's file, beside the
// node's file: <nodeFile>.d/<uid>. Root creates it, owned by the uid, when it
// delegates, so the user can replace the file atomically without root; the
// parent <nodeFile>.d stays root-owned, so the user can neither remove the
// directory nor make one for another uid.
func UserDir(nodeFile string, uid uint32) string {
	return filepath.Join(nodeFile+".d", strconv.FormatUint(uint64(uid), 10))
}

// UserFile is a delegated uid's file of share entries (Parse/FormatUser).
func UserFile(nodeFile string, uid uint32) string {
	return filepath.Join(UserDir(nodeFile, uid), userFileName)
}

// Dropped is a delegated entry, or a whole delegation, the node does not
// admit right now, and why. The node shares nothing for it; `k3sm share list`
// shows it so the user can see what to fix.
type Dropped struct {
	UID uint32
	// Entry is the dropped entry; zero when the whole user file or
	// delegation was dropped.
	Entry  Entry
	Reason string
}

// Effective is what the node admits on a create: the node file's own entries
// followed by every delegated entry that passes its delegation's checks now.
type Effective struct {
	Entries     []Entry
	Delegations []Delegation
	// Exposes are the node file's exposure grants, as written by root.
	Exposes []ExposeGrant
	// Owners maps an admitted delegated entry to the uid whose file holds it.
	// An entry absent from it came from the root-owned file.
	Owners  map[Entry]uint32
	Dropped []Dropped
}

// LoadEffective reads the node's file at path and every delegated user's
// file, and re-validates each delegated entry against the root-owned
// delegation (CheckDelegated) at the moment of reading, so editing a user
// file by hand admits nothing a `k3sm share add` would not. An error is
// returned only for the node's own file; a delegated file or entry that fails
// is dropped (Effective.Dropped) and shares nothing.
func LoadEffective(path string) (Effective, error) { return defaultLoader().loadEffective(path) }

// LoadEffectiveFor is LoadEffective for a reader that is not the node's own
// user, such as `k3sm share list` run by a delegated user: nodeUID is the
// uid the node's daemons and pods run as, which is never admitted as a
// delegated user.
func LoadEffectiveFor(path string, nodeUID uint32) (Effective, error) {
	l := defaultLoader()
	l.selfUID = nodeUID
	return l.loadEffective(path)
}

// CheckDelegated reports whether delegation d admits e, the entry of the user
// d names, now. It holds when:
//   - e passes ValidateEntry and d allows e's mode;
//   - e's path is d's prefix or under it, compared with ASCII case folded the
//     way APFS and Seatbelt compare paths;
//   - the path resolves to itself (no symlink anywhere in it);
//   - every component from the prefix down to the path is owned by d's uid,
//     is not a symlink, and the first of them is the same directory (device
//     and inode) as d's prefix, so a differently cased spelling on a
//     case-sensitive volume cannot name a sibling of the prefix;
//   - the path is a directory, or a socket for a socket entry.
//
// It is the same check `k3sm share add` makes, as the delegated user, before
// writing the user's file, and the node makes on every create. Run here it
// leaves out one check LoadEffective adds: that d's uid is not the reading
// daemon's own (the caller of this is the delegated user, and
// ValidateDelegation already refuses every system uid).
func CheckDelegated(d Delegation, e Entry) error {
	l := defaultLoader()
	l.selfUID = 0
	return l.checkDelegated(d, e)
}

// LoadUserFile returns the entries in uid's own file under nodeFile as
// written, before any delegation check, after the same file-safety checks
// LoadEffective makes. `k3sm share add|remove` rewrites the file from this.
func LoadUserFile(nodeFile string, uid uint32) ([]Entry, error) {
	return defaultLoader().loadUserFile(nodeFile, uid)
}

// AtOrUnder reports whether p is dir or inside it, by path components, with
// ASCII case folded the way APFS and Seatbelt compare paths.
func AtOrUnder(p, dir string) bool { return atOrUnderFold(p, dir) }

// loader carries the two identities the checks depend on, so a test can run
// them as an ordinary user.
type loader struct {
	// rootUID must own the node's file and <nodeFile>.d: 0 outside tests.
	rootUID uint32
	// selfUID is the reading daemon's own uid. Pods run as it, so it is
	// never admitted as a delegated user, whatever the node file says.
	selfUID uint32
	// validate is ValidateEntry outside tests (temp dirs sit under /var).
	validate func(Entry) error
}

func defaultLoader() loader {
	return loader{rootUID: 0, selfUID: uint32(os.Getuid()), validate: ValidateEntry}
}

func (l loader) loadEffective(path string) (Effective, error) {
	f, err := l.loadFile(path)
	if err != nil {
		return Effective{}, err
	}
	eff := Effective{Entries: slices.Clone(f.Entries), Delegations: f.Delegations, Exposes: f.Exposes, Owners: map[Entry]uint32{}}
	root := map[Entry]bool{}
	for _, e := range f.Entries {
		root[e] = true
	}
	byUID := map[uint32][]Delegation{}
	var uids []uint32
	for _, d := range f.Delegations {
		if err := l.checkPrefix(d); err != nil {
			eff.Dropped = append(eff.Dropped, Dropped{UID: d.UID, Reason: fmt.Sprintf("delegation of %s: %v", d.Prefix, err)})
			continue
		}
		if _, ok := byUID[d.UID]; !ok {
			uids = append(uids, d.UID)
		}
		byUID[d.UID] = append(byUID[d.UID], d)
	}
	slices.Sort(uids)
	for _, uid := range uids {
		entries, err := l.loadUserFile(path, uid)
		if err != nil {
			eff.Dropped = append(eff.Dropped, Dropped{UID: uid, Reason: err.Error()})
			continue
		}
		for _, e := range entries {
			var why error
			admitted := false
			for _, d := range byUID[uid] {
				err := l.checkDelegated(d, e)
				if err == nil {
					admitted = true
					break
				}
				if why == nil || atOrUnderFold(e.Path, d.Prefix) {
					why = err
				}
			}
			if !admitted {
				eff.Dropped = append(eff.Dropped, Dropped{UID: uid, Entry: e, Reason: why.Error()})
				continue
			}
			if root[e] {
				continue
			}
			if _, dup := eff.Owners[e]; dup {
				continue
			}
			eff.Owners[e] = uid
			eff.Entries = append(eff.Entries, e)
		}
	}
	return eff, nil
}

// checkPrefix reports whether d can admit anything now: its uid is not the
// node's own, and its prefix is still a real directory owned by that uid.
func (l loader) checkPrefix(d Delegation) error {
	if d.UID == l.selfUID || d.UID == 0 {
		return fmt.Errorf("uid %d is the node's own or root, which is never delegated", d.UID)
	}
	resolved, err := filepath.EvalSymlinks(d.Prefix)
	if err != nil {
		return errors.New("the prefix does not exist")
	}
	if resolved != d.Prefix {
		return errors.New("the prefix contains a symlink")
	}
	fi, err := os.Lstat(d.Prefix)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("the prefix is not a directory")
	}
	if uid, ok := fileUID(fi); !ok || uid != d.UID {
		return fmt.Errorf("the prefix is not owned by uid %d", d.UID)
	}
	return nil
}

func (l loader) checkDelegated(d Delegation, e Entry) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %q: %s", ErrNotDelegated, e.Path, fmt.Sprintf(format, a...))
	}
	if err := l.validate(e); err != nil {
		return fmt.Errorf("%w: %w", ErrNotDelegated, err)
	}
	if !d.Allows(e.Mode) {
		return bad("mode %s is not delegated under %s", e.Mode, d.Prefix)
	}
	if !atOrUnderFold(e.Path, d.Prefix) {
		return bad("outside the delegated prefix %s", d.Prefix)
	}
	if err := l.checkPrefix(d); err != nil {
		return bad("%v", err)
	}
	resolved, err := filepath.EvalSymlinks(e.Path)
	if err != nil {
		return bad("the path does not exist")
	}
	if resolved != e.Path {
		return bad("the path contains a symlink")
	}
	pfi, err := os.Lstat(d.Prefix)
	if err != nil {
		return bad("%v", err)
	}
	// Both paths are ASCII (validated), so a case-folded match has the
	// prefix's length: the entry's own spelling of the prefix is its first
	// len(prefix) bytes.
	cur := e.Path[:len(d.Prefix)]
	comps := []string{}
	if rest := strings.TrimPrefix(e.Path[len(d.Prefix):], "/"); rest != "" {
		comps = strings.Split(rest, "/")
	}
	for i := 0; ; i++ {
		fi, err := os.Lstat(cur)
		if err != nil {
			return bad("%v", err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return bad("%s is a symlink", cur)
		}
		if uid, ok := fileUID(fi); !ok || uid != d.UID {
			return bad("%s is not owned by the delegated uid %d", cur, d.UID)
		}
		if i == 0 && !os.SameFile(fi, pfi) {
			return bad("%s is not the delegated directory %s", cur, d.Prefix)
		}
		if i == len(comps) {
			if !FoldsCase(cur) {
				return bad("on a case-sensitive volume, where the sandbox's case-insensitive match would also reach other names")
			}
			switch {
			case e.Mode == ModeSocket && fi.Mode()&os.ModeSocket == 0:
				return bad("not a Unix socket")
			case e.Mode != ModeSocket && !fi.IsDir():
				return bad("not a directory")
			}
			return nil
		}
		if !fi.IsDir() {
			return bad("%s is not a directory", cur)
		}
		cur = cur + "/" + comps[i]
	}
}

// loadUserFile reads uid's file under nodeFile. A missing directory or file
// is no entries. Otherwise <nodeFile>.d must be a root-owned directory no one
// else can write, <uid> a directory owned by uid that no one else can write,
// and the file a regular file (not a symlink) owned by uid that no one else
// can write. A pod runs as the node's own user, so it can write none of them.
func (l loader) loadUserFile(nodeFile string, uid uint32) ([]Entry, error) {
	parent := nodeFile + ".d"
	dir := UserDir(nodeFile, uid)
	for _, c := range []struct {
		path  string
		owner uint32
	}{{parent, l.rootUID}, {dir, uid}} {
		fi, err := os.Lstat(c.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnsafeFile, c.path, err)
		}
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafeFile, c.path)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return nil, fmt.Errorf("%w: %s is group- or other-writable", ErrUnsafeFile, c.path)
		}
		if owner, ok := fileUID(fi); !ok || owner != c.owner {
			return nil, fmt.Errorf("%w: %s is not owned by uid %d", ErrUnsafeFile, c.path, c.owner)
		}
	}
	path := UserFile(nodeFile, uid)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrUnsafeFile, path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: stat %s: %v", ErrUnsafeFile, path, err)
	}
	if err := checkOwnedBy(fi, uid); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnsafeFile, path, err)
	}
	uf, err := parse(f, false, l.validate)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(uf.Entries) > maxUserEntries {
		return nil, fmt.Errorf("%w: %s: more than %d entries", ErrInvalidEntry, path, maxUserEntries)
	}
	return uf.Entries, nil
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
