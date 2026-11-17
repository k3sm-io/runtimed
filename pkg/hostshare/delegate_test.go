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
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDelegationParseAndFormat(t *testing.T) {
	t.Parallel()
	in := "rw /opt/w\ndelegate uid=501 user=dev modes=rw,socket /Users/dev/Code\n"
	f, err := ParseFile(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := Delegation{UID: 501, User: "dev", Modes: []Mode{ModeReadWrite, ModeSocket}, Prefix: "/Users/dev/Code"}
	if len(f.Entries) != 1 || len(f.Delegations) != 1 || f.Delegations[0].String() != want.String() {
		t.Fatalf("ParseFile = %+v, want one entry and %v", f, want)
	}
	if !f.Delegations[0].Allows(ModeSocket) || f.Delegations[0].Allows(ModeReadOnly) {
		t.Errorf("Allows: modes not honoured: %v", f.Delegations[0])
	}
	again, err := ParseFile(strings.NewReader(string(FormatFile(f))))
	if err != nil || len(again.Delegations) != 1 || again.Delegations[0].String() != want.String() {
		t.Errorf("FormatFile round trip = %+v, %v", again, err)
	}
	// A user's own file may never carry a delegation: that would let the
	// user widen their own prefix.
	if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("Parse(user file with a delegate line) = %v, want ErrInvalidEntry", err)
	}
	for _, line := range []string{
		"delegate uid=250 user=_k3sm modes=rw /Users/dev/Code",  // the pods' own user
		"delegate uid=0 user=root modes=rw /Users/dev/Code",     // root
		"delegate uid=501 user=dev modes=rw /Users/dev",         // a whole home
		"delegate uid=501 user=dev modes=rw /Users",             // /Users
		"delegate uid=501 user=dev modes=rw /users/DEV",         // a whole home, other case
		"delegate uid=501 user=dev modes=rw /Users/dev/.ssh",    // a dot directory
		"delegate uid=501 user=dev modes=rw /Users/dev/library", // the home's Library, other case
		"delegate uid=501 user=dev modes=rw /Library/k3sm.host-shares.d",
		"delegate uid=501 user=dev modes=rw /Users/dev/Code/../x",
		"delegate uid=501 user=dev modes=rw /Users/dev/Cöde",
		"delegate uid=501 user=dev modes=rwx /Users/dev/Code",
		"delegate uid=501 user=dev modes= /Users/dev/Code",
		"delegate uid=501 user=d;ev modes=rw /Users/dev/Code",
		"delegate uid=501 modes=rw /Users/dev/Code",
		"delegate user=dev uid=501 modes=rw /Users/dev/Code",
		"delegate uid=-1 user=dev modes=rw /Users/dev/Code",
	} {
		if _, err := ParseFile(strings.NewReader(line + "\n")); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("ParseFile(%q) = %v, want ErrInvalidEntry", line, err)
		}
	}
}

// fixture is a node file and one delegated user's tree in a temp dir, read
// by a loader that treats the test user as root for file ownership and
// accepts temp paths (which sit under the refused /var) by checking the
// part below the temp root against the real rules.
type fixture struct {
	root, nodeFile, prefix string
	uid                    uint32
	l                      loader
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if os.Getuid() == 0 || os.Getuid() < MinDelegateUID {
		t.Skip("needs an ordinary user account: the test delegates to itself")
	}
	// A short root: a Unix socket path is limited to 104 bytes, and
	// t.TempDir is long on macOS.
	tmp, err := os.MkdirTemp("/tmp", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	root, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{root: root, nodeFile: filepath.Join(root, "k3sm.host-shares"), prefix: filepath.Join(root, "Code"), uid: uint32(os.Getuid())}
	f.l = loader{rootUID: f.uid, selfUID: 1, validate: func(e Entry) error {
		if !strings.HasPrefix(e.Path, root+"/") {
			return ValidateEntry(e)
		}
		return ValidateEntry(Entry{Mode: e.Mode, Path: "/Users/dev" + strings.TrimPrefix(e.Path, root)})
	}}
	for _, d := range []string{f.prefix, filepath.Join(f.prefix, "app", "src"), filepath.Join(root, "Other")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(UserDir(f.nodeFile, f.uid), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{f.nodeFile + ".d", UserDir(f.nodeFile, f.uid)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) delegation(modes ...Mode) Delegation {
	if len(modes) == 0 {
		modes = []Mode{ModeReadWrite, ModeReadOnly, ModeSocket}
	}
	return Delegation{UID: f.uid, User: "dev", Modes: modes, Prefix: f.prefix}
}

func (f *fixture) writeNode(t *testing.T, file File) {
	t.Helper()
	if err := os.WriteFile(f.nodeFile, FormatFile(file), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeUser(t *testing.T, body string) {
	t.Helper()
	p := UserFile(f.nodeFile, f.uid)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckDelegatedPrefixContainment(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	d := f.delegation()
	app := filepath.Join(f.prefix, "app")
	sock := filepath.Join(app, "q.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Symlink(filepath.Join(f.root, "Other"), filepath.Join(f.prefix, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(app, "src"), filepath.Join(f.prefix, "in")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.prefix+"-secrets", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(app, "file"), filepath.Join(app, "hardlink")); err != nil {
		t.Fatal(err)
	}
	ok := []Entry{
		{Mode: ModeReadWrite, Path: f.prefix},
		{Mode: ModeReadWrite, Path: app},
		{Mode: ModeReadOnly, Path: filepath.Join(app, "src")},
		{Mode: ModeSocket, Path: sock},
	}
	for _, e := range ok {
		if err := f.l.checkDelegated(d, e); err != nil {
			t.Errorf("checkDelegated(%v) = %v, want nil", e, err)
		}
	}
	bad := map[string]Entry{
		"sibling_of_prefix":            {Mode: ModeReadWrite, Path: filepath.Join(f.root, "Other")},
		"shares_the_prefix_string":     {Mode: ModeReadWrite, Path: f.prefix + "-secrets"},
		"parent_of_prefix":             {Mode: ModeReadWrite, Path: f.root},
		"dot_dot_escape":               {Mode: ModeReadWrite, Path: f.prefix + "/../Other"},
		"symlink_out_of_prefix":        {Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "out")},
		"symlink_inside_prefix":        {Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "in")},
		"through_symlink":              {Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "in", "x")},
		"dot_directory_inside":         {Mode: ModeReadWrite, Path: filepath.Join(f.prefix, ".git")},
		"missing":                      {Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "nope")},
		"socket_mode_on_a_dir":         {Mode: ModeSocket, Path: app},
		"dir_mode_on_a_socket":         {Mode: ModeReadWrite, Path: sock},
		"a_file_is_never_an_entry":     {Mode: ModeReadWrite, Path: filepath.Join(app, "file")},
		"a_hard_link_is_never_a_entry": {Mode: ModeReadOnly, Path: filepath.Join(app, "hardlink")},
	}
	if err := os.Mkdir(filepath.Join(f.prefix, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, e := range bad {
		if err := f.l.checkDelegated(d, e); err == nil || !errors.Is(err, ErrNotDelegated) {
			t.Errorf("%s: checkDelegated(%v) = %v, want ErrNotDelegated", name, e, err)
		}
	}
	if err := f.l.checkDelegated(f.delegation(ModeReadOnly), Entry{Mode: ModeReadWrite, Path: app}); !errors.Is(err, ErrNotDelegated) {
		t.Errorf("checkDelegated(rw under an ro-only delegation) = %v, want ErrNotDelegated", err)
	}
}

// TestCheckDelegatedCaseFolding pins the case rules: a spelling of the prefix
// in another case is the prefix only when it is the same directory (APFS's
// default, case-insensitive volume), and is refused otherwise.
func TestCheckDelegatedCaseFolding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	upper := strings.TrimSuffix(f.prefix, "Code") + "CODE"
	e := Entry{Mode: ModeReadWrite, Path: upper + "/app"}
	_, statErr := os.Lstat(upper)
	err := f.l.checkDelegated(f.delegation(), e)
	switch {
	case statErr == nil && err != nil:
		t.Errorf("case-insensitive volume: checkDelegated(%v) = %v, want nil (the same directory)", e, err)
	case statErr != nil && err == nil:
		t.Errorf("case-sensitive volume: checkDelegated(%v) = nil, want a refusal", e)
	}
	// A refused name in another case is refused whatever the volume.
	if err := f.l.checkDelegated(f.delegation(), Entry{Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "app", ".GIT")}); err == nil {
		t.Error("checkDelegated(dot directory) = nil, want a refusal")
	}
}

func TestCheckDelegatedOwnership(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// The prefix is the test user's; a delegation naming another uid admits
	// nothing under it, because the prefix and the path are not that uid's.
	d := f.delegation()
	d.UID = f.uid + 1
	if err := f.l.checkDelegated(d, Entry{Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "app")}); !errors.Is(err, ErrNotDelegated) {
		t.Errorf("checkDelegated(owned by another uid) = %v, want ErrNotDelegated", err)
	}
	// The pods' own uid is never a delegated user.
	l := f.l
	l.selfUID = f.uid
	if err := l.checkDelegated(f.delegation(), Entry{Mode: ModeReadWrite, Path: filepath.Join(f.prefix, "app")}); !errors.Is(err, ErrNotDelegated) {
		t.Errorf("checkDelegated(delegated to the daemon's own uid) = %v, want ErrNotDelegated", err)
	}
	// A root-owned tree delegated to the test user admits nothing: the
	// owner check runs on the real filesystem, not on the record.
	rd := Delegation{UID: f.uid, User: "dev", Modes: []Mode{ModeReadWrite}, Prefix: "/usr"}
	if err := f.l.checkDelegated(rd, Entry{Mode: ModeReadWrite, Path: "/usr/bin"}); !errors.Is(err, ErrNotDelegated) {
		t.Errorf("checkDelegated(root-owned tree) = %v, want ErrNotDelegated", err)
	}
}

func TestLoadEffectiveDelegated(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	app := filepath.Join(f.prefix, "app")
	f.writeNode(t, File{Entries: []Entry{{Mode: ModeReadOnly, Path: "/opt/data"}}, Delegations: []Delegation{f.delegation()}})
	// The user's file has one good line and two it could only have written
	// by hand: a path outside the prefix, and a symlink inside it pointing
	// out. Enforcement re-validates, so only the good one is admitted.
	if err := os.Symlink(filepath.Join(f.root, "Other"), filepath.Join(f.prefix, "out")); err != nil {
		t.Fatal(err)
	}
	f.writeUser(t, "rw "+app+"\nrw "+filepath.Join(f.root, "Other")+"\nrw "+filepath.Join(f.prefix, "out")+"\n")
	eff, err := f.l.loadEffective(f.nodeFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.Entries) != 2 || eff.Entries[1].String() != (Entry{Mode: ModeReadWrite, Path: app}).String() {
		t.Fatalf("Entries = %v, want the root entry and %s", eff.Entries, app)
	}
	if uid, ok := eff.Owner(Entry{Mode: ModeReadWrite, Path: app}); !ok || uid != f.uid {
		t.Errorf("Owners = %v, want %s owned by %d", eff.Owners, app, f.uid)
	}
	if _, ok := eff.Owner(Entry{Mode: ModeReadOnly, Path: "/opt/data"}); ok {
		t.Error("a root entry is recorded as delegated")
	}
	if len(eff.Dropped) != 2 {
		t.Errorf("Dropped = %v, want the two tampered lines", eff.Dropped)
	}

	t.Run("revoking_the_delegation_drops_the_users_entries", func(t *testing.T) {
		f.writeNode(t, File{Entries: []Entry{{Mode: ModeReadOnly, Path: "/opt/data"}}})
		eff, err := f.l.loadEffective(f.nodeFile)
		if err != nil {
			t.Fatal(err)
		}
		if len(eff.Entries) != 1 || len(eff.Owners) != 0 {
			t.Errorf("after revoke: Entries = %v, want only the root entry", eff.Entries)
		}
		f.writeNode(t, File{Entries: []Entry{{Mode: ModeReadOnly, Path: "/opt/data"}}, Delegations: []Delegation{f.delegation()}})
	})
}

func TestLoadEffectiveRefusesAnUnsafeUserFile(t *testing.T) {
	t.Parallel()
	app := func(f *fixture) string { return filepath.Join(f.prefix, "app") }
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *fixture)
	}{
		{"group_writable_file", func(t *testing.T, f *fixture) {
			f.writeUser(t, "rw "+app(f)+"\n")
			if err := os.Chmod(UserFile(f.nodeFile, f.uid), 0o664); err != nil {
				t.Fatal(err)
			}
		}},
		{"other_writable_dir", func(t *testing.T, f *fixture) {
			f.writeUser(t, "rw "+app(f)+"\n")
			if err := os.Chmod(UserDir(f.nodeFile, f.uid), 0o757); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked_file", func(t *testing.T, f *fixture) {
			other := filepath.Join(f.root, "elsewhere")
			if err := os.WriteFile(other, []byte("rw "+app(f)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, UserFile(f.nodeFile, f.uid)); err != nil {
				t.Fatal(err)
			}
		}},
		{"user_file_delegates_itself", func(t *testing.T, f *fixture) {
			f.writeUser(t, "rw "+app(f)+"\ndelegate uid=501 user=dev modes=rw "+f.root+"\n")
		}},
		{"delegated_to_the_pods_uid", func(t *testing.T, f *fixture) {
			f.l.selfUID = f.uid
			f.writeUser(t, "rw "+app(f)+"\n")
		}},
		{"prefix_replaced_by_a_symlink", func(t *testing.T, f *fixture) {
			f.writeUser(t, "rw "+app(f)+"\n")
			moved := filepath.Join(f.root, "moved")
			if err := os.Rename(f.prefix, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, f.prefix); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.writeNode(t, File{Delegations: []Delegation{f.delegation()}})
			tc.setup(t, f)
			eff, err := f.l.loadEffective(f.nodeFile)
			if err != nil {
				t.Fatalf("loadEffective = %v; a bad user file must not fail the node file", err)
			}
			if len(eff.Entries) != 0 || len(eff.Dropped) == 0 {
				t.Errorf("Entries = %v, Dropped = %v; want nothing admitted and a reason", eff.Entries, eff.Dropped)
			}
		})
	}
	t.Run("node_file_not_owned_by_root", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		f.writeNode(t, File{Delegations: []Delegation{f.delegation()}})
		f.l.rootUID = f.uid + 1
		if _, err := f.l.loadEffective(f.nodeFile); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("loadEffective = %v, want ErrUnsafeFile", err)
		}
	})
}

// caseSensitiveFS is fakeFS on a case-sensitive volume.
type caseSensitiveFS struct{ fakeFS }

func (caseSensitiveFS) foldsCase(string) bool { return false }

// TestCaseSensitiveVolumeIsRefused pins that a share on a case-sensitive
// volume is refused: Seatbelt matches the granted path without regard to
// case even there, so the grant would also reach differently cased
// siblings someone else may own.
func TestCaseSensitiveVolumeIsRefused(t *testing.T) {
	t.Parallel()
	fs := caseSensitiveFS{fakeFS{kinds: map[string]string{"/Volumes/dev/app": "dir"}}}
	box := hostPathBox("/Volumes/dev/app", "Directory", "/Volumes/dev/app", "")
	if _, err := authorize([]Entry{{Mode: ModeReadWrite, Path: "/Volumes/dev"}}, "default", box, fs); !errors.Is(err, ErrNotShared) {
		t.Errorf("authorize on a case-sensitive volume = %v, want ErrNotShared", err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	upper := dir + "/X"
	if err := os.Mkdir(upper, 0o755); err != nil {
		t.Fatal(err)
	}
	_, lowerErr := os.Lstat(dir + "/x")
	if got := FoldsCase(upper); got != (lowerErr == nil) {
		t.Errorf("FoldsCase(%s) = %v, but the other case resolves: %v", upper, got, lowerErr == nil)
	}
	if FoldsCase(filepath.Join(dir, "missing")) {
		t.Error("FoldsCase(missing path) = true, want false")
	}
}
