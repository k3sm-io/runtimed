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
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func TestValidateEntry(t *testing.T) {
	t.Parallel()
	ok := []Entry{
		{ModeReadWrite, "/Users/dev/Code/app"},
		{ModeReadWrite, "/Users/dev/Code/app.lanes"},
		{ModeReadOnly, "/Volumes/data/models"},
		{ModeSocket, "/Users/dev/Code/app/run/queue.sock"},
		{ModeReadWrite, "/opt/work"},
	}
	for _, e := range ok {
		if err := ValidateEntry(e); err != nil {
			t.Errorf("ValidateEntry(%v) = %v, want nil", e, err)
		}
	}
	bad := []Entry{
		{"rwx", "/Users/dev/Code/app"},
		{ModeReadWrite, ""},
		{ModeReadWrite, "relative/path"},
		{ModeReadWrite, "/"},
		{ModeReadWrite, "/Users/dev/Code/../.ssh"},
		{ModeReadWrite, "/Users/dev/Code/app/"},
		{ModeReadWrite, "/Users"},
		{ModeReadWrite, "/Users/dev"},
		{ModeReadWrite, "/Users/dev/.ssh"},
		{ModeReadWrite, "/Users/dev/Code/.secret"},
		{ModeReadWrite, "/Users/dev/Library"},
		{ModeReadWrite, "/Users/dev/Library/Keychains"},
		{ModeReadWrite, "/var/lib/k3sm"},
		{ModeReadWrite, "/private/var/lib/k3sm/pods"},
		{ModeReadWrite, "/private/var/db"},
		{ModeReadWrite, "/Library/k3sm"},
		{ModeReadWrite, "/Library"},
		{ModeReadWrite, "/private"},
		{ModeReadWrite, "/System/Library"},
		{ModeReadWrite, "/etc"},
		// Case variants name the same directories to APFS and Seatbelt.
		{ModeReadWrite, "/users/dev/.ssh"},
		{ModeReadWrite, "/users/dev"},
		{ModeReadWrite, "/USERS/dev/library/Preferences"},
		{ModeReadWrite, "/LIBRARY/KEYCHAINS"},
		{ModeReadWrite, "/system/Volumes/Data/Users/dev/Code"},
		{ModeReadWrite, "/PRIVATE/VAR/db"},
		{ModeReadWrite, "/Users/dev/Code/caf\u00e9"},
		{ModeReadWrite, "/Users/dev/Code/a\"b"},
		{ModeReadWrite, "/Users/dev/Code/a b"},
		{ModeReadWrite, "/Users/dev/Code/a\nb"},
		{ModeReadWrite, "/Users/dev/Code/" + strings.Repeat("x", maxPathBytes)},
	}
	for _, e := range bad {
		if err := ValidateEntry(e); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("ValidateEntry(%q %q) = %v, want ErrInvalidEntry", e.Mode, e.Path, err)
		}
	}
}

func TestParseAndFormat(t *testing.T) {
	t.Parallel()
	in := "# comment\n\nrw /Users/dev/Code/app\n  ro /Volumes/data  \nsocket /Users/dev/Code/app/q.sock\nrw /Users/dev/Code/app\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("Parse = %v, want 4 entries", got)
	}
	again, err := Parse(strings.NewReader(string(Format(got))))
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 3 {
		t.Errorf("Format did not de-duplicate: %v", again)
	}
	for _, in := range []string{
		"rw\n",
		"rw /a /b\n",
		"rw /Users/dev\n",
		"write /Users/dev/Code/app\n",
	} {
		if _, err := Parse(strings.NewReader(in)); !errors.Is(err, ErrInvalidEntry) {
			t.Errorf("Parse(%q) = %v, want ErrInvalidEntry (one bad line fails the file)", in, err)
		}
	}
	var many strings.Builder
	for i := 0; i <= maxEntries; i++ {
		many.WriteString("rw /opt/w\n")
	}
	if _, err := Parse(strings.NewReader(many.String())); !errors.Is(err, ErrInvalidEntry) {
		t.Errorf("Parse(%d entries) = %v, want ErrInvalidEntry", maxEntries+1, err)
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if got, err := Load(filepath.Join(dir, "missing")); err != nil || got != nil {
		t.Errorf("Load(missing) = %v, %v, want nil, nil (no file shares nothing)", got, err)
	}
	f := filepath.Join(dir, "shares")
	if err := os.WriteFile(f, []byte("rw /opt/w\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The test runs as a non-root user, so its own file is refused: that is
	// the property (a list the unprivileged daemon could have written).
	if os.Geteuid() != 0 {
		if _, err := Load(f); !errors.Is(err, ErrUnsafeFile) {
			t.Errorf("Load(user-owned) = %v, want ErrUnsafeFile", err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(f, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("Load(symlink) = %v, want ErrUnsafeFile", err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrUnsafeFile) {
		t.Errorf("Load(dir) = %v, want ErrUnsafeFile", err)
	}
}

func TestCheckOwnership(t *testing.T) {
	t.Parallel()
	// A root-owned system file passes; a user file and a writable one do not.
	fi, err := os.Stat("/etc/hosts")
	if err != nil {
		t.Skip(err)
	}
	if err := checkOwnership(fi); err != nil {
		t.Errorf("checkOwnership(/etc/hosts) = %v, want nil", err)
	}
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o666); err != nil {
		t.Fatal(err)
	}
	ufi, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOwnership(ufi); err == nil {
		t.Error("checkOwnership(group/other-writable user file) = nil, want an error")
	}
}

// fakeFS is a fileChecker over a fixed table.
type fakeFS struct {
	kinds map[string]string
	links map[string]string
}

func (f fakeFS) resolve(p string) (string, error) {
	if r, ok := f.links[p]; ok {
		return r, nil
	}
	if _, ok := f.kinds[p]; !ok {
		return "", os.ErrNotExist
	}
	return p, nil
}

func (f fakeFS) kind(p string) (string, error) {
	k, ok := f.kinds[p]
	if !ok {
		return "", os.ErrNotExist
	}
	return k, nil
}

func hostPathBox(path, typ, mountPath, subPath string, readOnly ...bool) *runtimev1.PodBox {
	box := &runtimev1.PodBox{
		Volumes: []*runtimev1.Volume{{Name: "code", HostPath: &runtimev1.HostPathVolumeSource{Path: path, Type: typ}}},
	}
	if len(readOnly) == 0 {
		readOnly = []bool{false}
	}
	for i, ro := range readOnly {
		box.Containers = append(box.Containers, &runtimev1.Container{
			Name:         "c" + string(rune('0'+i)),
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "code", MountPath: mountPath, SubPath: subPath, ReadOnly: ro}},
		})
	}
	return box
}

func TestAuthorize(t *testing.T) {
	t.Parallel()
	const repo = "/Users/dev/Code/app"
	fs := fakeFS{
		kinds: map[string]string{
			repo:                  "dir",
			repo + "/sub":         "dir",
			"/Volumes/data":       "dir",
			repo + "/run/q.sock":  "socket",
			repo + "/file":        "other",
			"/Users/dev/Code/oth": "dir",
			repo + "/escape":      "dir",
		},
		links: map[string]string{repo + "/escape": "/Users/dev/.ssh"},
	}
	entries := []Entry{
		{ModeReadWrite, repo},
		{ModeReadOnly, "/Volumes/data"},
		{ModeSocket, repo + "/run/q.sock"},
	}
	granted := []struct {
		name string
		box  *runtimev1.PodBox
		want Grant
	}{
		{"rw_root", hostPathBox(repo, "Directory", repo, ""), Grant{Volume: "code", Path: repo}},
		{"rw_untyped_subdir", hostPathBox(repo+"/sub", "", repo+"/sub", ""), Grant{Volume: "code", Path: repo + "/sub"}},
		{"rw_entry_mounted_ro", hostPathBox(repo, "", repo, "", true), Grant{Volume: "code", Path: repo, ReadOnly: true}},
		{"ro_entry", hostPathBox("/Volumes/data", "", "/Volumes/data", "", true, true), Grant{Volume: "code", Path: "/Volumes/data", ReadOnly: true}},
		{"socket", hostPathBox(repo+"/run/q.sock", "Socket", repo+"/run/q.sock", ""), Grant{Volume: "code", Path: repo + "/run/q.sock", Socket: true}},
	}
	for _, tc := range granted {
		t.Run("grant/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := authorize(entries, tc.box, fs)
			if err != nil {
				t.Fatalf("authorize = %v, want a grant", err)
			}
			if len(got) != 1 {
				t.Fatalf("authorize = %v, want one grant", got)
			}
			g := got[0]
			g.Entry = Entry{}
			if g != tc.want {
				t.Errorf("grant = %+v, want %+v", g, tc.want)
			}
		})
	}
	refused := []struct {
		name string
		box  *runtimev1.PodBox
	}{
		{"not_listed", hostPathBox("/Users/dev/Code/oth", "", "/Users/dev/Code/oth", "")},
		{"parent_of_entry", hostPathBox("/Users/dev/Code", "", "/Users/dev/Code", "")},
		{"other_mount_path", hostPathBox(repo, "", "/workspace", "")},
		{"subpath", hostPathBox(repo, "", repo, "sub")},
		{"unclean", hostPathBox(repo+"/../oth", "", repo+"/../oth", "")},
		{"symlink", hostPathBox(repo+"/escape", "", repo+"/escape", "")},
		{"missing", hostPathBox(repo+"/nope", "", repo+"/nope", "")},
		{"file_type", hostPathBox(repo+"/file", "File", repo+"/file", "")},
		{"not_a_dir", hostPathBox(repo+"/file", "", repo+"/file", "")},
		{"create_type", hostPathBox(repo+"/sub", "DirectoryOrCreate", repo+"/sub", "")},
		{"ro_entry_mounted_rw", hostPathBox("/Volumes/data", "", "/Volumes/data", "")},
		{"mixed_ro_rw", hostPathBox(repo, "", repo, "", true, false)},
		{"socket_as_dir", hostPathBox(repo+"/run/q.sock", "Directory", repo+"/run/q.sock", "")},
		{"dir_entry_as_socket", hostPathBox(repo+"/sub", "Socket", repo+"/sub", "")},
	}
	for _, tc := range refused {
		t.Run("refuse/"+tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := authorize(entries, tc.box, fs); !errors.Is(err, ErrNotShared) {
				t.Errorf("authorize = %v, %v, want ErrNotShared", got, err)
			}
		})
	}
	t.Run("no_entries_refuses", func(t *testing.T) {
		t.Parallel()
		if _, err := authorize(nil, hostPathBox(repo, "", repo, ""), fs); !errors.Is(err, ErrNotShared) {
			t.Errorf("authorize(no entries) = %v, want ErrNotShared", err)
		}
	})
	t.Run("unmounted_volume_is_ignored", func(t *testing.T) {
		t.Parallel()
		box := hostPathBox("/Users/dev/Code/oth", "", "/x", "")
		box.Containers = nil
		if got, err := authorize(nil, box, fs); err != nil || len(got) != 0 {
			t.Errorf("authorize(unmounted) = %v, %v, want no grant and no error", got, err)
		}
	})
	t.Run("invalid_entry_admits_nothing", func(t *testing.T) {
		t.Parallel()
		if _, err := authorize([]Entry{{ModeReadWrite, "/Users/dev"}}, hostPathBox(repo, "", repo, ""), fs); !errors.Is(err, ErrNotShared) {
			t.Errorf("authorize(invalid entry) = %v, want ErrNotShared", err)
		}
	})
}

// TestMatchMostSpecificEntryWins pins that a narrower read-only entry
// narrows a broader read-write one, and that read-write wins only between
// two entries for the same path.
func TestMatchMostSpecificEntryWins(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{ModeReadWrite, "/Users/dev/Code/app"},
		{ModeReadOnly, "/Users/dev/Code/app/secrets"},
		{ModeReadOnly, "/Volumes/data"},
		{ModeReadWrite, "/Volumes/data"},
	}
	for _, tc := range []struct {
		path string
		want Mode
	}{
		{"/Users/dev/Code/app", ModeReadWrite},
		{"/Users/dev/Code/app/src", ModeReadWrite},
		{"/Users/dev/Code/app/secrets", ModeReadOnly},
		{"/Users/dev/Code/app/secrets/k", ModeReadOnly},
		{"/Volumes/data/x", ModeReadWrite},
	} {
		got, ok := match(entries, tc.path, "Directory")
		if !ok || got.Mode != tc.want {
			t.Errorf("match(%s) = %v %v, want mode %s", tc.path, got, ok, tc.want)
		}
	}
}
