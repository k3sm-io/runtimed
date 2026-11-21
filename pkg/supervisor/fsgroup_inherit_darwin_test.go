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

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDarwinNewEntriesTakeTheParentsGroup measures what the runtime's
// root-posture fsGroup path stands on: an entry created in a directory takes
// that directory's group, whatever the creator's own group, for every way the
// daemon creates entries in a pod's tree (mkdirat, openat O_CREAT, symlinkat,
// mkfifo, and clonefileat of a file and of a tree, whose source has another
// group), while an entry renamed in keeps the group it had.
func TestDarwinNewEntriesTakeTheParentsGroup(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "rootfs")
	src := filepath.Join(base, "src")
	for _, d := range []string{dir, src, filepath.Join(src, "tree", "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "tree", "sub", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "moved"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var sst unix.Stat_t
	if err := unix.Lstat(src, &sst); err != nil {
		t.Fatal(err)
	}
	gid := fsGroupTestGid(t, src)
	if err := os.Chown(dir, -1, gid); err != nil {
		t.Fatal(err)
	}
	t.Logf("the creator's gid %d, the source's gid %d, the directory's gid %d", os.Getegid(), sst.Gid, gid)

	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd)
	sfd, err := unix.Open(src, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sfd)
	steps := []struct {
		name string
		make func() error
		want uint32
	}{
		{"mkdirat", func() error { return unix.Mkdirat(dfd, "d", 0o755) }, uint32(gid)},
		{"openat O_CREAT", func() error {
			fd, err := unix.Openat(dfd, "f", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o644)
			if err == nil {
				unix.Close(fd)
			}
			return err
		}, uint32(gid)},
		{"symlinkat", func() error { return unix.Symlinkat("f", dfd, "l") }, uint32(gid)},
		{"mkfifo", func() error { return unix.Mkfifo(filepath.Join(dir, "p"), 0o644) }, uint32(gid)},
		{"clonefileat of a file", func() error { return unix.Clonefileat(sfd, "file", dfd, "cf", unix.CLONE_NOFOLLOW) }, uint32(gid)},
		{"clonefileat of a tree", func() error { return unix.Clonefileat(sfd, "tree", dfd, "ct", unix.CLONE_NOFOLLOW) }, uint32(gid)},
		{"renameat in (keeps its group)", func() error { return unix.Renameat(sfd, "moved", dfd, "moved") }, sst.Gid},
	}
	for _, s := range steps {
		if err := s.make(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	for name, want := range map[string]uint32{
		"d": uint32(gid), "f": uint32(gid), "l": uint32(gid), "p": uint32(gid), "cf": uint32(gid),
		"ct": uint32(gid), "ct/sub": uint32(gid), "ct/sub/f": uint32(gid), "moved": sst.Gid,
	} {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(dir, name), &st); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: gid %d", name, st.Gid)
		if st.Gid != want {
			t.Errorf("%s has gid %d, want %d", name, st.Gid, want)
		}
	}
}
