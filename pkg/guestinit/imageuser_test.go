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

package guestinit

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	guestv1 "k3sm.io/apis/guest/v1"
)

const (
	fixturePasswd = "root:x:0:0:root:/root:/bin/sh\napp:x:1000:1001::/home/app:/bin/sh\n"
	fixtureGroup  = "root:x:0:\nstaff:x:50:\napp:x:1001:\n"
	// decoyPasswd is what an ESCAPE would read: "app" as root. Any resolution
	// that returns uid 0 for "app" read the decoy.
	decoyPasswd = "app:x:0:0::/:/bin/sh\n"
)

// rootfsFixture builds a container root and, beside it (outside it), a decoy
// tree holding decoyPasswd. It returns both paths.
func rootfsFixture(t *testing.T) (root, decoy string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	decoy = filepath.Join(base, "decoy")
	for _, d := range []string{filepath.Join(root, "etc"), decoy} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(decoy, "passwd"), []byte(decoyPasswd), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, decoy
}

func writeEtc(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestResolveImageUserInRootfs pins in-guest resolution of
// GuestContainer.image_user against the container's own rootfs: the resolution
// rules, the precedence over a stamped uid, and — the security half — that no
// symlink shape, non-regular file or missing name can make it read outside the
// container root or fall back to uid 0.
//
// Every escape leg places a decoy passwd OUTSIDE the root that maps "app" to
// uid 0, and asserts the decoy was not used: a resolver that followed the
// link with the host's own path resolution would return uid 0 for "app".
func TestResolveImageUserInRootfs(t *testing.T) {
	supplemental := []int64{5, 2000}

	t.Run("resolution rules", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		writeEtc(t, root, "passwd", fixturePasswd)
		writeEtc(t, root, "group", fixtureGroup)
		cases := []struct {
			user     string
			uid, gid int64
		}{
			{"app", 1000, 1001},
			{"app:1000", 1000, 1000},
			{"app:staff", 1000, 50},
			{"root", 0, 0},
			// numeric with a passwd entry: that entry's gid (containerd's WithUserID).
			{"1000", 1000, 1001},
			// numeric with no passwd entry: gid 0.
			{"4242", 4242, 0},
			// numeric with an explicit group keeps it.
			{"1000:77", 1000, 77},
			{"4242:staff", 4242, 50},
		}
		for _, tc := range cases {
			got, err := ResolveImageUser(root, tc.user, supplemental)
			if err != nil {
				t.Errorf("%q: %v", tc.user, err)
				continue
			}
			want := Ident{UID: tc.uid, GID: tc.gid, Groups: supplemental}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%q = %+v, want %+v", tc.user, got, want)
			}
		}
	})

	t.Run("an unresolvable name is an error, never uid 0", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		writeEtc(t, root, "passwd", fixturePasswd)
		writeEtc(t, root, "group", fixtureGroup)
		for _, user := range []string{"ghost", "app:nogroup"} {
			got, err := ResolveImageUser(root, user, nil)
			if !errors.Is(err, ErrNoSuchUser) {
				t.Errorf("%q: err = %v, want ErrNoSuchUser", user, err)
			}
			if !reflect.DeepEqual(got, Ident{}) {
				t.Errorf("%q returned identity %+v alongside the error", user, got)
			}
		}
		// A name in a scratch image (no passwd at all) is still unresolvable.
		bare, _ := rootfsFixture(t)
		if _, err := ResolveImageUser(bare, "app", nil); !errors.Is(err, ErrNoSuchUser) {
			t.Errorf("name with no passwd: err = %v, want ErrNoSuchUser", err)
		}
	})

	t.Run("grammar", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		for _, user := range []string{"a:b:c", ":staff", "app:", ""} {
			if _, err := ResolveImageUser(root, user, nil); !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("%q: err = %v, want ErrInvalidSpec", user, err)
			}
		}
	})

	escapes := []struct {
		name  string
		build func(t *testing.T, root, decoy string)
	}{
		{"absolute symlink passwd", func(t *testing.T, root, decoy string) {
			// To the decoy's HOST path: chroot semantics read it as a path inside
			// the root, where nothing exists.
			if err := os.Symlink(filepath.Join(decoy, "passwd"), filepath.Join(root, "etc", "passwd")); err != nil {
				t.Fatal(err)
			}
		}},
		{"relative dot-dot symlink passwd", func(t *testing.T, root, _ string) {
			if err := os.Symlink("../../decoy/passwd", filepath.Join(root, "etc", "passwd")); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked etc dir", func(t *testing.T, root, _ string) {
			if err := os.Remove(filepath.Join(root, "etc")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../decoy", filepath.Join(root, "etc")); err != nil {
				t.Fatal(err)
			}
		}},
		{"absolute symlinked etc dir", func(t *testing.T, root, decoy string) {
			if err := os.Remove(filepath.Join(root, "etc")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoy, filepath.Join(root, "etc")); err != nil {
				t.Fatal(err)
			}
		}},
		{"dangling symlink", func(t *testing.T, root, _ string) {
			if err := os.Symlink("/nowhere/passwd", filepath.Join(root, "etc", "passwd")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range escapes {
		t.Run("escape: "+tc.name, func(t *testing.T) {
			root, decoy := rootfsFixture(t)
			tc.build(t, root, decoy)
			got, err := ResolveImageUser(root, "app", nil)
			if err == nil {
				t.Fatalf("resolved %+v; want an error (the decoy maps app to uid 0)", got)
			}
			if !errors.Is(err, ErrUserDatabase) {
				t.Errorf("err = %v, want ErrUserDatabase", err)
			}
		})
	}

	t.Run("a container-absolute symlink inside the root is followed", func(t *testing.T) {
		// The positive control for the escape legs: chroot semantics are not a
		// blanket refusal of absolute links.
		root, _ := rootfsFixture(t)
		if err := os.MkdirAll(filepath.Join(root, "usr", "lib"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "usr", "lib", "passwd"), []byte(fixturePasswd), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/lib/passwd", filepath.Join(root, "etc", "passwd")); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveImageUser(root, "app", nil)
		if err != nil || got.UID != 1000 {
			t.Fatalf("got %+v, %v; want uid 1000", got, err)
		}
	})

	t.Run("a FIFO passwd is an error and does not hang", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		if err := syscall.Mkfifo(filepath.Join(root, "etc", "passwd"), 0o644); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := ResolveImageUser(root, "app", nil)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrUserDatabase) {
				t.Errorf("err = %v, want ErrUserDatabase", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("resolution blocked on a FIFO")
		}
	})

	t.Run("a directory passwd is an error", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		if err := os.Mkdir(filepath.Join(root, "etc", "passwd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveImageUser(root, "app", nil); !errors.Is(err, ErrUserDatabase) {
			t.Errorf("err = %v, want ErrUserDatabase", err)
		}
	})

	t.Run("an oversized passwd is an error", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		big := make([]byte, maxUserDatabaseBytes+1)
		if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), big, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveImageUser(root, "app", nil); !errors.Is(err, ErrUserDatabase) {
			t.Errorf("err = %v, want ErrUserDatabase", err)
		}
	})

	t.Run("no passwd and a numeric user works", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		got, err := ResolveImageUser(root, "1000", supplemental)
		if err != nil {
			t.Fatalf("ResolveImageUser: %v", err)
		}
		if want := (Ident{UID: 1000, GID: 0, Groups: supplemental}); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a numeric uid:gid does not read a hostile passwd", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		if err := syscall.Mkfifo(filepath.Join(root, "etc", "passwd"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolveImageUser(root, "1000:1000", nil); err != nil {
			t.Fatalf("numeric uid:gid: %v (no lookup is needed, so the file must not be read)", err)
		}
		// Without a group half the default gid comes from passwd, so the
		// hostile file is read and refused.
		if _, err := ResolveImageUser(root, "1000", nil); !errors.Is(err, ErrUserDatabase) {
			t.Fatalf("numeric uid over a FIFO passwd: err = %v, want ErrUserDatabase", err)
		}
	})

	t.Run("image_user beats a stamped uid and keeps the supplemental gids", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		writeEtc(t, root, "passwd", fixturePasswd)
		c := &guestv1.GuestContainer{
			Name: "app", Uid: 4242, Gid: 4242, ImageUser: "app",
			SupplementalGids: []int64{2000}, RootfsTag: "k3sm.rootfs", Command: []string{"/x"},
		}
		ident, err := ContainerIdent(c, 3000)
		if err != nil {
			t.Fatalf("ContainerIdent: %v", err)
		}
		cp := ContainerPlan{Name: "app", Root: root, Ident: ident, PendingImageUser: c.GetImageUser()}
		if err := ResolvePlanIdent(&cp); err != nil {
			t.Fatalf("ResolvePlanIdent: %v", err)
		}
		want := Ident{UID: 1000, GID: 1001, Groups: []int64{2000, 3000}}
		if !reflect.DeepEqual(cp.Ident, want) {
			t.Errorf("ident = %+v, want %+v (image_user wins, host groups kept)", cp.Ident, want)
		}
		if cp.PendingImageUser != "" {
			t.Errorf("pending mark not cleared: %q", cp.PendingImageUser)
		}
	})

	t.Run("a failed resolution leaves the identity pending", func(t *testing.T) {
		root, _ := rootfsFixture(t)
		cp := ContainerPlan{Name: "app", Root: root, PendingImageUser: "ghost"}
		if err := ResolvePlanIdent(&cp); err == nil {
			t.Fatal("ResolvePlanIdent succeeded for an unknown name")
		}
		if cp.PendingImageUser != "ghost" {
			t.Errorf("pending mark = %q; a failed resolution must not clear it", cp.PendingImageUser)
		}
	})
}
