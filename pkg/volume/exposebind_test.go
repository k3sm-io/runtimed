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

package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
)

// aclCall is one call a fakeACL saw.
type aclCall struct {
	op        string
	dir       string
	uid       uint32
	readWrite bool
}

// fakeACL records calls and returns err for every Grant.
type fakeACL struct {
	calls []aclCall
	err   error
}

func (f *fakeACL) Grant(dir string, uid uint32, readWrite bool) error {
	f.calls = append(f.calls, aclCall{"grant", dir, uid, readWrite})
	return f.err
}

func (f *fakeACL) Revoke(dir string, uid uint32) error {
	f.calls = append(f.calls, aclCall{"revoke", dir, uid, false})
	return nil
}

// exposeBox is a pod demo-0 in namespace yurei-system with an exposure volume
// "sockets" at /var/run/yureid, plus any extra mounts (an emptyDir each).
func exposeBox(extra ...string) *runtimev1.PodBox {
	box := &runtimev1.PodBox{
		PodId:     "pod-1",
		Namespace: "yurei-system",
		Name:      "demo-0",
		Volumes: []*runtimev1.Volume{{
			Name:   "sockets",
			Expose: &runtimev1.ExposeVolumeSource{User: "miko", Uid: 501, ReadWrite: true},
		}},
		Containers: []*runtimev1.Container{{
			Name:         "main",
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "sockets", MountPath: "/var/run/yureid"}},
		}},
	}
	for i, p := range extra {
		name := "extra" + string(rune('a'+i))
		box.Volumes = append(box.Volumes, &runtimev1.Volume{Name: name, EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
		box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts, &runtimev1.VolumeMount{Name: name, MountPath: p})
	}
	return box
}

// exposeEnv is a temp data root with its exposures root created (as k3sm
// install would), and a pod rootfs.
func exposeEnv(t *testing.T) (dataRoot, rootfs string) {
	t.Helper()
	base := t.TempDir()
	dataRoot = filepath.Join(base, "data")
	if err := os.MkdirAll(hostshare.ExposeRoot(dataRoot), 0o711); err != nil {
		t.Fatal(err)
	}
	rootfs = filepath.Join(base, "pods", "pod-1", "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	return dataRoot, rootfs
}

// authorized is the exposure AuthorizeExposures would return for exposeBox.
func authorized(t *testing.T, dataRoot string) []hostshare.Exposure {
	t.Helper()
	dir, err := hostshare.ExposeDir(dataRoot, "yurei-system", "demo-0", "sockets")
	if err != nil {
		t.Fatal(err)
	}
	return []hostshare.Exposure{{Volume: "sockets", Dir: dir, UID: 501, User: "miko", ReadWrite: true}}
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

func TestExposeBindCreatesLeafAndLinks(t *testing.T) {
	dataRoot, rootfs := exposeEnv(t)
	acl := &fakeACL{}
	exps := authorized(t, dataRoot)
	got, err := BindExposures(context.Background(), acl, exposeBox(), rootfs, dataRoot, exps)
	if err != nil {
		t.Fatalf("BindExposures: %v", err)
	}
	leaf := exps[0].Dir
	if len(got) != 1 || got[0].Dir != leaf {
		t.Fatalf("bindings = %+v, want one at %s", got, leaf)
	}
	for _, c := range []struct {
		path string
		want os.FileMode
	}{
		{filepath.Dir(filepath.Dir(leaf)), os.ModeDir | 0o711},
		{filepath.Dir(leaf), os.ModeDir | 0o711},
		{leaf, os.ModeDir | 0o700},
	} {
		if m := mode(t, c.path); m != c.want {
			t.Errorf("mode of %s = %v, want %v", c.path, m, c.want)
		}
	}
	link := filepath.Join(rootfs, "var/run/yureid")
	if dst, err := os.Readlink(link); err != nil || dst != leaf {
		t.Errorf("link %s -> %q (%v), want %s", link, dst, err, leaf)
	}
	if !slices.Equal(got[0].Links, []string{link}) {
		t.Errorf("links = %v, want [%s]", got[0].Links, link)
	}
	want := []aclCall{{"grant", leaf, 501, true}}
	if !slices.Equal(acl.calls, want) {
		t.Errorf("acl calls = %+v, want %+v", acl.calls, want)
	}
	plan, err := PlanExposures(exposeBox(), dataRoot)
	if err != nil || !slices.Equal(plan, []string{leaf}) {
		t.Errorf("PlanExposures = %v, %v; want [%s]", plan, err, leaf)
	}
}

func TestExposeBindRefuses(t *testing.T) {
	cases := []struct {
		name    string
		acl     ExposeACL
		box     *runtimev1.PodBox
		setup   func(t *testing.T, dataRoot string)
		wantErr error
	}{
		{name: "nil acl", box: exposeBox(), wantErr: ErrNoExposeACL},
		{name: "nested under another mount", acl: &fakeACL{}, box: exposeBox("/var/run"), wantErr: ErrInvalid},
		{name: "contains another mount", acl: &fakeACL{}, box: exposeBox("/var/run/yureid/x"), wantErr: ErrInvalid},
		{name: "same path as another mount", acl: &fakeACL{}, box: exposeBox("/var/run/YUREID"), wantErr: ErrInvalid},
		{
			name: "missing exposures root", acl: &fakeACL{}, box: exposeBox(), wantErr: ErrInvalid,
			setup: func(t *testing.T, dataRoot string) {
				if err := os.Remove(hostshare.ExposeRoot(dataRoot)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked namespace dir", acl: &fakeACL{}, box: exposeBox(), wantErr: ErrInvalid,
			setup: func(t *testing.T, dataRoot string) {
				elsewhere := t.TempDir()
				if err := os.Symlink(elsewhere, filepath.Join(hostshare.ExposeRoot(dataRoot), "yurei-system")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked pod dir", acl: &fakeACL{}, box: exposeBox(), wantErr: ErrInvalid,
			setup: func(t *testing.T, dataRoot string) {
				ns := filepath.Join(hostshare.ExposeRoot(dataRoot), "yurei-system")
				if err := os.Mkdir(ns, 0o711); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(ns, "demo-0")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "pod dir is a file", acl: &fakeACL{}, box: exposeBox(), wantErr: ErrInvalid,
			setup: func(t *testing.T, dataRoot string) {
				ns := filepath.Join(hostshare.ExposeRoot(dataRoot), "yurei-system")
				if err := os.Mkdir(ns, 0o711); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(ns, "demo-0"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataRoot, rootfs := exposeEnv(t)
			if tc.setup != nil {
				tc.setup(t, dataRoot)
			}
			_, err := BindExposures(context.Background(), tc.acl, tc.box, rootfs, dataRoot, authorized(t, dataRoot))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if f, ok := tc.acl.(*fakeACL); ok && len(f.calls) != 0 {
				t.Errorf("acl called on a refused bind: %+v", f.calls)
			}
		})
	}
}

// TestExposeBindReplacesStaleLeaf plants, in a leaf an earlier pod of the
// same name left, a symlink to a directory outside the tree, a read-only
// subdirectory and a user-immutable file: the bind removes all of it without
// touching the symlink's target.
func TestExposeBindReplacesStaleLeaf(t *testing.T) {
	dataRoot, rootfs := exposeEnv(t)
	leaf := authorized(t, dataRoot)[0].Dir
	if err := os.MkdirAll(filepath.Join(leaf, "locked"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	keep := filepath.Join(target, "keep")
	if err := os.WriteFile(keep, []byte("node data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(leaf, "escape")); err != nil {
		t.Fatal(err)
	}
	frozen := filepath.Join(leaf, "locked", "frozen")
	if err := os.WriteFile(frozen, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(frozen, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(leaf, "locked"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // in case the bind did not remove it
		_ = unix.Chflags(frozen, 0)
		_ = os.Chmod(filepath.Join(leaf, "locked"), 0o700)
	})

	if _, err := BindExposures(context.Background(), &fakeACL{}, exposeBox(), rootfs, dataRoot, authorized(t, dataRoot)); err != nil {
		t.Fatalf("BindExposures: %v", err)
	}
	ents, err := os.ReadDir(leaf)
	if err != nil || len(ents) != 0 {
		t.Errorf("leaf entries = %v (%v), want an empty leaf", ents, err)
	}
	if b, err := os.ReadFile(keep); err != nil || string(b) != "node data" {
		t.Errorf("symlink target changed: %q, %v", b, err)
	}
}

func TestExposeRemoveStaysUnderRoot(t *testing.T) {
	dataRoot, rootfs := exposeEnv(t)
	if _, err := BindExposures(context.Background(), &fakeACL{}, exposeBox(), rootfs, dataRoot, authorized(t, dataRoot)); err != nil {
		t.Fatal(err)
	}
	leaf := authorized(t, dataRoot)[0].Dir
	target := t.TempDir()
	keep := filepath.Join(target, "keep")
	if err := os.WriteFile(keep, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(leaf, "escape")); err != nil {
		t.Fatal(err)
	}
	// A symlinked namespace is never entered: the pod dir behind it survives.
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "demo-0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(hostshare.ExposeRoot(dataRoot), "linked")); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name, ns, pod string
		wantErr       bool
	}{
		{"traversal pod name", "yurei-system", "..", true},
		{"traversal namespace", "..", "demo-0", true},
		{"symlinked namespace", "linked", "demo-0", true},
		{"missing pod", "yurei-system", "gone", false},
		{"the pod", "yurei-system", "demo-0", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := RemoveExposures(dataRoot, c.ns, c.pod); (err != nil) != c.wantErr {
				t.Fatalf("RemoveExposures(%q, %q) = %v, wantErr %v", c.ns, c.pod, err, c.wantErr)
			}
		})
	}
	if _, err := os.Lstat(filepath.Dir(leaf)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pod exposure dir still present: %v", err)
	}
	for _, p := range []string{keep, filepath.Join(other, "demo-0"), hostshare.ExposeRoot(dataRoot)} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
}

func TestExposeSweepRemovesUnknownPods(t *testing.T) {
	dataRoot, _ := exposeEnv(t)
	root := hostshare.ExposeRoot(dataRoot)
	for _, p := range []string{"ns-a/live/v", "ns-a/gone/v", "ns-b/gone/v"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "victim"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ns-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ns-a", "podlink")); err != nil {
		t.Fatal(err)
	}
	removed, err := SweepExposures(dataRoot, func(ns, pod string) bool { return ns == "ns-a" && pod == "live" })
	if err != nil {
		t.Fatalf("SweepExposures: %v", err)
	}
	slices.Sort(removed)
	if want := []string{"ns-a/gone", "ns-b/gone"}; !slices.Equal(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}
	for _, p := range []string{filepath.Join(root, "ns-a/live/v"), filepath.Join(outside, "victim"), filepath.Join(root, "ns-a", "podlink")} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if removed, err := SweepExposures(filepath.Join(t.TempDir(), "none"), func(string, string) bool { return false }); err != nil || removed != nil {
		t.Errorf("sweep of a missing root = %v, %v", removed, err)
	}
}
