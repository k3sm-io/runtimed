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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// exposeCall is one call a recordingACL saw.
type exposeCall struct {
	op        string
	dir       string
	uid       uint32
	readWrite bool
}

// recordingACL is a volume.ExposeACL that records every call.
type recordingACL struct {
	mu    sync.Mutex
	calls []exposeCall
}

func (a *recordingACL) Grant(dir string, uid uint32, readWrite bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, exposeCall{"grant", dir, uid, readWrite})
	return nil
}

func (a *recordingACL) Revoke(dir string, uid uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, exposeCall{"revoke", dir, uid, false})
	return nil
}

func (a *recordingACL) got() []exposeCall {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.calls)
}

// exposeGrant admits read-write exposures from namespace default to miko.
var exposeGrant = hostshare.ExposeGrant{UID: 501, User: "miko", Namespaces: []string{"default"}, ReadWrite: true}

// exposeRuntime is a test runtime with acl wired, the exposures root made (as
// k3sm install makes it), uid 501 named miko, and grants as the node's.
func exposeRuntime(t *testing.T, acl *recordingACL, w *blockingWaiter, grants ...hostshare.ExposeGrant) *Runtime {
	t.Helper()
	var d Deps
	if acl != nil {
		d.ExposeACL = acl
	}
	if w != nil {
		d.Waiter = w
	}
	rt := newTestRuntime(t, d)
	if err := os.Mkdir(hostshare.ExposeRoot(rt.cfg.Root), 0o711); err != nil {
		t.Fatal(err)
	}
	rt.exposeGrants = func() ([]hostshare.ExposeGrant, error) { return grants, nil }
	rt.accountName = func(uid uint32) (string, error) {
		if uid == 501 {
			return "miko", nil
		}
		return "", fmt.Errorf("no uid %d", uid)
	}
	return rt
}

// exposeBoxFor is hostBinBox with a read-write exposure to miko at
// /var/run/yureid.
func exposeBoxFor(rt *Runtime, podID string) *runtimev1.PodBox {
	box := hostBinBox(rt, podID)
	box.Volumes = append(box.Volumes, &runtimev1.Volume{
		Name:   "sockets",
		Expose: &runtimev1.ExposeVolumeSource{User: "miko", Uid: 501, ReadWrite: true},
	})
	box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts, &runtimev1.VolumeMount{Name: "sockets", MountPath: "/var/run/yureid"})
	return box
}

func exposeLeaf(t *testing.T, rt *Runtime) string {
	t.Helper()
	dir, err := hostshare.ExposeDir(rt.cfg.Root, "default", "p", "sockets")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExposeCreateRefuses(t *testing.T) {
	cases := []struct {
		name   string
		acl    bool
		grants []hostshare.ExposeGrant
		edit   func(*runtimev1.PodBox)
		want   string
	}{
		{name: "no grant", acl: true, want: "no exposure grant"},
		{name: "grant for another namespace", acl: true, grants: []hostshare.ExposeGrant{{UID: 501, User: "miko", Namespaces: []string{"other"}, ReadWrite: true}}, want: "no exposure grant"},
		{name: "read-only grant", acl: true, grants: []hostshare.ExposeGrant{{UID: 501, User: "miko", Namespaces: []string{"default"}}}, want: "allows read only"},
		{name: "no ExposeACL", grants: []hostshare.ExposeGrant{exposeGrant}, want: "no exposure ACL"},
		{name: "renamed account", acl: true, grants: []hostshare.ExposeGrant{exposeGrant}, edit: func(b *runtimev1.PodBox) { b.Volumes[0].Expose.User = "someone" }, want: "is not the account"},
		{name: "nested mount", acl: true, grants: []hostshare.ExposeGrant{exposeGrant}, edit: func(b *runtimev1.PodBox) {
			b.Volumes = append(b.Volumes, &runtimev1.Volume{Name: "run", EmptyDir: &runtimev1.EmptyDirVolumeSource{}})
			b.Containers[0].VolumeMounts = append(b.Containers[0].VolumeMounts, &runtimev1.VolumeMount{Name: "run", MountPath: "/var/run"})
		}, want: "overlaps"},
		{name: "no pod name", acl: true, grants: []hostshare.ExposeGrant{exposeGrant}, edit: func(b *runtimev1.PodBox) { b.Name = "" }, want: "not a pod name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var acl *recordingACL
			if tc.acl {
				acl = &recordingACL{}
			}
			rt := exposeRuntime(t, acl, nil, tc.grants...)
			box := exposeBoxFor(rt, "pod-x")
			if tc.edit != nil {
				tc.edit(box)
			}
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() == nil || resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Fatalf("CreatePod = %v (reason %v), want an INVALID_POD_BOX refusal", resp.GetError(), resp.GetFailureReason())
			}
			if msg := resp.GetError().GetMessage(); !strings.Contains(msg, tc.want) {
				t.Errorf("refusal %q does not say %q", msg, tc.want)
			}
			if n := len(rt.spawner.(*fakeSpawner).specs); n != 0 {
				t.Errorf("%d containers were spawned for a refused pod", n)
			}
			if acl != nil && len(acl.got()) != 0 {
				t.Errorf("acl was called for a refused pod: %+v", acl.got())
			}
			if ents, _ := os.ReadDir(hostshare.ExposeRoot(rt.cfg.Root)); len(ents) != 0 {
				t.Errorf("a refused pod left %v under the exposures root", ents)
			}
		})
	}
	t.Run("the refusal wraps ErrNotExposed", func(t *testing.T) {
		rt := exposeRuntime(t, &recordingACL{}, nil)
		_, err := rt.authorizeExposures(exposeBoxFor(rt, "pod-x"))
		if !errors.Is(err, hostshare.ErrNotExposed) || !errors.Is(err, errInvalidPodBox) {
			t.Errorf("err = %v, want errInvalidPodBox and hostshare.ErrNotExposed", err)
		}
	})
}

func TestExposeCreateGrantedThenDelete(t *testing.T) {
	w := newBlockingWaiter()
	acl := &recordingACL{}
	rt := exposeRuntime(t, acl, w, exposeGrant)
	rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
	rt.signalGroup = rec.signal
	box := exposeBoxFor(rt, "pod-x")
	mustCreatePod(t, rt, box)

	leaf := exposeLeaf(t, rt)
	if fi, err := os.Lstat(leaf); err != nil || fi.Mode() != os.ModeDir|0o700 {
		t.Fatalf("leaf %s: %v, %v; want a 0700 directory", leaf, fi, err)
	}
	if want := []exposeCall{{"grant", leaf, 501, true}}; !slices.Equal(acl.got(), want) {
		t.Errorf("acl calls = %+v, want %+v", acl.got(), want)
	}
	link := filepath.Join(rt.cache.PodsRoot(), "pod-x", "rootfs", "var/run/yureid")
	if dst, err := os.Readlink(link); err != nil || dst != leaf {
		t.Errorf("link %s -> %q (%v), want %s", link, dst, err, leaf)
	}
	rt.mu.Lock()
	profile := rt.pods["pod-x"].profile
	rt.mu.Unlock()
	if !strings.Contains(profile, "(allow file-read* file-write*\n  (subpath \""+leaf+"\")") {
		t.Errorf("leaf %s is not in the profile's read/write scope:\n%s", leaf, profile)
	}
	// The re-attach derivation is the create's: the same profile, byte for byte.
	if again, err := rt.boxProfile(box); err != nil || again != profile {
		t.Errorf("boxProfile differs from the create's profile (err %v)", err)
	}

	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-x"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if _, err := os.Lstat(filepath.Dir(leaf)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pod's exposure dir survived the delete: %v", err)
	}
	if _, err := os.Lstat(hostshare.ExposeRoot(rt.cfg.Root)); err != nil {
		t.Errorf("the exposures root was removed: %v", err)
	}
}

func TestExposeAttachRecheck(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grants     []hostshare.ExposeGrant
		wantRevoke bool
	}{
		{name: "grant still present", grants: []hostshare.ExposeGrant{exposeGrant}},
		{name: "grant revoked while down", wantRevoke: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl := &recordingACL{}
			groups := fakeGroups{members: map[int][]supervisor.ProcMember{100: {mem(100, 5000)}}}
			rt := newTestRuntime(t, Deps{
				ExposeACL:     acl,
				ProcGroup:     groups.inspect,
				ProcStartTime: func(int) (int64, bool) { return 5000, true },
			})
			rt.exposeGrants = func() ([]hostshare.ExposeGrant, error) { return tc.grants, nil }
			rt.accountName = func(uint32) (string, error) { return "miko", nil }
			box := exposeBoxFor(rt, "p1")
			profile, err := rt.boxProfile(box)
			if err != nil {
				t.Fatal(err)
			}
			leaf := exposeLeaf(t, rt)
			if !strings.Contains(profile, leaf) {
				t.Fatalf("the attach profile does not name the leaf %s", leaf)
			}
			seedPodProcRecord(t, rt, podProcRecord{PodID: "p1", Container: "main", Pgid: 100, StartUnixNano: 5000, ProfileSHA256: profileDigest(profile)})

			if _, err := rt.AttachPod(context.Background(), box); err != nil {
				t.Fatalf("AttachPod: %v", err)
			}
			var want []exposeCall
			if tc.wantRevoke {
				want = []exposeCall{{"revoke", leaf, 501, false}}
			}
			if got := acl.got(); !slices.Equal(got, want) {
				t.Errorf("acl calls = %+v, want %+v", got, want)
			}
			rt.mu.Lock()
			_, attached := rt.pods["p1"]
			rt.mu.Unlock()
			if !attached {
				t.Error("the pod was not attached; a revoked exposure must not cost the pod")
			}
		})
	}
}

func TestExposeVMPodRefused(t *testing.T) {
	rt := exposeRuntime(t, &recordingACL{}, nil, exposeGrant)
	box := exposeBoxFor(rt, "pod-vm")
	_, reason, err := rt.createVMPod(context.Background(), box, box.GetSandboxProfile())
	if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX || !errors.Is(err, hostshare.ErrNotExposed) {
		t.Fatalf("createVMPod = %v (reason %v), want an INVALID_POD_BOX ErrNotExposed refusal", err, reason)
	}
	if !strings.Contains(err.Error(), "native pods only") {
		t.Errorf("refusal %q does not name the native-only rule", err)
	}
}

func TestExposeStartupSweep(t *testing.T) {
	w := newBlockingWaiter()
	rt := exposeRuntime(t, &recordingACL{}, w, exposeGrant)
	mustCreatePod(t, rt, exposeBoxFor(rt, "pod-x"))
	root := hostshare.ExposeRoot(rt.cfg.Root)
	gone := filepath.Join(root, "default", "deleted-while-down", "v")
	if err := os.MkdirAll(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rt.ReapOrphanedPods(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(gone)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an unknown pod's exposures survived the startup sweep: %v", err)
	}
	if _, err := os.Lstat(exposeLeaf(t, rt)); err != nil {
		t.Errorf("a live pod's exposure was swept: %v", err)
	}
}

// TestExposeSubdirMirror pins sandbox's mirror of the exposures-root name to
// hostshare's, so the profile denies the tree the binder writes.
func TestExposeSubdirMirror(t *testing.T) {
	if sandbox.ExposeSubdir != hostshare.ExposeSubdir {
		t.Errorf("sandbox.ExposeSubdir = %q, hostshare.ExposeSubdir = %q", sandbox.ExposeSubdir, hostshare.ExposeSubdir)
	}
}
