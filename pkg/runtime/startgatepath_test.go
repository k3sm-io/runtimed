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
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// spawnedPodArgv0 is the pod program's argv[0] in the last spawn: what follows
// the profile in fakeBackend's shim argv shape, i.e. what the exec shim would
// exec.
func spawnedPodArgv0(t *testing.T, sp *fakeSpawner) string {
	t.Helper()
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.specs) == 0 {
		t.Fatal("nothing was spawned")
	}
	argv := sp.specs[len(sp.specs)-1].Argv
	for i, a := range argv {
		if a == "/tmp/profile.sb" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	t.Fatalf("no pod argv after the profile in %v", argv)
	return ""
}

// counts is how many Check calls the signer and spawns the spawner have seen.
func counts(sg *fakeSigner, sp *fakeSpawner) (checks, signs, spawns int) {
	sg.mu.Lock()
	checks, signs = len(sg.checked), len(sg.signed)
	sg.mu.Unlock()
	sp.mu.Lock()
	spawns = len(sp.specs)
	sp.mu.Unlock()
	return checks, signs, spawns
}

// TestStartSpawnsTheBinaryTheGateChecked pins that a pulled container's start
// resolves argv[0] once beneath the rootfs and hands that one path to the
// signature check and to the exec shim's argv, and that a link out of the root
// is refused before either runs.
//
// It pins PATH IDENTITY ONLY. It does not test, and nothing here claims to
// close, the swap window: codesign and the shim are separate processes taking a
// path, so an in-place swap of the resolved file between the check and the
// shim's exec remains possible.
//
// Links, not plain files, are the fixture on purpose: with a plain file the
// lexical path and the resolved path are the same string, which passed before
// the start path walked links at all.
func TestStartSpawnsTheBinaryTheGateChecked(t *testing.T) {
	const podID = "pod-gatepath"
	type rig struct {
		rt     *Runtime
		signer *fakeSigner
		spawn  *fakeSpawner
		rootfs string
		c      *runtimev1.Container
		p      *pod
	}
	link := func(t *testing.T, rootfs, target string) {
		t.Helper()
		at := filepath.Join(rootfs, "bin", "app")
		if err := os.Remove(at); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	// newRig creates the pod with argv[0] an in-root relative link, so its
	// first start succeeds and the live pod (profile and all) is what each case
	// then starts or restarts against.
	newRig := func(t *testing.T) rig {
		t.Helper()
		sg, sp, w := &fakeSigner{}, &fakeSpawner{}, newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Signer: sg, Spawner: sp, Waiter: w})
		rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
		rt.signalGroup = rec.signal
		rootfs := derivedRootfs(t, rt, podID)
		if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootfs, "bin", "app.real"), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		link(t, rootfs, "app.real")
		c := &runtimev1.Container{Name: "main", Image: pullRef, Command: []string{"/bin/app"}}
		mustCreatePod(t, rt, pullBox(rt, podID, c))
		if _, _, spawns := counts(sg, sp); spawns != 1 {
			t.Fatalf("spawns after create = %d, want 1", spawns)
		}
		rt.mu.Lock()
		p := rt.pods[podID]
		rt.mu.Unlock()
		return rig{rt: rt, signer: sg, spawn: sp, rootfs: rootfs, c: c, p: p}
	}
	// outside is a real file beyond the rootfs, named relative to bin/, so a
	// link to it resolves on the host and only the walk's refusal keeps it from
	// being checked and run.
	outside := func(t *testing.T, rootfs string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "host-app")
		if err := os.WriteFile(f, []byte("host"), 0o755); err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(filepath.Join(rootfs, "bin"), f)
		if err != nil {
			t.Fatal(err)
		}
		return rel
	}

	t.Run("in_root_link_check_and_argv_name_one_file", func(t *testing.T) {
		r := newRig(t)
		// Root-absolute: codesign and the kernel would read it against the HOST
		// root; in the image it means rootfs/bin/app.real.
		link(t, r.rootfs, "/bin/app.real")
		checks0, _, _ := counts(r.signer, r.spawn)
		if _, _, err := r.rt.startContainer(r.p.supCtx, r.p, r.rootfs, r.c, false, 0); err != nil {
			t.Fatalf("startContainer: %v", err)
		}
		r.signer.mu.Lock()
		checked := append([]string(nil), r.signer.checked[checks0:]...)
		r.signer.mu.Unlock()
		if len(checked) == 0 {
			t.Fatal("the signature gate was never asked")
		}
		argv0 := spawnedPodArgv0(t, r.spawn)
		for _, got := range checked {
			if got != argv0 {
				t.Errorf("Check(%q) but the shim was handed argv[0] %q", got, argv0)
			}
		}
		if want := filepath.Join(r.rootfs, "bin", "app.real"); argv0 != want {
			t.Errorf("argv[0] = %q, want the in-image file %q", argv0, want)
		}
	})

	t.Run("out_of_root_link_is_refused_before_check_and_spawn", func(t *testing.T) {
		r := newRig(t)
		link(t, r.rootfs, outside(t, r.rootfs))
		checks0, signs0, spawns0 := counts(r.signer, r.spawn)
		_, _, err := r.rt.startContainer(r.p.supCtx, r.p, r.rootfs, r.c, false, 0)
		if !errors.Is(err, ErrImageArgvEscapes) {
			t.Fatalf("startContainer err = %v, want ErrImageArgvEscapes", err)
		}
		if checks, signs, spawns := counts(r.signer, r.spawn); checks != checks0 || signs != signs0 || spawns != spawns0 {
			t.Errorf("the refused start reached the gate or the spawner: checks %d->%d, signs %d->%d, spawns %d->%d",
				checks0, checks, signs0, signs, spawns0, spawns)
		}
	})

	t.Run("restart_after_a_swap_to_an_out_of_root_link_is_refused", func(t *testing.T) {
		r := newRig(t)
		link(t, r.rootfs, outside(t, r.rootfs))
		checks0, signs0, spawns0 := counts(r.signer, r.spawn)
		resp, err := r.rt.RestartContainer(context.Background(), &runtimev1.RestartContainerRequest{
			PodId: podID, Container: "main", Reason: "test",
		})
		if err != nil {
			t.Fatalf("RestartContainer: %v", err)
		}
		// The RPC carries a status, not the Go error, so the sentinel is matched
		// by its text and the typed reason.
		if resp.GetError() == nil || !strings.Contains(resp.GetError().GetMessage(), ErrImageArgvEscapes.Error()) {
			t.Fatalf("restart error = %v, want one naming %q", resp.GetError(), ErrImageArgvEscapes)
		}
		if got := resp.GetFailureReason(); got != runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG {
			t.Errorf("restart reason = %v, want CONTAINER_CONFIG", got)
		}
		if checks, signs, spawns := counts(r.signer, r.spawn); checks != checks0 || signs != signs0 || spawns != spawns0 {
			t.Errorf("the refused restart reached the gate or the spawner: checks %d->%d, signs %d->%d, spawns %d->%d",
				checks0, checks, signs0, signs, spawns0, spawns)
		}
	})
}
