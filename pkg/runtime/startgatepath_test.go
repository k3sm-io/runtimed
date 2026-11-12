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
	goruntime "runtime"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/sandbox"

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

	// The ad-hoc sign is the one gate step that writes a file, so it must be
	// handed the resolved path too. The fake's first Check fails, which makes
	// the ADHOC_OK gate (the rig's policy) sign and re-check.
	t.Run("adhoc_sign_receives_the_checked_and_spawned_path", func(t *testing.T) {
		r := newRig(t)
		link(t, r.rootfs, "/bin/app.real")
		checks0, signs0, _ := counts(r.signer, r.spawn)
		r.signer.mu.Lock()
		r.signer.failNextCheck = errors.New("code object is not signed at all")
		r.signer.mu.Unlock()
		if _, _, err := r.rt.startContainer(r.p.supCtx, r.p, r.rootfs, r.c, false, 0); err != nil {
			t.Fatalf("startContainer: %v", err)
		}
		r.signer.mu.Lock()
		checked := append([]string(nil), r.signer.checked[checks0:]...)
		signed := append([]string(nil), r.signer.signed[signs0:]...)
		r.signer.mu.Unlock()
		if len(signed) != 1 {
			t.Fatalf("Sign calls = %v, want exactly one (the first Check failed)", signed)
		}
		if len(checked) != 2 {
			t.Fatalf("Check calls = %v, want a failed check and a re-check", checked)
		}
		argv0 := spawnedPodArgv0(t, r.spawn)
		want := filepath.Join(r.rootfs, "bin", "app.real")
		if argv0 != want {
			t.Errorf("argv[0] = %q, want the in-image file %q", argv0, want)
		}
		if signed[0] != argv0 {
			t.Errorf("Sign(%q) but the shim was handed argv[0] %q", signed[0], argv0)
		}
		for _, got := range checked {
			if got != signed[0] {
				t.Errorf("Check(%q) but Sign(%q)", got, signed[0])
			}
		}
	})

	// A relative link whose target stays in the root keeps its lexical name, as
	// exec does: the program may read its own argv[0] (a multi-call binary).
	t.Run("relative_in_root_link_keeps_the_lexical_name", func(t *testing.T) {
		r := newRig(t) // bin/app -> app.real
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
		want := filepath.Join(r.rootfs, "bin", "app")
		if argv0 := spawnedPodArgv0(t, r.spawn); argv0 != want {
			t.Errorf("argv[0] = %q, want the lexical name %q, not the link target", argv0, want)
		}
		for _, got := range checked {
			if got != want {
				t.Errorf("Check(%q), want the lexical name %q, not the link target", got, want)
			}
		}
	})

	// With no entry in the image at argv[0], the walker returns the lexical
	// path and false. Start then fails as it did before the walk: the gate is
	// asked about a file that is not there (statOnCheck stands in for
	// codesign's ENOENT), not with an escape error, and nothing is spawned.
	t.Run("missing_argv0_fails_as_a_missing_file", func(t *testing.T) {
		r := newRig(t)
		if err := os.Remove(filepath.Join(r.rootfs, "bin", "app")); err != nil {
			t.Fatal(err)
		}
		r.signer.mu.Lock()
		r.signer.statOnCheck = true
		r.signer.mu.Unlock()
		checks0, _, spawns0 := counts(r.signer, r.spawn)
		_, _, err := r.rt.startContainer(r.p.supCtx, r.p, r.rootfs, r.c, false, 0)
		if err == nil {
			t.Fatal("startContainer of a missing argv[0] succeeded")
		}
		if errors.Is(err, ErrImageArgvEscapes) {
			t.Fatalf("startContainer err = %v, want a missing-file failure, not an escape", err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("startContainer err = %v, want one wrapping os.ErrNotExist", err)
		}
		r.signer.mu.Lock()
		checked := append([]string(nil), r.signer.checked[checks0:]...)
		r.signer.mu.Unlock()
		want := filepath.Join(r.rootfs, "bin", "app")
		if len(checked) == 0 || checked[0] != want {
			t.Errorf("Check calls = %v, want the lexical path %q first", checked, want)
		}
		if _, _, spawns := counts(r.signer, r.spawn); spawns != spawns0 {
			t.Errorf("spawns %d->%d, want none for a missing argv[0]", spawns0, spawns)
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

// TestStartRefusesAnImageVolumeProgram pins a container whose argv[0] is an
// image-volume mount path, in any spelling that cleans to it or any case
// variant of it, or lies beneath a directory image-volume mount: an image
// volume holds data, not programs (its view files are 0444, the profile denies
// exec on view paths), so start refuses it by name with ErrImageArgvEscapes
// before anything is signed, checked or spawned, even while the mount is the
// link the daemon placed. An in-image link whose target is or lies beneath a
// mount path is not matched by name; the rootfs walk follows it into the view
// and refuses it with the same sentinel. A sibling path that only shares a string prefix with
// a mount path is a real in-image program and still starts.
func TestStartRefusesAnImageVolumeProgram(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("the daemon's views clone with APFS clonefile, darwin-only")
	}
	cases := []struct {
		name      string
		argv0     string
		mountPath string
		subPath   string
		program   string // an in-image file written before create, "" for none
		linkAt    string // an in-image symlink planted before create, "" for none
		linkTo    string // linkAt's target, as written into the link
		refused   bool
		// byWalk marks a refusal that comes from the rootfs walk following an
		// in-image link into the view, not from the by-name mount check, so its
		// message need not name the mount.
		byWalk bool
	}{
		{name: "exact", argv0: "/opt/run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "relative", argv0: "./opt/run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "double slash", argv0: "/opt//run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "dot-dot", argv0: "/opt/x/../run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "case variant", argv0: "/Opt/Run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "beneath a directory mount", argv0: "/models/run.json", mountPath: "/models", refused: true},
		{name: "trailing slash argv0", argv0: "/opt/run/", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "trailing slash directory mount", argv0: "/models/run.json", mountPath: "/models/", refused: true},
		{name: "in-image link to the mount path", argv0: "/bin/tool", mountPath: "/opt/run", subPath: "run.json",
			linkAt: "bin/tool", linkTo: "/opt/run", refused: true, byWalk: true},
		{name: "relative in-image link to the mount path", argv0: "/bin/tool", mountPath: "/opt/run", subPath: "run.json",
			linkAt: "bin/tool", linkTo: "../opt/run", refused: true, byWalk: true},
		{name: "in-image link beneath a directory mount", argv0: "/bin/tool", mountPath: "/models",
			linkAt: "bin/tool", linkTo: "/models/run.json", refused: true, byWalk: true},
		{name: "sibling sharing a prefix", argv0: "/opt/runner", mountPath: "/opt/run", subPath: "run.json", program: "opt/runner"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			podID := fmt.Sprintf("pod-volprog-%d", i)
			f := modelArtifact(map[string][]byte{"run.json": []byte("prog"), "w.safetensors": []byte("w")}, []string{"run.json", "w.safetensors"})
			sg, sp, w := &fakeSigner{}, &fakeSpawner{}, newBlockingWaiter()
			lazy := &lazyArtifactPuller{}
			_, rt := imagesTestClientDeps(t, Deps{Puller: &fakePuller{}, ArtifactPuller: lazy, Signer: sg, Spawner: sp, Waiter: w})
			ap, err := artifact.New(artifact.Config{
				RegistryHost: artifactTestHost,
				PartialDir:   filepath.Join(rt.cache.Root(), sandbox.ArtifactPartialSubdir),
				StorePath:    rt.cache.Root(),
				FreeBytes:    func(string) (uint64, error) { return 1 << 40, nil },
			}, artifact.Deps{Blobs: rt.cache, Leases: rt.cache, Reclaimer: rt.cache, Index: rt.index, Fetcher: f})
			if err != nil {
				t.Fatal(err)
			}
			lazy.p = ap
			t.Cleanup(func() { restoreWritable(t, filepath.Join(rt.cache.Root(), sandbox.ArtifactViewsSubdir)) })
			rec := &recordingSignalGroup{onKill: func(pid int) { w.release(pid) }}
			rt.signalGroup = rec.signal
			rootfs := derivedRootfs(t, rt, podID)
			if tc.program != "" {
				at := filepath.Join(rootfs, filepath.FromSlash(tc.program))
				if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(at, []byte("x"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.linkAt != "" {
				at := filepath.Join(rootfs, filepath.FromSlash(tc.linkAt))
				if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tc.linkTo, at); err != nil {
					t.Fatal(err)
				}
			}
			c := &runtimev1.Container{
				Name: "main", Image: pullRef, Command: []string{tc.argv0},
				VolumeMounts: []*runtimev1.VolumeMount{{Name: "model", MountPath: tc.mountPath, SubPath: tc.subPath}},
			}
			box := pullBox(rt, podID, c)
			box.Volumes = []*runtimev1.Volume{{
				Name:  "model",
				Image: &runtimev1.ImageVolumeSource{Reference: artifactTestHost + "/models/tiny:v1"},
			}}
			mustCreatePod(t, rt, box)
			view, err := rt.ArtifactView(context.Background(), sha(f.manifest), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := os.Readlink(filepath.Join(rootfs, filepath.FromSlash(tc.mountPath))); err != nil || got != filepath.Join(view, tc.subPath) {
				t.Fatalf("mount link = %q, %v; want the daemon-placed view", got, err)
			}
			rt.mu.Lock()
			p := rt.pods[podID]
			rt.mu.Unlock()
			checks0, signs0, spawns0 := counts(sg, sp)
			_, _, err = rt.startContainer(p.supCtx, p, rootfs, c, false, 0)
			if !tc.refused {
				if err != nil {
					t.Fatalf("startContainer of the in-image program %q: %v", tc.argv0, err)
				}
				if _, _, spawns := counts(sg, sp); spawns != spawns0+1 {
					t.Errorf("spawns %d->%d, want one more", spawns0, spawns)
				}
				return
			}
			if !errors.Is(err, ErrImageArgvEscapes) {
				t.Fatalf("startContainer err = %v, want ErrImageArgvEscapes", err)
			}
			if msg := err.Error(); !tc.byWalk && (!strings.Contains(msg, tc.mountPath) || !strings.Contains(msg, "holds data, not programs")) {
				t.Errorf("startContainer err = %q, want it to name %q and say an image volume holds data, not programs", msg, tc.mountPath)
			}
			if checks, signs, spawns := counts(sg, sp); checks != checks0 || signs != signs0 || spawns != spawns0 {
				t.Errorf("the refused start reached the gate or the spawner: checks %d->%d, signs %d->%d, spawns %d->%d",
					checks0, checks, signs0, signs, spawns0, spawns)
			}
		})
	}
}
