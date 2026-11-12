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
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"k3sm.io/runtimed/pkg/artifact"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestExecRefusesAnImageVolumeProgram pins exec to start's rule
// (TestStartRefusesAnImageVolumeProgram): an exec argv[0] that is an image-volume
// mount path, a case variant of one or lies beneath one is refused by name with
// ErrImageArgvEscapes, before the volume-mount early return and before any gate,
// because an image volume holds data, not programs. An in-image link into the
// mount is not matched by name; the rootfs walk follows it out of the root and
// refuses it with the same sentinel. A sibling that only shares a string prefix
// with the mount path is a real in-image program and resolves, and a program
// under an ordinary (non-image) volume mount keeps the early return, left as
// sent but cleaned. The by-name check covers only an absolute argv[0] on the
// image route: a relative name and every command on the host-binary route are
// left as sent, as before, and those rows pin that. No refusal names the host
// rootfs or the image-volume view, which are the daemon's to know.
func TestExecRefusesAnImageVolumeProgram(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("the daemon's views clone with APFS clonefile, darwin-only")
	}
	const dataMount = "/data"
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
		// in-image link into the view, not from the by-name mount check.
		byWalk bool
		// hostRoute resolves through a copy of the container on the host-binary
		// route (Image: NativeImage), where nothing is checked by name.
		hostRoute bool
		// want is the resolved argv[0] of an accepted row, given the rootfs.
		want func(rootfs string) string
	}{
		{name: "exact mount path", argv0: "/opt/run", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "beneath a directory mount", argv0: "/models/run.json", mountPath: "/models", refused: true},
		{name: "case variant", argv0: "/Models/run.json", mountPath: "/models", refused: true},
		{name: "trailing slash argv0", argv0: "/opt/run/", mountPath: "/opt/run", subPath: "run.json", refused: true},
		{name: "trailing slash directory mount", argv0: "/models/run.json", mountPath: "/models/", refused: true},
		{name: "dot-dot through a sibling", argv0: "/opt/../models/run.json", mountPath: "/models", refused: true},
		{name: "doubled leading slash", argv0: "//models/run.json", mountPath: "/models", refused: true},
		{name: "in-image link into the mount", argv0: "/bin/tool", mountPath: "/models",
			linkAt: "bin/tool", linkTo: "/models/run.json", refused: true, byWalk: true},
		{name: "sibling sharing a prefix", argv0: "/models2/x", mountPath: "/models", program: "models2/x",
			want: func(rootfs string) string { return filepath.Join(rootfs, "models2/x") }},
		{name: "ordinary volume mount keeps the early return", argv0: "/data//tool", mountPath: "/models", program: "data/tool",
			want: func(string) string { return "/data/tool" }},
		// Today's behaviour, pinned: the host-binary route returns before the
		// by-name check, so the mount refusal deliberately does not fire there.
		{name: "host-binary route is left as sent", argv0: "/models/run.json", mountPath: "/models", hostRoute: true,
			want: func(string) string { return "/models/run.json" }},
		// Today's behaviour, pinned: a relative argv[0] means the session's
		// working directory and is not checked by name; the pod's profile is the
		// boundary there, not this check.
		{name: "relative name is left as sent", argv0: "models/run.json", mountPath: "/models",
			want: func(string) string { return "models/run.json" }},
		{name: "dot-relative name is left as sent", argv0: "./models/run.json", mountPath: "/models",
			want: func(string) string { return "./models/run.json" }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			podID := fmt.Sprintf("pod-execvolprog-%d", i)
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
				VolumeMounts: []*runtimev1.VolumeMount{
					{Name: "model", MountPath: tc.mountPath, SubPath: tc.subPath},
					{Name: "data", MountPath: dataMount},
				},
			}
			box := pullBox(rt, podID, c)
			box.Volumes = []*runtimev1.Volume{
				{Name: "model", Image: &runtimev1.ImageVolumeSource{Reference: artifactTestHost + "/models/tiny:v1"}},
				mediumVolume("data", ""),
			}
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
			ec := c
			if tc.hostRoute {
				ec = proto.Clone(c).(*runtimev1.Container)
				ec.Image = NativeImage
			}
			got, err := rt.resolveExecCommand(context.Background(), p, ec, []string{tc.argv0, "arg"})
			if !tc.refused {
				if err != nil {
					t.Fatalf("resolveExecCommand(%q): %v", tc.argv0, err)
				}
				if want := tc.want(rootfs); len(got) != 2 || got[0] != want || got[1] != "arg" {
					t.Errorf("resolveExecCommand(%q) = %q, want [%q arg]", tc.argv0, got, want)
				}
				return
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("resolveExecCommand(%q) = %q, %v; want InvalidArgument", tc.argv0, got, err)
			}
			msg := err.Error()
			if !strings.Contains(msg, ErrImageArgvEscapes.Error()) {
				t.Errorf("resolveExecCommand err = %q, want it to name %q", msg, ErrImageArgvEscapes)
			}
			for _, host := range hostForms(rootfs, view) {
				if strings.Contains(msg, host) {
					t.Errorf("resolveExecCommand err = %q names the host path %q, which is the daemon's to know", msg, host)
				}
			}
			if !tc.byWalk && (!strings.Contains(msg, tc.mountPath) || !strings.Contains(msg, "holds data, not programs")) {
				t.Errorf("resolveExecCommand err = %q, want it to name %q and say an image volume holds data, not programs", msg, tc.mountPath)
			}
			if checks, signs, spawns := counts(sg, sp); checks != checks0 || signs != signs0 || spawns != spawns0 {
				t.Errorf("the refused exec reached the gate or the spawner: checks %d->%d, signs %d->%d, spawns %d->%d",
					checks0, checks, signs0, signs, spawns0, spawns)
			}
		})
	}
}

// hostForms returns each of paths and, where it differs, its form with links
// resolved (/var is /private/var on darwin), so a message naming either is
// caught.
func hostForms(paths ...string) []string {
	var out []string
	for _, p := range paths {
		out = append(out, p)
		if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
			out = append(out, r)
		}
	}
	return out
}
