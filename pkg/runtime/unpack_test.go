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
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// TestResolveBinaryMaterializesTheImage pins the M11.2-d7 wiring at the seam:
// a container whose image is pulled has that image materialized into this pod's
// rootfs, under the native layer dialect, exactly once.
//
// Before this deliverable resolveBinary stopped at "the blobs are cached" and
// argv[0] named a file that was never written, so this is the assertion that
// distinguishes the substrate being wired from it merely existing.
func TestResolveBinaryMaterializesTheImage(t *testing.T) {
	unpack := &fakeUnpacker{}
	pull := &fakePuller{manifest: &runtimev1.ImageManifest{
		Reference: "example.com/app:v1",
		Config:    &runtimev1.Descriptor{Digest: "sha256:" + hexRun('c')},
	}}
	rt := newTestRuntime(t, Deps{Puller: pull, Unpacker: unpack})
	p := &pod{
		box:     hostBinBox(rt, "pod-materialize"),
		backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC,
	}
	rootfs := derivedRootfs(t, rt, "pod-materialize")
	c := &runtimev1.Container{Name: "app", Image: "example.com/app:v1", Command: []string{"bin/app"}, Args: []string{"--x"}}

	rb, err := rt.resolveBinary(context.Background(), p, rootfs, c)
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}

	calls, policy, dst := unpack.observed()
	if calls != 1 {
		t.Fatalf("MaterializeTree called %d times, want 1", calls)
	}
	if dst != rootfs {
		t.Errorf("materialized into %q, want the pod's own rootfs %q", dst, rootfs)
	}
	if policy != image.NativeUnpackPolicy() {
		t.Errorf("materialized under policy %+v, want the native dialect", policy)
	}
	// The manifest handed to the unpacker must be the one the PULL resolved and
	// verified — not one re-derived from anything else, or the digests the
	// unpacker checks against would have a second, unverified provenance.
	if got := unpack.manifest(); got != pull.manifest {
		t.Errorf("unpacker received manifest %v, want the pull's own %v", got, pull.manifest)
	}
	// argv[0] is the relative command resolved against the now-populated rootfs.
	if want := filepath.Join(rootfs, "bin/app"); rb.path != want {
		t.Errorf("binary = %q, want %q", rb.path, want)
	}
	if len(rb.argv) != 2 || rb.argv[0] != rb.path || rb.argv[1] != "--x" {
		t.Errorf("argv = %v, want [%q --x]", rb.argv, rb.path)
	}
}

// TestResolveBinaryFailsWhenMaterializationFails pins the fail-closed posture:
// there is no "materialize what we can" degradation, because a partial rootfs is
// a pod that starts and then behaves in a way no manifest describes.
func TestResolveBinaryFailsWhenMaterializationFails(t *testing.T) {
	boom := errors.New("tree refused")
	rt := newTestRuntime(t, Deps{
		Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
		Unpacker: &fakeUnpacker{err: boom},
	})
	p := &pod{box: hostBinBox(rt, "pod-badtree"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	c := &runtimev1.Container{Name: "app", Image: "example.com/app:v1", Command: []string{"app"}}

	_, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-badtree"), c)
	if !errors.Is(err, boom) {
		t.Fatalf("resolveBinary error = %v, want it to wrap %v", err, boom)
	}
}

// TestHostBinaryRoutesNeverMaterialize pins the two routes that have no image to
// unpack: the "native" sentinel and the absolute-host-path convention both run a
// binary that is already on the host, so touching the unpacker for them would be
// work — and a pod-rootfs write — with no image behind it.
func TestHostBinaryRoutesNeverMaterialize(t *testing.T) {
	cases := []struct {
		name string
		c    *runtimev1.Container
	}{
		{"native_sentinel", &runtimev1.Container{Name: "app", Image: NativeImage, Command: []string{"/bin/sleep"}}},
		{"absolute_host_path", &runtimev1.Container{Name: "app", Image: "/bin/sleep"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unpack := &fakeUnpacker{}
			rt := newTestRuntime(t, Deps{Unpacker: unpack})
			p := &pod{box: hostBinBox(rt, "pod-host"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
			if _, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-host"), tc.c); err != nil {
				t.Fatalf("resolveBinary: %v", err)
			}
			if calls, _, _ := unpack.observed(); calls != 0 {
				t.Errorf("MaterializeTree called %d times on a host-binary route, want 0", calls)
			}
		})
	}
}

// TestDefaultUnpackerWiring exercises the unpacker runtime.New builds when
// Deps.Unpacker is absent — the DAEMON'S own wiring, image.NewUnpacker over the
// same cache the puller commits into — end to end against an in-process
// registry, with a MULTI-LAYER image.
//
// Every other test in this file injects a fakeUnpacker, so none of them can tell
// the production wiring from a mis-wiring: an unpacker built over a second cache
// would leave them all green and would fail on the first real pod. This is the
// unit-tier companion to the M11.2-a6 integration acceptance — it proves the
// bytes land, where a6 additionally proves argv[0] execs.
func TestDefaultUnpackerWiring(t *testing.T) {
	host := testRegistryHost(t)
	ref := pushMultiLayerImage(t, host, "multi")

	root := t.TempDir()
	// testDeps leaves both Puller and Unpacker nil, so New builds the daemon's
	// own pair over one cache.
	rt, err := New(Config{Root: root}, testDeps(t, Deps{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := rt.unpacker.(*image.Unpacker); !ok {
		t.Fatalf("New wired unpacker %T, want *image.Unpacker", rt.unpacker)
	}

	p := &pod{box: hostBinBox(rt, "pod-unpack"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	rootfs := derivedRootfs(t, rt, "pod-unpack")
	c := &runtimev1.Container{Name: "app", Image: ref, Command: []string{"bin/app"}}

	rb, err := rt.resolveBinary(context.Background(), p, rootfs, c)
	if err != nil {
		t.Fatalf("resolveBinary: %v", err)
	}
	if want := filepath.Join(rootfs, "bin/app"); rb.path != want {
		t.Fatalf("binary = %q, want %q", rb.path, want)
	}
	// The later layer's bin/app is what landed, and the earlier layer's untouched
	// file survived — the multi-layer ordering the deliverable is about.
	if got := readFile(t, rb.path); got != "#!/bin/sh\nexit 0\n" {
		t.Errorf("bin/app = %q, want the second layer's content", got)
	}
	if got := readFile(t, filepath.Join(rootfs, "etc/from-layer-1")); got != "ONE" {
		t.Errorf("etc/from-layer-1 = %q, want ONE", got)
	}
	// It must be executable — a materialized payload that cannot be spawned is
	// the failure mode the owner-bit widening exists to prevent.
	fi, err := os.Stat(rb.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("bin/app mode = %#o, want the owner-execute bit", fi.Mode().Perm())
	}
	// A second pod materializes from the same committed tree.
	rootfs2 := derivedRootfs(t, rt, "pod-unpack-2")
	p2 := &pod{box: hostBinBox(rt, "pod-unpack-2"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
	if _, err := rt.resolveBinary(context.Background(), p2, rootfs2, c); err != nil {
		t.Fatalf("second resolveBinary: %v", err)
	}
	if got := readFile(t, filepath.Join(rootfs2, "bin/app")); got != "#!/bin/sh\nexit 0\n" {
		t.Errorf("second pod bin/app = %q", got)
	}
}

// --- fixtures ------------------------------------------------------------

// pushMultiLayerImage publishes a two-layer darwin/arm64 image whose second
// layer overwrites the first's bin/app, and returns its reference.
//
// Two layers is the point: a single-layer image cannot distinguish an unpacker
// that applies layers in order from one that applies only the last (or only the
// first), which is the mistake the M11.2-a6 acceptance names explicitly.
func pushMultiLayerImage(t *testing.T, host, repo string) string {
	t.Helper()
	img := multiLayerImage(t)
	ref, err := name.ParseReference(host + "/" + repo + ":v1")
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatalf("write image %s: %v", ref, err)
	}
	return ref.String()
}

// multiLayerImage builds the two-layer darwin/arm64 fixture.
func multiLayerImage(t *testing.T) ggcrv1.Image {
	t.Helper()
	l1 := layerFromTar(t, []testTarEntry{
		{name: "bin", dir: true, mode: 0o755},
		{name: "bin/app", mode: 0o755, data: "REPLACED BY LAYER 2"},
		{name: "etc", dir: true, mode: 0o755},
		{name: "etc/from-layer-1", mode: 0o644, data: "ONE"},
	})
	l2 := layerFromTar(t, []testTarEntry{
		{name: "bin/app", mode: 0o755, data: "#!/bin/sh\nexit 0\n"},
	})
	img, err := mutate.AppendLayers(empty.Image, l1, l2)
	if err != nil {
		t.Fatalf("append layers: %v", err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatalf("config file: %v", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = "darwin", "arm64", ""
	if img, err = mutate.ConfigFile(img, cf); err != nil {
		t.Fatalf("mutate config: %v", err)
	}
	return img
}

// testTarEntry is one entry of a fixture layer.
type testTarEntry struct {
	name string
	dir  bool
	mode int64
	data string
}

// layerFromTar renders entries as a real go-containerregistry layer (gzipped,
// with a correctly derived diffID), so the unpacker's digest and diffID checks
// are exercised against values it did not compute itself.
func layerFromTar(t *testing.T, entries []testTarEntry) ggcrv1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Typeflag: tar.TypeReg, Size: int64(len(e.data))}
		if e.dir {
			hdr.Typeflag, hdr.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", e.name, err)
		}
		if !e.dir && e.data != "" {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatalf("write body %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	raw := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(raw)), nil
	})
	if err != nil {
		t.Fatalf("layer from tar: %v", err)
	}
	return l
}

// readFile reads a materialized file.
func readFile(t *testing.T, path string) string {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(buf)
}

// hexRun builds a 64-character sha256 hex body out of one repeated nibble.
func hexRun(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// TestUnpackPolicyFollowsTheResolvedBackend pins the dialect discriminator at
// the one place that produces it: the pod's RESOLVED sandbox backend, the same
// value pullPolicy reads. A pod on the vm rung must materialize under the LINUX
// dialect, and an unset backend must fail closed rather than silently apply
// Mach-O rules to a Linux image.
func TestUnpackPolicyFollowsTheResolvedBackend(t *testing.T) {
	cases := []struct {
		backend runtimev1.SandboxBackend
		want    image.UnpackPolicy
		wantErr bool
	}{
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC, image.NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_EXEC, image.NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_UIDJAIL, image.NativeUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_VM, image.LinuxUnpackPolicy(), false},
		{runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED, image.UnpackPolicy{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.backend.String(), func(t *testing.T) {
			got, err := unpackPolicy(tc.backend)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("unpackPolicy(%v) = %+v, want an error", tc.backend, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unpackPolicy: %v", err)
			}
			if got != tc.want {
				t.Errorf("policy = %+v, want %+v", got, tc.want)
			}
		})
	}

	// Through resolveBinary: a pod whose resolved backend is the vm rung
	// materializes under the Linux dialect, not the native one.
	t.Run("through_resolve_binary", func(t *testing.T) {
		unpack := &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}}}
		rt := newTestRuntime(t, Deps{
			Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
			Unpacker: unpack,
		})
		p := &pod{box: hostBinBox(rt, "pod-vm"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM}
		if _, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-vm"),
			&runtimev1.Container{Name: "app", Image: "example.com/app:v1"}); err != nil {
			t.Fatalf("resolveBinary: %v", err)
		}
		if _, policy, _ := unpack.observed(); policy != image.LinuxUnpackPolicy() {
			t.Errorf("materialized under %+v, want the linux dialect", policy)
		}
	})

	// An unresolved backend refuses the container instead of materializing it.
	t.Run("unset_backend_refuses", func(t *testing.T) {
		unpack := &fakeUnpacker{}
		rt := newTestRuntime(t, Deps{
			Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
			Unpacker: unpack,
		})
		p := &pod{box: hostBinBox(rt, "pod-nobackend")}
		_, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-nobackend"),
			&runtimev1.Container{Name: "app", Image: "example.com/app:v1", Command: []string{"app"}})
		if err == nil {
			t.Fatal("resolveBinary accepted a pod with no resolved backend")
		}
		if calls, _, _ := unpack.observed(); calls != 0 {
			t.Errorf("MaterializeTree called %d times with no resolved backend, want 0", calls)
		}
	})
}

// TestResolveBinaryMergesTheImageConfig pins the M11.2-d1 wiring of
// image.MergeRunSpec into the OCI route — the replacement for the M1 placeholder
// that made argv literally command+args.
//
// Two rows are RED AT main in the strongest sense: a container with args and no
// command PANICKED on cmd[0], and a container with neither was refused outright
// even though its image declared an Entrypoint.
func TestResolveBinaryMergesTheImageConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      image.ImageRunConfig
		command  []string
		args     []string
		wantArgv []string
		wantEnv  []string
		wantDir  string
	}{
		{
			name:     "image_entrypoint_and_cmd_with_no_pod_command",
			cfg:      image.ImageRunConfig{Entrypoint: []string{"bin/server"}, Cmd: []string{"--serve"}, Env: []string{"PATH=/usr/bin"}, WorkingDir: "/srv"},
			wantArgv: []string{"bin/server", "--serve"},
			wantEnv:  []string{"PATH=/usr/bin"},
			wantDir:  "/srv",
		},
		{
			name:     "pod_args_over_image_entrypoint",
			cfg:      image.ImageRunConfig{Entrypoint: []string{"bin/server"}, Cmd: []string{"--serve"}},
			args:     []string{"--other"},
			wantArgv: []string{"bin/server", "--other"},
		},
		{
			name:     "pod_command_discards_image_cmd",
			cfg:      image.ImageRunConfig{Entrypoint: []string{"bin/server"}, Cmd: []string{"--serve"}},
			command:  []string{"bin/other"},
			wantArgv: []string{"bin/other"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unpack := &fakeUnpacker{runCfg: tc.cfg}
			rt := newTestRuntime(t, Deps{
				Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
				Unpacker: unpack,
			})
			p := &pod{box: hostBinBox(rt, "pod-merge"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
			rootfs := derivedRootfs(t, rt, "pod-merge")
			rb, err := rt.resolveBinary(context.Background(), p, rootfs,
				&runtimev1.Container{Name: "app", Image: "example.com/app:v1", Command: tc.command, Args: tc.args})
			if err != nil {
				t.Fatalf("resolveBinary: %v", err)
			}
			// argv[0] is the merged program resolved against the pod rootfs.
			want := append([]string{}, tc.wantArgv...)
			want[0] = filepath.Join(rootfs, want[0])
			if len(rb.argv) != len(want) {
				t.Fatalf("argv = %v, want %v", rb.argv, want)
			}
			for i := range want {
				if rb.argv[i] != want[i] {
					t.Fatalf("argv = %v, want %v", rb.argv, want)
				}
			}
			if rb.path != want[0] {
				t.Errorf("path = %q, want %q", rb.path, want[0])
			}
			if tc.wantEnv != nil {
				if len(rb.env) != len(tc.wantEnv) || rb.env[0] != tc.wantEnv[0] {
					t.Errorf("env = %v, want %v", rb.env, tc.wantEnv)
				}
			}
			if rb.workingDir != tc.wantDir {
				t.Errorf("workingDir = %q, want %q", rb.workingDir, tc.wantDir)
			}
		})
	}

	// A container that neither the pod nor the image gives a command to is a
	// legible refusal, not an empty argv handed to a spawn.
	t.Run("nothing_to_run_is_refused", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
			Unpacker: &fakeUnpacker{},
		})
		p := &pod{box: hostBinBox(rt, "pod-nocmd"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		_, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-nocmd"),
			&runtimev1.Container{Name: "app", Image: "example.com/app:v1"})
		if !errors.Is(err, image.ErrRunSpecInvalid) {
			t.Fatalf("resolveBinary error = %v, want image.ErrRunSpecInvalid", err)
		}
	})

	// The runAsNonRoot rule reaches the container: an image whose USER is a NAME
	// under runAsNonRoot is refused, because the host will not resolve a name out
	// of the image's own /etc/passwd to decide a privilege question.
	t.Run("run_as_non_root_with_a_named_image_user_is_refused", func(t *testing.T) {
		rt := newTestRuntime(t, Deps{
			Puller:   &fakePuller{manifest: &runtimev1.ImageManifest{Reference: "example.com/app:v1"}},
			Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Cmd: []string{"/app"}, User: "nobody"}},
		})
		p := &pod{box: hostBinBox(rt, "pod-nonroot"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
		_, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-nonroot"),
			&runtimev1.Container{
				Name: "app", Image: "example.com/app:v1",
				SecurityContext: &runtimev1.SecurityContext{RunAsNonRoot: true},
			})
		if !errors.Is(err, image.ErrRunSpecInvalid) {
			t.Fatalf("resolveBinary error = %v, want image.ErrRunSpecInvalid", err)
		}
	})

	// The HOST-BINARY routes never consult the image config: there is no image.
	t.Run("host_binary_routes_carry_no_merged_env", func(t *testing.T) {
		for _, c := range []*runtimev1.Container{
			{Name: "app", Image: NativeImage, Command: []string{"/bin/sleep"}, WorkingDir: "/w"},
			{Name: "app", Image: "/bin/sleep", WorkingDir: "/w"},
		} {
			rt := newTestRuntime(t, Deps{Unpacker: &fakeUnpacker{runCfg: image.ImageRunConfig{Env: []string{"LEAK=1"}}}})
			p := &pod{box: hostBinBox(rt, "pod-host2"), backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC}
			rb, err := rt.resolveBinary(context.Background(), p, derivedRootfs(t, rt, "pod-host2"), c)
			if err != nil {
				t.Fatalf("resolveBinary: %v", err)
			}
			if rb.env != nil {
				t.Errorf("host-binary route carried a merged env %v", rb.env)
			}
			if rb.workingDir != "/w" {
				t.Errorf("workingDir = %q, want the pod's own /w", rb.workingDir)
			}
		}
	})
}

// TestContainerEnvMergesTheImageEnvironment pins the env seam: a pulled image's
// $PATH reaches the child, the pod's entries still override it, and the DYLD
// shim injection is unchanged on top of the merged base.
//
// The runtime's own injections are excluded from the comparison rather than
// spelled out here: this test is about what the MERGE contributes, and each
// injection is pinned by the test that owns it (TMPDIR by
// TestPodLaunchEnvCarriesTmpInDataVolume, the shims by pod_pathshim_test.go).
func TestContainerEnvMergesTheImageEnvironment(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	box := hostBinBox(rt, "pod-env")
	c := &runtimev1.Container{Name: "app", Env: []*runtimev1.EnvVar{{Name: "POD", Value: "1"}}}

	merged, err := rt.containerEnv(box, c, []string{"PATH=/usr/bin", "POD=1"})
	if err != nil {
		t.Fatalf("containerEnv: %v", err)
	}
	if got := withoutName(merged, tmpDirEnv); len(got) != 2 || got[0] != "PATH=/usr/bin" || got[1] != "POD=1" {
		t.Errorf("env = %v, want the merged base verbatim", merged)
	}

	// nil base keeps the pre-M11.2-d1 behaviour byte for byte.
	fallback, err := rt.containerEnv(box, c, nil)
	if err != nil {
		t.Fatalf("containerEnv: %v", err)
	}
	if got := withoutName(fallback, tmpDirEnv); len(got) != 1 || got[0] != "POD=1" {
		t.Errorf("fallback env = %v, want [POD=1]", fallback)
	}
}

// withoutName drops every "name=..." entry from env, so a test can assert on the
// entries it is actually about.
func withoutName(env []string, name string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); k != name {
			out = append(out, e)
		}
	}
	return out
}
