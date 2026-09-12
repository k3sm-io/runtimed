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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"

	guestv1 "k3sm.io/apis/guest/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// the M11.2-d11 GATE: what createVMPod stamps on VMSpec.Containers.
//
// Every row drives the real wiring — CreatePod → createVMPod →
// resolveVMContainers → pkg/image.MergeRunSpec — and reads the VMSpec the vm
// backend was handed. Nothing here re-implements the merge or hand-writes an
// argv: the four-quadrant table, the $(VAR) expansion and the runAsNonRoot rule
// are asserted through the shipped merge function, so a divergence between the
// two spines shows up as a failing row rather than as two green tables.

// imageWorld is the pull+unpack seam pair serving a different image config per
// REFERENCE.
//
// The harness's shared fakePuller/fakeUnpacker cannot express this: they serve
// one manifest and one run config for every reference, so a multi-container pod
// would have every container merge against the same image — which is exactly the
// confusion a per-container mapper has to be proven free of. Serving the config
// through the manifest's own reference also keeps the two halves of the seam
// consistent (Unpacker's doc: the tree and the config come from one image).
type imageWorld struct {
	cfgs map[string]image.ImageRunConfig
	// indexHits names the references this world answers WITHOUT a registry
	// round trip — the PullResult.Fetched=false shape. A reference absent from
	// the map is fetched, which is the ordinary case and so the default.
	indexHits map[string]bool
	// errs makes a named reference's pull fail with a chosen error, which is the
	// only way to drive the pull-failure classification through the real path:
	// the sentinel is what pullFailureReason reads, never the message.
	errs map[string]error
	// delays holds a reference's pull for a fixed span, so a duration assertion
	// has a real lower bound to test against instead of a zero it cannot
	// distinguish from an unstamped field.
	delays map[string]time.Duration

	mu           sync.Mutex
	pulled       []string
	policies     []image.PlatformPolicy
	materialized int
}

func newImageWorld(cfgs map[string]image.ImageRunConfig) *imageWorld {
	return &imageWorld{cfgs: cfgs}
}

// servesFromIndex marks ref as answered from the local index (no registry round
// trip), returning the world so a fixture reads as one expression.
func (w *imageWorld) servesFromIndex(ref string) *imageWorld {
	if w.indexHits == nil {
		w.indexHits = map[string]bool{}
	}
	w.indexHits[ref] = true
	return w
}

// failsWith makes ref's pull fail with err.
func (w *imageWorld) failsWith(ref string, err error) *imageWorld {
	if w.errs == nil {
		w.errs = map[string]error{}
	}
	w.errs[ref] = err
	return w
}

// takes makes ref's pull last at least d.
func (w *imageWorld) takes(ref string, d time.Duration) *imageWorld {
	if w.delays == nil {
		w.delays = map[string]time.Duration{}
	}
	w.delays[ref] = d
	return w
}

func (w *imageWorld) Pull(_ context.Context, ref string, _ *image.RegistryCredential, policy image.PlatformPolicy, _ runtimev1.ImagePullPolicy) (*image.PullResult, error) {
	w.mu.Lock()
	w.pulled = append(w.pulled, ref)
	w.policies = append(w.policies, policy)
	w.mu.Unlock()
	if err, ok := w.errs[ref]; ok {
		return nil, err
	}
	if _, ok := w.cfgs[ref]; !ok {
		return nil, fmt.Errorf("no image %q in this world", ref)
	}
	if d := w.delays[ref]; d > 0 {
		time.Sleep(d)
	}
	return &image.PullResult{
		Manifest: &runtimev1.ImageManifest{
			Reference: ref,
			Config:    &runtimev1.Descriptor{Digest: "sha256:" + strings.Repeat("a", 64)},
		},
		CacheHit: true,
		// The fact ContainerStatus.image_pull is made of: whether a registry was
		// contacted. It is not CacheHit inverted (see image.PullResult.Fetched),
		// which is why this world sets the two independently.
		Fetched: !w.indexHits[ref],
	}, nil
}

func (w *imageWorld) MaterializeTree(_ context.Context, _ *runtimev1.ImageManifest, policy image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	w.mu.Lock()
	w.materialized++
	w.mu.Unlock()
	return &image.MaterializeResult{Tree: &image.Tree{Key: "sha256:fake", Rootfs: dst, Policy: policy}}, nil
}

func (w *imageWorld) ImageRunConfig(mfst *runtimev1.ImageManifest) (image.ImageRunConfig, error) {
	cfg, ok := w.cfgs[mfst.GetReference()]
	if !ok {
		return image.ImageRunConfig{}, fmt.Errorf("no config for %q", mfst.GetReference())
	}
	return cfg, nil
}

func (w *imageWorld) observed() (pulled []string, policies []image.PlatformPolicy, materialized int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.pulled...), append([]image.PlatformPolicy(nil), w.policies...), w.materialized
}

// newVMImageRuntime builds a vm-routed Runtime over an imageWorld, wired exactly
// as production wires the vm path (the share planner's pod-dir/work-root
// alignment included — see vmPodConfig).
func newVMImageRuntime(t *testing.T, w *imageWorld) (*Runtime, *fakeVMBackend) {
	t.Helper()
	return newVMImageRuntimeWith(t, w, Deps{})
}

// newVMImageRuntimeWith is newVMImageRuntime with the caller's own extra seams
// (the credential resolver, for the one classification that fails before any
// pull is attempted) filled in around the image world.
func newVMImageRuntimeWith(t *testing.T, w *imageWorld, d Deps) (*Runtime, *fakeVMBackend) {
	t.Helper()
	vmb := &fakeVMBackend{available: true, bootOK: true}
	d.VMBackend, d.Puller, d.Unpacker = vmb, w, w
	cfg, d := vmPodConfig(t, d)
	return newTestRuntimeCfg(t, cfg, d), vmb
}

// vmBoxWith builds a vm-routed PodBox carrying exactly the given init and main
// containers.
func vmBoxWith(rt *Runtime, podID string, inits, mains []*runtimev1.Container) *runtimev1.PodBox {
	box := vmPodBox(rt, podID, 0)
	box.InitContainers = inits
	box.Containers = mains
	return box
}

// createVMSpec drives the real CreatePod and returns the VMSpec the backend was
// handed, failing the test if the pod did not reach the backend.
func createVMSpec(t *testing.T, rt *Runtime, vmb *fakeVMBackend, box *runtimev1.PodBox) sandbox.VMSpec {
	t.Helper()
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	n, spec := vmb.created()
	if n != 1 {
		t.Fatalf("CreateVM called %d times, want 1", n)
	}
	return spec
}

// oneVMContainer returns the single mapped container of a one-container pod.
func oneVMContainer(t *testing.T, spec sandbox.VMSpec) sandbox.VMContainer {
	t.Helper()
	if len(spec.Containers) != 1 {
		t.Fatalf("VMSpec carries %d containers, want 1", len(spec.Containers))
	}
	return spec.Containers[0]
}

// TestVMContainerMergeQuadrants drives Kubernetes' four-quadrant command/args
// table, the $(VAR) expansion and the env/working-dir precedence through the
// real merge, on the real vm create path.
//
// Row 3 (a pod command DISCARDS the image's Cmd) is the one people get wrong and
// the reason this is a table rather than a single happy path: the image's Cmd is
// arguments to an entrypoint the pod just replaced, so carrying it over would
// pass one program's arguments to another.
func TestVMContainerMergeQuadrants(t *testing.T) {
	const ref = "docker.io/library/app:1"
	cfg := image.ImageRunConfig{
		Entrypoint: []string{"/app"},
		Cmd:        []string{"--serve", "--port=$(PORT)"},
		Env:        []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=C"},
		WorkingDir: "/srv",
	}
	cases := []struct {
		name        string
		container   *runtimev1.Container
		wantArgv    []string
		wantEnv     []string
		wantWorkdir string
	}{
		{
			name:        "no-command-no-args-takes-entrypoint-plus-cmd",
			container:   &runtimev1.Container{Name: "c", Image: ref},
			wantArgv:    []string{"/app", "--serve", "--port=8080"},
			wantEnv:     []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=C"},
			wantWorkdir: "/srv",
		},
		{
			name:        "args-only-keep-entrypoint-and-replace-cmd",
			container:   &runtimev1.Container{Name: "c", Image: ref, Args: []string{"--debug", "--port=$(PORT)"}},
			wantArgv:    []string{"/app", "--debug", "--port=8080"},
			wantEnv:     []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=C"},
			wantWorkdir: "/srv",
		},
		{
			name:        "command-only-drops-the-image-cmd",
			container:   &runtimev1.Container{Name: "c", Image: ref, Command: []string{"/bin/sh"}},
			wantArgv:    []string{"/bin/sh"},
			wantEnv:     []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=C"},
			wantWorkdir: "/srv",
		},
		{
			name: "command-and-args-replace-both-halves",
			container: &runtimev1.Container{
				Name: "c", Image: ref,
				Command:    []string{"/bin/sh", "-c"},
				Args:       []string{"echo $(PORT) $(UNDEFINED) $$HOME"},
				WorkingDir: "/work",
			},
			// PORT expands; an UNDEFINED reference is left verbatim (a shell
			// snippet must never be silently emptied); "$$" is a literal "$".
			wantArgv:    []string{"/bin/sh", "-c", "echo 8080 $(UNDEFINED) $HOME"},
			wantEnv:     []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=C"},
			wantWorkdir: "/work",
		},
		{
			name: "pod-env-overrides-in-place-and-appends",
			container: &runtimev1.Container{
				Name: "c", Image: ref, Command: []string{"/app"},
				Env: []*runtimev1.EnvVar{
					{Name: "LANG", Value: "en_US.UTF-8"},
					{Name: "EXTRA", Value: "yes"},
				},
			},
			wantArgv: []string{"/app"},
			// LANG is overridden IN place (image order preserved), EXTRA appended.
			wantEnv:     []string{"PATH=/usr/local/bin", "PORT=8080", "LANG=en_US.UTF-8", "EXTRA=yes"},
			wantWorkdir: "/srv",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, vmb := newVMImageRuntime(t, newImageWorld(map[string]image.ImageRunConfig{ref: cfg}))
			box := vmBoxWith(rt, "pod-merge", nil, []*runtimev1.Container{tc.container})
			got := oneVMContainer(t, createVMSpec(t, rt, vmb, box))

			if !reflect.DeepEqual(got.Argv, tc.wantArgv) {
				t.Errorf("argv = %q, want %q", got.Argv, tc.wantArgv)
			}
			if !reflect.DeepEqual(got.Env, tc.wantEnv) {
				t.Errorf("env = %q, want %q", got.Env, tc.wantEnv)
			}
			if got.WorkingDir != tc.wantWorkdir {
				t.Errorf("working dir = %q, want %q", got.WorkingDir, tc.wantWorkdir)
			}
		})
	}
}

// TestVMContainerEnvCarriesNoHostProcessInjections pins the one deliberate
// divergence from the host-process spine's environment: the guest gets the merge
// and nothing else.
//
// containerEnv injects TMPDIR (a HOST path inside the pod data volume) and
// DYLD_INSERT_LIBRARIES (the macOS path-rebase and DNS shims). Both are
// host-process facts: the path does not exist in the guest's namespace and the
// dynamic linker is not dyld. Carrying them would put a broken TMPDIR in front of
// every workload that asks the platform for a temp directory.
func TestVMContainerEnvCarriesNoHostProcessInjections(t *testing.T) {
	const ref = "docker.io/library/app:1"
	w := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/app"}, Env: []string{"PATH=/usr/bin"}}})
	rt, vmb := newVMImageRuntime(t, w)
	box := vmBoxWith(rt, "pod-env", nil, []*runtimev1.Container{{
		Name:         "c",
		Image:        ref,
		VolumeMounts: []*runtimev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}},
	}})
	box.Volumes = []*runtimev1.Volume{{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}}}
	box.Annotations = map[string]string{dyldInsertAnnotation: "/opt/k3sm/lib/libdns.dylib"}

	got := oneVMContainer(t, createVMSpec(t, rt, vmb, box))
	for _, e := range got.Env {
		name, _, _ := strings.Cut(e, "=")
		switch name {
		case tmpDirEnv, dyldInsertEnv, pathShimRootfsEnv, pathShimMountsEnv:
			t.Errorf("guest container env carries the host-process entry %q; the guest has no dyld and no host TMPDIR", e)
		}
	}
	if !reflect.DeepEqual(got.Env, []string{"PATH=/usr/bin"}) {
		t.Errorf("env = %q, want the merge alone", got.Env)
	}
}

// TestVMContainersMapTheWholePodInStartOrder is the multi-container row: init
// containers first, every field carried, and each container's rootfs tag taken
// from the share plan rather than restated.
func TestVMContainersMapTheWholePodInStartOrder(t *testing.T) {
	const (
		initRef = "docker.io/library/initdb:1"
		mainRef = "docker.io/library/postgres:16"
		auxRef  = "docker.io/library/exporter:1"
	)
	w := newImageWorld(map[string]image.ImageRunConfig{
		initRef: {Entrypoint: []string{"/usr/bin/initdb"}, Cmd: []string{"/pgdata"}, Env: []string{"PGDATA=/pgdata"}, WorkingDir: "/"},
		mainRef: {Entrypoint: []string{"/usr/local/bin/postgres"}, Cmd: []string{"-D", "/pgdata"}, Env: []string{"PGDATA=/pgdata"}, WorkingDir: "/var/lib/postgresql"},
		auxRef:  {Entrypoint: []string{"/exporter"}, User: "65534"},
	})
	rt, vmb := newVMImageRuntime(t, w)

	box := vmBoxWith(rt, "pod-multi",
		[]*runtimev1.Container{{Name: "init-db", Image: initRef}},
		[]*runtimev1.Container{
			{Name: "postgres", Image: mainRef, Tty: true, Stdin: true},
			{Name: "aux", Image: auxRef},
		})
	// The identity chain: a pod-level runAsUser plus a container-level runAsUser
	// that must WIN for the container that sets it.
	//
	// No fsGroup, and it is not an omission: a vm pod that requests one is now
	// refused outright (errVMFsGroupUnsupported), because this host's virtiofs
	// cannot provide the idmapped mount that would apply it to the pod's volumes.
	// The supplemental-GID half used to work and is what made the drop look
	// harmless — a container held the group while its volumes were not owned by
	// it — so that assertion is gone with the behaviour it described.
	box.PodSecurityContext = &runtimev1.PodSecurityContext{RunAsUser: 999, RunAsGroup: 999}
	box.Containers[0].SecurityContext = &runtimev1.SecurityContext{RunAsUser: 1001} // postgres

	spec := createVMSpec(t, rt, vmb, box)

	t.Run("start order is init containers first", func(t *testing.T) {
		var names []string
		for _, c := range spec.Containers {
			names = append(names, c.Name)
		}
		if want := []string{"init-db", "postgres", "aux"}; !reflect.DeepEqual(names, want) {
			t.Fatalf("containers = %v, want %v (init first, then mains in list order)", names, want)
		}
		if !spec.Containers[0].Init {
			t.Error("init-db is not marked init")
		}
		for _, c := range spec.Containers[1:] {
			if c.Init {
				t.Errorf("main container %q is marked init", c.Name)
			}
		}
	})

	t.Run("each container merged against ITS OWN image", func(t *testing.T) {
		want := map[string][]string{
			"init-db":  {"/usr/bin/initdb", "/pgdata"},
			"postgres": {"/usr/local/bin/postgres", "-D", "/pgdata"},
			"aux":      {"/exporter"},
		}
		for _, c := range spec.Containers {
			if !reflect.DeepEqual(c.Argv, want[c.Name]) {
				t.Errorf("%s argv = %q, want %q", c.Name, c.Argv, want[c.Name])
			}
		}
		if spec.Containers[1].WorkingDir != "/var/lib/postgresql" {
			t.Errorf("postgres working dir = %q, want the image's", spec.Containers[1].WorkingDir)
		}
		if !spec.Containers[1].TTY || !spec.Containers[1].Stdin {
			t.Error("postgres lost its tty/stdin request")
		}
	})

	t.Run("rootfs tags are the share plan's", func(t *testing.T) {
		plan, err := mount.ComputeSharePlan(box, mustPodDir(t, rt, box.GetPodId()), rt.cfg.Root, rt.binder.Class())
		if err != nil {
			t.Fatalf("ComputeSharePlan: %v", err)
		}
		wantTag, err := vmRootfsShareTag(plan)
		if err != nil {
			t.Fatalf("vmRootfsShareTag: %v", err)
		}
		declared := map[string]bool{}
		for _, s := range spec.Volumes.Shares {
			declared[s.Tag] = true
		}
		for _, c := range spec.Containers {
			if c.RootfsTag != wantTag {
				t.Errorf("%s rootfs tag = %q, want the plan's %q", c.Name, c.RootfsTag, wantTag)
			}
			if !declared[c.RootfsTag] {
				t.Errorf("%s names rootfs tag %q, which the spec's own share plan does not carry", c.Name, c.RootfsTag)
			}
		}
	})

	t.Run("identity is numeric and follows the securityContext chain", func(t *testing.T) {
		byName := map[string]sandbox.VMContainer{}
		for _, c := range spec.Containers {
			byName[c.Name] = c
		}
		if got := byName["init-db"]; got.UID != 999 || got.GID != 999 {
			t.Errorf("init-db uid/gid = %d/%d, want the pod's 999/999", got.UID, got.GID)
		}
		if got := byName["postgres"]; got.UID != 1001 {
			t.Errorf("postgres uid = %d, want the container's 1001", got.UID)
		}
		// The image's numeric user supplies the uid when the pod set none for
		// that container... except that this pod DID set one pod-wide, which
		// wins. That is the precedence being pinned.
		if got := byName["aux"]; got.UID != 999 {
			t.Errorf("aux uid = %d, want the pod's 999 (it outranks the image USER)", got.UID)
		}
	})

	t.Run("pulls once per container, under the VM platform policy, and materializes exactly one rootfs", func(t *testing.T) {
		pulled, policies, materialized := w.observed()
		if want := []string{initRef, mainRef, auxRef}; !reflect.DeepEqual(pulled, want) {
			t.Errorf("pulled %v, want %v (one pull per container, in start order)", pulled, want)
		}
		for i, p := range policies {
			if p.Backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
				t.Errorf("pull %d ran under backend %v, want SANDBOX_BACKEND_VM — a vm pod must not select a Mach-O image", i, p.Backend)
			}
		}
		// The recorded ceiling, asserted: the plan carries ONE pod-wide rootfs
		// share, so exactly one image is materialized into it — the first
		// container's, in start order. Materializing every container's image
		// would have each overwrite the last; materializing none is the empty
		// rootfs the guest cannot exec out of.
		if materialized != 1 {
			t.Errorf("materialized %d trees; want exactly 1 (the single pod-wide rootfs share)", materialized)
		}
	})
}

// TestVMContainerImageUserSuppliesTheUID pins the other half of the identity
// rule: with no runAsUser anywhere, a numeric image USER is the uid.
func TestVMContainerImageUserSuppliesTheUID(t *testing.T) {
	const ref = "docker.io/library/app:1"
	w := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/app"}, User: "65534:65534"}})
	rt, vmb := newVMImageRuntime(t, w)
	box := vmBoxWith(rt, "pod-imguser", nil, []*runtimev1.Container{{Name: "c", Image: ref}})

	got := oneVMContainer(t, createVMSpec(t, rt, vmb, box))
	if got.UID != 65534 {
		t.Errorf("uid = %d, want the image USER's 65534", got.UID)
	}
	// The GROUP half does not cross (guest/v1 carries no user string, B193), and
	// that is recorded rather than silently rounded: the gid comes from the
	// securityContext chain alone, which is unset here.
	if got.GID != 0 {
		t.Errorf("gid = %d, want 0 — the image USER's group half is not carried today", got.GID)
	}
}

// TestVMContainerFailsClosed is the refusal table: every shape the vm path must
// reject before a guest exists, with the pod's own reason.
//
// Each row asserts the backend was never called, because a refusal that still
// booted a machine would be a leak, not a refusal.
func TestVMContainerFailsClosed(t *testing.T) {
	const (
		plainRef = "docker.io/library/app:1"
		rootRef  = "docker.io/library/root:1"
		namedRef = "docker.io/library/named:1"
		bareRef  = "docker.io/library/bare:1"
	)
	world := map[string]image.ImageRunConfig{
		plainRef: {Entrypoint: []string{"/app"}},
		rootRef:  {Entrypoint: []string{"/app"}, User: "0"},
		namedRef: {Entrypoint: []string{"/app"}, User: "nobody"},
		bareRef:  {},
	}
	cases := []struct {
		name    string
		inits   []*runtimev1.Container
		mains   []*runtimev1.Container
		mutate  func(*runtimev1.PodBox)
		wantErr error
		wantMsg string
	}{
		{
			// The M0 absolute-path convention names a Mach-O on this Mac. A
			// Linux guest cannot exec one and cannot see the host filesystem, so
			// the reference is refused where it is read rather than crossing as
			// an argv[0] that dies as a bare ENOENT.
			name:    "absolute-path-host-binary-image",
			mains:   []*runtimev1.Container{{Name: "c", Image: "/bin/sleep"}},
			wantErr: errVMHostBinaryImage,
			wantMsg: "/bin/sleep",
		},
		{
			name:    "native-host-process-sentinel",
			mains:   []*runtimev1.Container{{Name: "c", Image: NativeImage, Command: []string{"/bin/sleep"}}},
			wantErr: errVMHostBinaryImage,
			wantMsg: NativeImage,
		},
		{
			name:    "empty-image",
			mains:   []*runtimev1.Container{{Name: "c", Image: ""}},
			wantErr: errInvalidPodBox,
			wantMsg: "image is required",
		},
		{
			// The B193 gap, failed closed: the host will not read a
			// pod-controlled /etc/passwd to answer a privilege question, and
			// guest/v1 has no field to hand the guest the name — so the only
			// remaining behaviour would be to run as root a container that asked
			// to be someone else.
			name:    "non-numeric-image-user-with-no-runAsUser",
			mains:   []*runtimev1.Container{{Name: "c", Image: namedRef}},
			wantErr: errVMUnresolvableUser,
			wantMsg: `"nobody"`,
		},
		{
			// Upstream's verifyRunAsNonRoot, reached through the real merge.
			name: "runAsNonRoot-with-a-root-image",
			mains: []*runtimev1.Container{{
				Name: "c", Image: rootRef,
				SecurityContext: &runtimev1.SecurityContext{RunAsNonRoot: true},
			}},
			wantErr: image.ErrRunSpecInvalid,
			wantMsg: "runAsNonRoot",
		},
		{
			name:    "no-command-anywhere",
			mains:   []*runtimev1.Container{{Name: "c", Image: bareRef}},
			wantErr: image.ErrRunSpecInvalid,
			wantMsg: "neither Entrypoint nor Cmd",
		},
		{
			// guest/v1 carries one ordering bit, read as "run to completion
			// first". A sidecar never exits, so mapping it onto that bit is a
			// boot that never fails and never finishes.
			name: "native-sidecar-cannot-be-ordered",
			inits: []*runtimev1.Container{{
				Name: "side", Image: plainRef,
				RestartPolicy: runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS,
			}},
			mains:   []*runtimev1.Container{{Name: "c", Image: plainRef}},
			wantErr: errVMSidecarUnexpressible,
			wantMsg: "sidecar",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, vmb := newVMImageRuntime(t, newImageWorld(world))
			box := vmBoxWith(rt, "pod-refuse", tc.inits, tc.mains)
			if tc.mutate != nil {
				tc.mutate(box)
			}
			_, reason, err := rt.createPod(context.Background(), box)
			if err == nil {
				t.Fatal("the vm path accepted a pod it must refuse")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want one wrapping %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not name %q, so an operator cannot act on it", err, tc.wantMsg)
			}
			if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
				t.Errorf("reason = %v, want INVALID_POD_BOX (the box is unrunnable; nothing was attempted)", reason)
			}
			if n, _ := vmb.created(); n != 0 {
				t.Errorf("CreateVM called %d times on a refused pod; must be 0", n)
			}
		})
	}
}

// TestVMContainerPullFailureIsAnImagePullFailure keeps the pull's own failures in
// the IMAGE_PULL bucket rather than blaming the box: a registry that is down is
// not a pod the operator wrote wrongly.
func TestVMContainerPullFailureIsAnImagePullFailure(t *testing.T) {
	rt, vmb := newVMImageRuntime(t, newImageWorld(map[string]image.ImageRunConfig{}))
	box := vmBoxWith(rt, "pod-pullfail", nil, []*runtimev1.Container{{Name: "c", Image: "docker.io/library/missing:1"}})

	_, reason, err := rt.createPod(context.Background(), box)
	if err == nil {
		t.Fatal("a failed pull must fail the pod")
	}
	if reason != runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL {
		t.Errorf("reason = %v, want IMAGE_PULL", reason)
	}
	if n, _ := vmb.created(); n != 0 {
		t.Errorf("CreateVM called %d times after a failed pull; must be 0", n)
	}
}

// TestVMRootfsShareTagFailsClosedWithoutTheShare pins the share-plan dependency
// directly: a plan carrying no rootfs share describes a pod no guest can compose,
// and the mapper must say so rather than stamping an empty tag the composer would
// then reject with a less specific message.
func TestVMRootfsShareTagFailsClosedWithoutTheShare(t *testing.T) {
	if _, err := vmRootfsShareTag(mount.SharePlan{}); !errors.Is(err, errVMNoRootfsShare) {
		t.Errorf("err = %v, want errVMNoRootfsShare", err)
	}
	tag, err := vmRootfsShareTag(mount.SharePlan{Shares: []mount.Share{
		{Tag: mount.ShareTagProj}, {Tag: mount.ShareTagRootfs, Root: "/pods/p/rootfs"},
	}})
	if err != nil {
		t.Fatalf("vmRootfsShareTag: %v", err)
	}
	if tag != mount.ShareTagRootfs {
		t.Errorf("tag = %q, want the plan's %q", tag, mount.ShareTagRootfs)
	}
}

// mustPodDir returns the runtime's own derivation of a pod's directory.
func mustPodDir(t *testing.T, rt *Runtime, podID string) string {
	t.Helper()
	dir, err := rt.podDir(podID)
	if err != nil {
		t.Fatalf("podDir: %v", err)
	}
	return dir
}

// containsInt64 reports whether v is in xs.
func containsInt64(xs []int64, v int64) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// TestVMContainerStatusReportsTheImagePullOutcome is the vm half of the
// image_pull gate: the fact is produced host-side, at plan time, and has to
// survive into a status folded from a guest event that knows nothing about it.
//
// The two shapes are both driven, because the whole point of the field is that a
// consumer can choose between the kubelet's two Pulled messages without guessing:
// a container whose image was fetched reports pulled=true with the resolution's
// wall time, and one served from the node's local index reports pulled=false.
// The init container carries it too — an init container's image is pulled
// exactly like a main's, and its status rides a different list.
func TestVMContainerStatusReportsTheImagePullOutcome(t *testing.T) {
	const (
		fetchRef = "docker.io/library/app:1"
		hitRef   = "docker.io/library/initdb:1"
		pullTook = 20 * time.Millisecond
	)
	w := newImageWorld(map[string]image.ImageRunConfig{
		fetchRef: {Entrypoint: []string{"/app"}},
		hitRef:   {Entrypoint: []string{"/initdb"}},
	}).servesFromIndex(hitRef).takes(fetchRef, pullTook)
	rt, vmb := newVMImageRuntime(t, w)

	box := vmBoxWith(rt, "pod-vm-pull",
		[]*runtimev1.Container{{Name: "init", Image: hitRef}},
		[]*runtimev1.Container{{Name: "app", Image: fetchRef}})
	// The real assembly, then the real fold: createPod returns the pod
	// createVMPod built, and the guest event is applied to it exactly as the
	// ContainerEvents watcher applies one.
	p, _, err := rt.createPod(context.Background(), box)
	if err != nil {
		t.Fatalf("createPod: %v", err)
	}
	if n, _ := vmb.created(); n != 1 {
		t.Fatalf("CreateVM called %d times, want 1", n)
	}
	for _, name := range []string{"init", "app"} {
		rt.applyGuestContainerEvent(p, &guestv1.ContainerEvent{
			Container: name,
			Started:   &guestv1.ContainerStarted{Pid: 7},
		})
	}

	st := rt.podStatus(p)
	inits, mains := st.GetInitContainerStatuses(), st.GetContainerStatuses()
	if len(inits) != 1 || len(mains) != 1 {
		t.Fatalf("statuses = %d init / %d main, want 1 / 1", len(inits), len(mains))
	}

	main := mains[0].GetImagePull()
	if main == nil {
		t.Fatal("the main container's status carries no image_pull, so a consumer cannot tell a fetch from a local hit")
	}
	if !main.GetPulled() {
		t.Error("pulled = false for an image the puller reported it fetched")
	}
	if got := main.GetDuration().AsDuration(); got < pullTook {
		t.Errorf("duration = %v, want at least the %v the pull took — the field must measure the image step, not report a zero", got, pullTook)
	}

	init := inits[0].GetImagePull()
	if init == nil {
		t.Fatal("the init container's status carries no image_pull; an init image is pulled exactly like a main's")
	}
	if init.GetPulled() {
		t.Error("pulled = true for an image served from the local index — that is the 'already present on machine' shape")
	}
	if init.GetDuration() == nil {
		t.Error("a local hit reports no duration; it is the time spent proving the image was there, not an absence")
	}
}

// TestVMImagePullFailureIsTypedLikeTheHostSpine pins the vm path to the SAME
// classification the host-process spine applies (pullFailureReason), so the
// provider reads one taxonomy whichever runtime ran the pod. Before this, every
// vm image failure — an unparseable reference, a Never-policy image that is
// absent, an image with no matching platform, an unreadable imagePullSecret —
// arrived as the generic retryable IMAGE_PULL, and the provider retried three
// terminal conditions forever.
//
// A vm image failure still fails the WHOLE pod: createVMPod pulls before it
// builds the machine, and a vm pod has no per-container partial-start surface to
// leave a single container Waiting in (the guest starts every container itself).
// Only the reason is corrected here.
func TestVMImagePullFailureIsTypedLikeTheHostSpine(t *testing.T) {
	const ref = "docker.io/library/app:1"
	cases := []struct {
		name       string
		pullErr    error
		credErr    error
		pullPolicy runtimev1.ImagePullPolicy
		want       runtimev1.FailureReason
	}{{
		name:    "unparseable-reference-is-INVALID_IMAGE_NAME",
		pullErr: fmt.Errorf("parse %q: %w", ref, image.ErrInvalidReference),
		want:    runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME,
	}, {
		// Terminal by construction: the policy forbids the fetch that would fix
		// it, so a retry cannot succeed. This is the kubelet's ErrImageNeverPull.
		name:       "absent-under-Never-is-IMAGE_NEVER_PULL",
		pullErr:    fmt.Errorf("%q: %w", ref, image.ErrImageNotPresent),
		pullPolicy: runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_NEVER,
		want:       runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL,
	}, {
		name:    "no-platform-match-is-IMAGE_NO_PLATFORM_MATCH",
		pullErr: fmt.Errorf("%q: %w", ref, image.ErrNoPlatformMatch),
		want:    runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH,
	}, {
		// Fails BEFORE any registry round trip, which is why no pull error can
		// produce it and the resolver has to be the thing that fails.
		name:    "unresolvable-imagePullSecret-is-IMAGE_PULL_CREDENTIAL",
		credErr: errors.New("secret regcred is not a docker config"),
		want:    runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL,
	}, {
		// The default, restated here so the table says what an unclassified
		// failure is: retryable, never terminal.
		name:    "an-unclassified-failure-stays-IMAGE_PULL",
		pullErr: errors.New("registry is down"),
		want:    runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newImageWorld(map[string]image.ImageRunConfig{ref: {Entrypoint: []string{"/app"}}})
			if tc.pullErr != nil {
				w.failsWith(ref, tc.pullErr)
			}
			deps := Deps{}
			if tc.credErr != nil {
				deps.Credentials = &fakeCredentialResolver{err: tc.credErr}
			}
			rt, vmb := newVMImageRuntimeWith(t, w, deps)
			box := vmBoxWith(rt, "pod-vm-imgfail", nil,
				[]*runtimev1.Container{{Name: "app", Image: ref, ImagePullPolicy: tc.pullPolicy}})
			if tc.credErr != nil {
				box.ImagePullSecrets = []*runtimev1.LocalObjectReference{{Name: "regcred"}}
			}

			_, reason, err := rt.createPod(context.Background(), box)
			if err == nil {
				t.Fatal("a failed image resolution must fail the vm pod")
			}
			if reason != tc.want {
				t.Errorf("reason = %v, want %v — the provider reads this taxonomy to decide whether a retry can help", reason, tc.want)
			}
			if n, _ := vmb.created(); n != 0 {
				t.Errorf("CreateVM called %d times after a failed image resolution; must be 0", n)
			}
		})
	}
}
