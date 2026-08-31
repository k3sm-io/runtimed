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
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/volume"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// vmShareBox builds the standard multi-class vm-routed PodBox the share-plan
// gate drives. Every container names an OCI REFERENCE and carries a command:
// the vm path refuses the absolute-path host-binary convention (a Mach-O cannot
// run in a Linux guest) and merges argv against an image config the harness's
// fake unpacker leaves empty, so both are what it takes to reach the backend.
// The box carries: every volume class (configMap, secret, projected-with-token,
// default-medium emptyDir, Memory-medium emptyDir, PVC), an init container
// mounting the emptyDir, and TWO main containers with ASYMMETRIC mounts (main
// mounts everything; aux mounts nothing).
func vmShareBox(podID string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:           podID,
		Namespace:       "default",
		Name:            "p",
		SandboxProfile:  &runtimev1.SandboxProfile{Backend: runtimev1.SandboxBackend_SANDBOX_BACKEND_VM},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Volumes: []*runtimev1.Volume{
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-cfg"}},
			{Name: "creds", Secret: &runtimev1.SecretVolumeSource{SecretName: "app-secret"}},
			{Name: "token", Projected: &runtimev1.ProjectedVolumeSource{
				Sources: []*runtimev1.VolumeProjection{
					{ServiceAccountToken: &runtimev1.ServiceAccountTokenProjection{Path: "token"}},
				},
			}},
			{Name: "scratch", EmptyDir: &runtimev1.EmptyDirVolumeSource{}},
			{Name: "mem", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory", SizeLimit: "64Mi"}},
			{Name: "data", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "pgdata"}},
		},
		InitContainers: []*runtimev1.Container{{
			Name:         "setup",
			Image:        "docker.io/library/busybox:1",
			Command:      []string{"/bin/true"},
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "scratch", MountPath: "/work"}},
		}},
		Containers: []*runtimev1.Container{
			{
				Name:    "main",
				Image:   "docker.io/library/busybox:1",
				Command: []string{"/bin/sleep", "3600"},
				VolumeMounts: []*runtimev1.VolumeMount{
					// cfg carries a sub_path so the wiring row pins the MAPPER
					// carrying SubPath through to the VMBind (a mapping drop
					// would otherwise survive: field parity checks names, not
					// values).
					{Name: "cfg", MountPath: "/etc/app", SubPath: "app.yaml"},
					{Name: "creds", MountPath: "/etc/creds"},
					{Name: "token", MountPath: "/var/run/secrets/token", ReadOnly: true},
					{Name: "scratch", MountPath: "/scratch"},
					{Name: "mem", MountPath: "/cache"},
					{Name: "data", MountPath: "/var/lib/pg"},
				},
			},
			{Name: "aux", Image: "docker.io/library/busybox:1", Command: []string{"/bin/sleep", "3600"}},
		},
	}
}

// vmPodConfig returns a Config+Deps pair whose image cache is rooted at
// Config.Root — the production New() wiring (runtime.go builds the cache from
// cfg.Root when none is injected). Every test that drives a vm pod to the
// backend needs this alignment: the share planner bounds the pod dir to
// <Config.Root>/pods (mount.ComputeSharePlan via guardShareRoots), so a cache
// rooted anywhere else rejects every vm pod before CreateVM.
//
// Since B142 testDeps no longer splits the two, so this states the requirement
// locally rather than repairing a harness default — a test that names the
// alignment it depends on does not silently lose it to a future harness change.
func vmPodConfig(t *testing.T, d Deps) (Config, Deps) {
	t.Helper()
	root := t.TempDir()
	cache, err := image.NewCache(root)
	if err != nil {
		t.Fatal(err)
	}
	d.Cache = cache
	return Config{Root: root}, d
}

// newVMPlanRuntime builds a Runtime whose vm backend is the available
// fakeVMBackend recorder — the real vm wiring with the boot stub at the end.
func newVMPlanRuntime(t *testing.T) (*Runtime, *fakeVMBackend) {
	t.Helper()
	vmb := &fakeVMBackend{available: true}
	cfg, d := vmPodConfig(t, Deps{VMBackend: vmb})
	rt := newTestRuntimeCfg(t, cfg, d)
	return rt, vmb
}

// mustPlanVM drives box through the REAL createPod vm wiring and returns the
// recorded VMSpec. The lab-gated CreateVM stub then fails the pod — expected
// and orthogonal to the plan assertions; what matters is the ONE recorded
// CreateVM call carrying the plan. The recorder returns the VMSpec by value
// but its slices/maps are shallow, so the recorded plan is treated as
// READ-ONLY by every caller.
func mustPlanVM(t *testing.T, rt *Runtime, vmb *fakeVMBackend, box *runtimev1.PodBox) sandbox.VMSpec {
	t.Helper()
	if _, _, err := rt.createPod(context.Background(), box); err == nil {
		t.Fatal("vm createPod should surface the lab-gated boot error")
	}
	n, spec := vmb.created()
	if n != 1 {
		t.Fatalf("CreateVM called %d times, want 1 (the plan must reach the backend)", n)
	}
	return spec
}

// mustRejectVM drives box through createPod and asserts the share-plan reject
// contract: an error wrapping errInvalidPodBox whose wrap NAMES the share
// planner ("share plan" — createVMPod's wrap text), FailureReason
// INVALID_POD_BOX, and CreateVM NEVER called (reject strictly before the
// backend). The fragment check keeps the helper from becoming vacuously
// satisfiable if another INVALID_POD_BOX exit is later wrapped in the same
// sentinel.
func mustRejectVM(t *testing.T, rt *Runtime, vmb *fakeVMBackend, box *runtimev1.PodBox) {
	t.Helper()
	_, reason, err := rt.createPod(context.Background(), box)
	if err == nil {
		t.Fatal("want a share-plan reject, got nil error")
	}
	if !errors.Is(err, errInvalidPodBox) {
		t.Errorf("reject error = %v, want errInvalidPodBox in the chain", err)
	}
	if !strings.Contains(err.Error(), "share plan") {
		t.Errorf("reject error %q does not come from the share planner (want a %q fragment in the wrap)", err, "share plan")
	}
	if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
		t.Errorf("reason = %v, want INVALID_POD_BOX", reason)
	}
	if n, _ := vmb.created(); n != 0 {
		t.Errorf("CreateVM called %d times on a rejected box; must be 0 (reject before the backend)", n)
	}
}

// findVMShare returns the recorded share with the given tag, failing the test
// when it is absent.
func findVMShare(t *testing.T, spec sandbox.VMSpec, tag string) sandbox.VMShare {
	t.Helper()
	for _, s := range spec.Volumes.Shares {
		if s.Tag == tag {
			return s
		}
	}
	t.Fatalf("share %q not in recorded plan (shares: %+v)", tag, spec.Volumes.Shares)
	return sandbox.VMShare{}
}

// findVMBind returns container's recorded bind for volumeName, failing the
// test when it is absent.
func findVMBind(t *testing.T, spec sandbox.VMSpec, container, volumeName string) sandbox.VMBind {
	t.Helper()
	for _, b := range spec.Volumes.Binds[container] {
		if b.VolumeName == volumeName {
			return b
		}
	}
	t.Fatalf("container %q has no bind for volume %q (binds: %+v)", container, volumeName, spec.Volumes.Binds[container])
	return sandbox.VMBind{}
}

// vmShareRoots returns the recorded share roots in plan order.
func vmShareRoots(spec sandbox.VMSpec) []string {
	roots := make([]string, 0, len(spec.Volumes.Shares))
	for _, s := range spec.Volumes.Shares {
		roots = append(roots, s.Root)
	}
	return roots
}

// underStrict is the test-side separator-aware STRICT containment check:
// equality is false, and /a/bc is not under /a/b.
func underStrict(path, base string) bool {
	return path != base && strings.HasPrefix(path, base+string(filepath.Separator))
}

// TestCreateVMPodVolumeSharePlan is the B106 gate: a vm-RuntimeClass pod's
// PodBox volumes are compiled into a virtiofs share-device plan — pure data,
// threaded through the REAL createPod → createVMPod wiring into the
// sandbox.VMSpec the vm backend receives — with every reject fail-closed
// (INVALID_POD_BOX, before the backend is ever called).
func TestCreateVMPodVolumeSharePlan(t *testing.T) {
	t.Run("production-wiring-vmspec-carries-share-plan", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-wire"))

		// Every expected path is derived from Config.Root + the documented
		// layout literals — never from the same rt.podDir/binder helpers the
		// plan itself consumed, which would compare a derivation to itself.
		podDir := filepath.Join(rt.cfg.Root, "pods", "pod-plan-wire")
		dataDir := filepath.Join(rt.cfg.Root, "storage", "default", "pgdata")
		wantShares := []sandbox.VMShare{
			{Tag: "k3sm.rootfs", Root: filepath.Join(podDir, "rootfs"), Writable: false},
			{Tag: "k3sm.proj", Root: filepath.Join(podDir, "k3sm.proj"), Writable: false},
			{Tag: "k3sm.vols", Root: filepath.Join(podDir, "k3sm.vols"), Writable: true},
			{Tag: "k3sm.pvc0", Root: dataDir, Writable: true},
		}
		if !reflect.DeepEqual(spec.Volumes.Shares, wantShares) {
			t.Errorf("shares = %+v, want %+v", spec.Volumes.Shares, wantShares)
		}

		wantMain := []sandbox.VMBind{
			{VolumeName: "cfg", ShareTag: "k3sm.proj", SourceRel: "cfg", MountPath: "/etc/app", SubPath: "app.yaml"},
			{VolumeName: "creds", ShareTag: "k3sm.proj", SourceRel: "creds", MountPath: "/etc/creds", ReadOnly: true},
			{VolumeName: "token", ShareTag: "k3sm.proj", SourceRel: "token", MountPath: "/var/run/secrets/token", ReadOnly: true},
			{VolumeName: "scratch", ShareTag: "k3sm.vols", SourceRel: "scratch", MountPath: "/scratch"},
			{VolumeName: "data", ShareTag: "k3sm.pvc0", SourceRel: "", MountPath: "/var/lib/pg"},
		}
		if !reflect.DeepEqual(spec.Volumes.Binds["main"], wantMain) {
			t.Errorf("main binds = %+v, want %+v", spec.Volumes.Binds["main"], wantMain)
		}
		wantSetup := []sandbox.VMBind{
			{VolumeName: "scratch", ShareTag: "k3sm.vols", SourceRel: "scratch", MountPath: "/work"},
		}
		if !reflect.DeepEqual(spec.Volumes.Binds["setup"], wantSetup) {
			t.Errorf("setup (init) binds = %+v, want %+v", spec.Volumes.Binds["setup"], wantSetup)
		}
		wantTmpfs := []sandbox.VMTmpfs{{VolumeName: "mem", MountPath: "/cache", SizeLimit: "64Mi"}}
		if !reflect.DeepEqual(spec.Volumes.Tmpfs["main"], wantTmpfs) {
			t.Errorf("main tmpfs = %+v, want %+v", spec.Volumes.Tmpfs["main"], wantTmpfs)
		}
	})

	t.Run("share-roots-inside-owning-pod-dir", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-dir"))

		// Containment is asserted against the CONFIG-derived pod tree
		// (<Config.Root>/pods/<podID>) — never against the same rt.podDir(...)
		// the plan was built from, which the three pod-dir roots satisfy BY
		// CONSTRUCTION (each is Join(podDir, <literal>)) for any podDir at all.
		podsRoot := filepath.Join(rt.cfg.Root, "pods")
		wantPodDir := filepath.Join(podsRoot, "pod-plan-dir")

		// Non-vacuity anchor: the three pod-dir shares must exist at all.
		for _, tag := range []string{"k3sm.rootfs", "k3sm.proj", "k3sm.vols"} {
			s := findVMShare(t, spec, tag)
			if !underStrict(s.Root, wantPodDir) {
				t.Errorf("share %s root %q is not strictly inside the config-derived pod dir %q", tag, s.Root, wantPodDir)
			}
			if !underStrict(s.Root, podsRoot) {
				t.Errorf("share %s root %q is not strictly inside the runtime pods root %q", tag, s.Root, podsRoot)
			}
		}
	})

	// B140 INVERTS the second half of this case. It used to assert that a hostile
	// box.rootfs_path was merely INERT for share roots — the plan ignored it, but
	// the pod still reached the vm backend carrying that path as
	// VMSpec.RootfsPath. It is now REFUSED outright, strictly before the backend,
	// because rootfs_path must be byte-equal to the runtime's derived pod data
	// volume. The share-root half is unchanged and still meaningful: it pins that
	// the planner derives roots locally rather than from the box.
	t.Run("box-supplied-rootfs-path-never-moves-a-share-root", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)

		clean := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-hostile"))
		cleanRoots := vmShareRoots(clean)
		if len(cleanRoots) == 0 {
			t.Fatal("unhostile run recorded no shares (vacuous comparison)")
		}
		podDir, podDirErr := rt.podDir("pod-plan-hostile")
		if podDirErr != nil {
			t.Fatalf("podDir: %v", podDirErr)
		}
		if got, want := findVMShare(t, clean, "k3sm.rootfs").Root, filepath.Join(podDir, "rootfs"); got != want {
			t.Errorf("rootfs share root = %q, want the podDir-derived %q", got, want)
		}

		// The DERIVED spelling is still accepted, so the guard is byte-equality and
		// not "any rootfs_path is fatal". A failed vm create registers nothing, so
		// the same pod id re-runs on the same runtime; the recorder count is
		// cumulative, hence want 2 here.
		derivedBox := vmShareBox("pod-plan-hostile")
		derivedBox.RootfsPath = filepath.Join(podDir, "rootfs")
		if _, _, err := rt.createPod(context.Background(), derivedBox); err == nil {
			t.Fatal("vm createPod should surface the lab-gated boot error")
		}
		n, derived := vmb.created()
		if n != 2 {
			t.Fatalf("CreateVM called %d times, want 2 (the derived-spelling run must still reach the backend)", n)
		}
		if got := vmShareRoots(derived); !reflect.DeepEqual(got, cleanRoots) {
			t.Errorf("derived rootfs_path moved share roots:\n  derived: %v\n  clean:   %v", got, cleanRoots)
		}
		if got, want := derived.RootfsPath, filepath.Join(podDir, "rootfs"); got != want {
			t.Errorf("VMSpec.RootfsPath = %q, want the derived %q", got, want)
		}

		// Hostile box.rootfs_path (the runtime work root itself): REFUSED before
		// the backend — the vm path must never carry an uncontained host path into
		// VMSpec.RootfsPath.
		hostileBox := vmShareBox("pod-plan-hostile")
		hostileBox.RootfsPath = rt.cfg.Root
		_, reason, err := rt.createPod(context.Background(), hostileBox)
		if err == nil {
			t.Fatal("a hostile rootfs_path must be refused, got nil error")
		}
		if !errors.Is(err, errUncontainedRootfs) {
			t.Errorf("reject error = %v, want errUncontainedRootfs in the chain", err)
		}
		if reason != runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX {
			t.Errorf("reason = %v, want INVALID_POD_BOX", reason)
		}
		if n2, _ := vmb.created(); n2 != 2 {
			t.Errorf("CreateVM called %d times, want a still-2 count (the hostile run must NOT reach the backend)", n2)
		}
	})

	t.Run("share-roots-pairwise-disjoint-vols-not-ancestor-of-proj", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-disjoint"))
		podDir, podDirErr := rt.podDir("pod-plan-disjoint")
		if podDirErr != nil {
			t.Fatalf("podDir: %v", podDirErr)
		}

		// The sibling-prefix regression probe: the proj and vols roots are the
		// EXACT expected siblings (a proj dir renamed to share the vols name as
		// a plain prefix, e.g. "k3sm.volsproj", must fail here).
		if got, want := findVMShare(t, spec, "k3sm.proj").Root, filepath.Join(podDir, "k3sm.proj"); got != want {
			t.Errorf("proj share root = %q, want %q", got, want)
		}
		if got, want := findVMShare(t, spec, "k3sm.vols").Root, filepath.Join(podDir, "k3sm.vols"); got != want {
			t.Errorf("vols share root = %q, want %q", got, want)
		}

		roots := vmShareRoots(spec)
		if len(roots) < 2 {
			t.Fatalf("want multiple shares for the pairwise check, got %v", roots)
		}
		for i := 0; i < len(roots); i++ {
			for j := i + 1; j < len(roots); j++ {
				if roots[i] == roots[j] || underStrict(roots[i], roots[j]) || underStrict(roots[j], roots[i]) {
					t.Errorf("share roots %q and %q are nested/equal; roots must be pairwise disjoint", roots[i], roots[j])
				}
			}
		}
	})

	t.Run("proj-and-rootfs-readonly-in-plan", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-ro"))
		if s := findVMShare(t, spec, "k3sm.rootfs"); s.Writable {
			t.Error("rootfs share is writable in the plan; must be read-only")
		}
		if s := findVMShare(t, spec, "k3sm.proj"); s.Writable {
			t.Error("proj share is writable in the plan; must be read-only")
		}
	})

	t.Run("container-binds-only-declared-volume-mounts", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-asym"))

		// Non-vacuity anchor: main HAS its own binds (and the init container
		// setup has its one), so the aux omission below means something.
		findVMBind(t, spec, "main", "cfg")
		findVMBind(t, spec, "setup", "scratch")
		if got := spec.Volumes.Binds["aux"]; len(got) != 0 {
			t.Errorf("aux declares no volumeMounts but got binds %+v (a pod-wide union leak)", got)
		}
		if got := spec.Volumes.Tmpfs["aux"]; len(got) != 0 {
			t.Errorf("aux declares no volumeMounts but got tmpfs %+v (a pod-wide union leak)", got)
		}
		// setup mounts ONLY scratch — main's other volumes must not leak in.
		if got := spec.Volumes.Binds["setup"]; len(got) != 1 {
			t.Errorf("setup binds = %+v, want exactly its one declared mount", got)
		}
	})

	t.Run("credential-materializations-never-on-writable-share", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		spec := mustPlanVM(t, rt, vmb, vmShareBox("pod-plan-cred"))

		for _, cred := range []string{"creds", "token"} {
			b := findVMBind(t, spec, "main", cred)
			if !b.ReadOnly {
				t.Errorf("credential volume %q bind is not read-only", cred)
			}
			if s := findVMShare(t, spec, b.ShareTag); s.Writable {
				t.Errorf("credential volume %q landed on writable share %q", cred, b.ShareTag)
			}
		}
	})

	t.Run("memory-emptydir-is-guest-tmpfs-not-a-virtiofs-share", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		box := vmShareBox("pod-plan-mem")
		// Narrow to the Memory emptyDir alone: with no default-medium emptyDir
		// declared, no vols share may be emitted either. The mount is
		// read_only + sub_path-narrowed: BOTH must ride the VMTmpfs verbatim
		// (the native path honors read_only on a Memory emptyDir and upstream
		// permits sub_path on one — dropping either would be a silent vm-path
		// narrowing).
		box.Volumes = []*runtimev1.Volume{
			{Name: "mem", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "Memory", SizeLimit: "64Mi"}},
		}
		box.InitContainers = nil
		box.Containers = []*runtimev1.Container{{
			Name:         "main",
			Image:        "docker.io/library/busybox:1",
			Command:      []string{"/bin/sleep", "3600"},
			VolumeMounts: []*runtimev1.VolumeMount{{Name: "mem", MountPath: "/cache", ReadOnly: true, SubPath: "warm"}},
		}}
		spec := mustPlanVM(t, rt, vmb, box)

		wantTmpfs := []sandbox.VMTmpfs{{VolumeName: "mem", MountPath: "/cache", SubPath: "warm", SizeLimit: "64Mi", ReadOnly: true}}
		if !reflect.DeepEqual(spec.Volumes.Tmpfs["main"], wantTmpfs) {
			t.Errorf("main tmpfs = %+v, want %+v (SizeLimit/SubPath verbatim, ReadOnly honored)", spec.Volumes.Tmpfs["main"], wantTmpfs)
		}
		for _, b := range spec.Volumes.Binds["main"] {
			if b.VolumeName == "mem" {
				t.Errorf("Memory emptyDir got a virtiofs bind %+v; must be guest tmpfs only", b)
			}
		}
		for _, s := range spec.Volumes.Shares {
			if s.Tag == "k3sm.vols" {
				t.Errorf("vols share %+v emitted with no default-medium emptyDir declared", s)
			}
		}
	})

	t.Run("unknown-emptydir-medium-rejected", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		box := vmShareBox("pod-plan-medium")
		box.Volumes = append(box.Volumes,
			&runtimev1.Volume{Name: "huge", EmptyDir: &runtimev1.EmptyDirVolumeSource{Medium: "HugePages"}})
		box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts,
			&runtimev1.VolumeMount{Name: "huge", MountPath: "/hugepages"})
		mustRejectVM(t, rt, vmb, box)
	})

	t.Run("unknown-volume-source-rejected-fail-closed", func(t *testing.T) {
		t.Run("no-source-set", func(t *testing.T) {
			rt, vmb := newVMPlanRuntime(t)
			box := vmShareBox("pod-plan-nosrc")
			box.Volumes = append(box.Volumes, &runtimev1.Volume{Name: "mystery"})
			box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts,
				&runtimev1.VolumeMount{Name: "mystery", MountPath: "/mystery"})
			mustRejectVM(t, rt, vmb, box)
		})
		t.Run("two-sources-set", func(t *testing.T) {
			rt, vmb := newVMPlanRuntime(t)
			box := vmShareBox("pod-plan-twosrc")
			box.Volumes = append(box.Volumes, &runtimev1.Volume{
				Name:      "both",
				ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-cfg"},
				EmptyDir:  &runtimev1.EmptyDirVolumeSource{},
			})
			box.Containers[0].VolumeMounts = append(box.Containers[0].VolumeMounts,
				&runtimev1.VolumeMount{Name: "both", MountPath: "/both"})
			mustRejectVM(t, rt, vmb, box)
		})
		t.Run("declared-but-unmounted-no-source", func(t *testing.T) {
			rt, vmb := newVMPlanRuntime(t)
			box := vmShareBox("pod-plan-unmounted")
			// Declared in the pod's volume set, mounted by NO container: the
			// arity check runs over the DECLARATION set, so this still rejects.
			box.Volumes = append(box.Volumes, &runtimev1.Volume{Name: "mystery"})
			mustRejectVM(t, rt, vmb, box)
		})
	})

	t.Run("pvc-crafted-claim-rejected-before-backend", func(t *testing.T) {
		// The fix-round probe case, bound into the gate: a lateral
		// "../<other-ns>/…" claim stays INSIDE the storage root (so the
		// escapes-base guard alone never fires) but addresses a sibling
		// namespace's tree — the single-path-component rule must reject it
		// before the backend ever sees a plan.
		rt, vmb := newVMPlanRuntime(t)
		box := vmShareBox("pod-plan-crafted")
		box.Volumes = append(box.Volumes, &runtimev1.Volume{
			Name:                  "lateral",
			PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "../tenant-b/pgdata"},
		})
		mustRejectVM(t, rt, vmb, box)
	})

	t.Run("pvc-share-root-equality-derived-from-datadir", func(t *testing.T) {
		rt, vmb := newVMPlanRuntime(t)
		box := vmShareBox("pod-plan-pvc")
		// Two PVCs declared in REVERSE name order: tags index the SORTED
		// volume-name order. data-b is a read_only source.
		box.Volumes = []*runtimev1.Volume{
			{Name: "data-b", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-b", ReadOnly: true}},
			{Name: "data-a", PersistentVolumeClaim: &runtimev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim-a"}},
		}
		box.InitContainers = nil
		box.Containers = []*runtimev1.Container{{
			Name:    "main",
			Image:   "docker.io/library/busybox:1",
			Command: []string{"/bin/sleep", "3600"},
			VolumeMounts: []*runtimev1.VolumeMount{
				{Name: "data-a", MountPath: "/a"},
				{Name: "data-b", MountPath: "/b"},
			},
		}}
		spec := mustPlanVM(t, rt, vmb, box)

		dirA, err := rt.binder.Class().DataDir("default", "claim-a")
		if err != nil {
			t.Fatal(err)
		}
		dirB, err := rt.binder.Class().DataDir("default", "claim-b")
		if err != nil {
			t.Fatal(err)
		}
		a := findVMShare(t, spec, "k3sm.pvc0")
		if a.Root != dirA {
			t.Errorf("pvc0 root = %q, want the exact DataDir %q", a.Root, dirA)
		}
		if !a.Writable {
			t.Error("pvc0 (rw source) must be Writable")
		}
		b := findVMShare(t, spec, "k3sm.pvc1")
		if b.Root != dirB {
			t.Errorf("pvc1 root = %q, want the exact DataDir %q", b.Root, dirB)
		}
		if b.Writable {
			t.Error("pvc1 (read_only source) must not be Writable")
		}
		if bb := findVMBind(t, spec, "main", "data-b"); !bb.ReadOnly {
			t.Error("read_only PVC source must force a read-only bind")
		}
		if ba := findVMBind(t, spec, "main", "data-a"); ba.ReadOnly {
			t.Error("rw PVC bind unexpectedly read-only")
		}
	})

	t.Run("no-share-root-under-workdir-run", func(t *testing.T) {
		// A binder class mis-rooted INSIDE <workRoot>/run — the daemon socket
		// tree (netd.sock / runtimed.sock / run/keys) — must be refused: no
		// share root may ever land in that tree (R7), even one that satisfies
		// every other derivation rule.
		vmb := &fakeVMBackend{available: true}
		cfg, d := vmPodConfig(t, Deps{VMBackend: vmb})
		class := storagev1.LocalPathClass{BasePath: filepath.Join(cfg.Root, "run", "storage")}
		d.Binder = volume.NewBinder(class, nil, nil, nil)
		rt := newTestRuntimeCfg(t, cfg, d)

		box := vmShareBox("pod-plan-rundir")
		mustRejectVM(t, rt, vmb, box)
	})
}

// TestVMVolumePlanFieldParity asserts the pkg/mount plan types and the
// sandbox DTO types expose IDENTICAL field-name sets, pairwise. vmVolumePlan
// (pod.go) maps the plan onto the DTO value for value; a field added to a
// planner type but not the DTO (or vice versa) would otherwise ship silently
// unmapped — this reds the suite instead, naming the divergence.
func TestVMVolumePlanFieldParity(t *testing.T) {
	fieldNames := func(v any) []string {
		typ := reflect.TypeOf(v)
		names := make([]string, 0, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			names = append(names, typ.Field(i).Name)
		}
		sort.Strings(names)
		return names
	}
	cases := []struct {
		name string
		mnt  any
		dto  any
	}{
		{"plan", mount.SharePlan{}, sandbox.VMVolumePlan{}},
		{"share", mount.Share{}, sandbox.VMShare{}},
		{"bind", mount.Bind{}, sandbox.VMBind{}},
		{"tmpfs", mount.Tmpfs{}, sandbox.VMTmpfs{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, d := fieldNames(tc.mnt), fieldNames(tc.dto)
			if !reflect.DeepEqual(m, d) {
				t.Errorf("field sets diverge (a new planner field must be mirrored in the DTO and mapped in vmVolumePlan):\n  %T: %v\n  %T: %v",
					tc.mnt, m, tc.dto, d)
			}
		})
	}
}
