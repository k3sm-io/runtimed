package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- fakes ---------------------------------------------------------------

// fakeBackend is a sandbox.Backend whose availability is settable; WrapCommand
// returns a trivial wrapped argv with a no-op cleanup.
type fakeBackend struct{ available bool }

func (f fakeBackend) Available() bool { return f.available }
func (f fakeBackend) Name() string    { return "fake" }
func (f fakeBackend) WrapCommand(_ context.Context, profile string, argv []string, cred supervisor.Credential) (string, []string, func() error, error) {
	if err := sandbox.Validate(profile); err != nil {
		return "", nil, nil, err
	}
	// Mirror the production shim argv shape: [shim, <uid>, <gid>, <groups>, profile, argv...].
	wrapped := append([]string{"/fake/shim"}, cred.ShimArgs()...)
	wrapped = append(wrapped, "/tmp/profile.sb")
	wrapped = append(wrapped, argv...)
	return "/fake/shim", wrapped, func() error { return nil }, nil
}

// fakeSpawner returns sequential pids and records argv/env.
type fakeSpawner struct {
	mu    sync.Mutex
	next  int
	specs []supervisor.SpawnSpec
	err   error
}

func (f *fakeSpawner) Spawn(_ context.Context, spec supervisor.SpawnSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.specs = append(f.specs, spec)
	f.next++
	return 1000 + f.next, nil
}

func (f *fakeSpawner) lastEnv() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return nil
	}
	return f.specs[len(f.specs)-1].Env
}

// blockingWaiter blocks until released, so created pods stay "running". On
// release it reports code/sig (sig defaults to 0; the OOM test sets sig=9, code=137
// to simulate a SIGKILLed container).
type blockingWaiter struct {
	mu       sync.Mutex
	released map[int]chan struct{}
	code     int
	sig      int
}

func newBlockingWaiter() *blockingWaiter {
	return &blockingWaiter{released: make(map[int]chan struct{})}
}

func (w *blockingWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	w.mu.Lock()
	ch, ok := w.released[pid]
	if !ok {
		ch = make(chan struct{})
		w.released[pid] = ch
	}
	code, sig := w.code, w.sig
	w.mu.Unlock()
	select {
	case <-ch:
		return code, sig, nil
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	}
}

func (w *blockingWaiter) release(pid int) {
	w.mu.Lock()
	ch, ok := w.released[pid]
	if !ok {
		ch = make(chan struct{})
		w.released[pid] = ch
	}
	w.mu.Unlock()
	close(ch)
}

// instantWaiter returns immediately (used for init containers).
type instantWaiter struct{ code int }

func (w instantWaiter) WaitExit(context.Context, int) (int, int, error) { return w.code, 0, nil }

// fakePuller never touches a registry. It records the last credential it received
// (M2.6) so a test can assert the imagePullSecret reaches the pull client.
type fakePuller struct {
	err error

	mu       sync.Mutex
	lastCred *image.RegistryCredential
	lastRef  string
}

func (f *fakePuller) Pull(_ context.Context, ref string, cred *image.RegistryCredential) (*image.PullResult, error) {
	f.mu.Lock()
	f.lastRef = ref
	f.lastCred = cred
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &image.PullResult{Manifest: &runtimev1.ImageManifest{}, CacheHit: true}, nil
}

func (f *fakePuller) credential() *image.RegistryCredential {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCred
}

// fakeSigner records sign calls and applies a policy-gate decision.
type fakeSigner struct {
	mu        sync.Mutex
	signed    []string
	checkErr  error
	signError error
}

func (f *fakeSigner) Sign(_ context.Context, path string) error {
	f.mu.Lock()
	f.signed = append(f.signed, path)
	f.mu.Unlock()
	return f.signError
}

func (f *fakeSigner) Check(_ context.Context, policy runtimev1.SignaturePolicy, path string) error {
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		return image.ErrPolicyUnspecified
	}
	return f.checkErr
}

// newTestRuntime builds a Runtime with all fakes; waiter/spawner/backend default
// to "available + blocking" unless overridden.
func newTestRuntime(t *testing.T, d Deps) *Runtime {
	t.Helper()
	cache, err := image.NewCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if d.Cache == nil {
		d.Cache = cache
	}
	if d.Backend == nil {
		d.Backend = fakeBackend{available: true}
	}
	if d.Spawner == nil {
		d.Spawner = &fakeSpawner{}
	}
	if d.Waiter == nil {
		d.Waiter = newBlockingWaiter()
	}
	if d.Puller == nil {
		d.Puller = &fakePuller{}
	}
	if d.Signer == nil {
		d.Signer = &fakeSigner{}
	}
	if d.Network == nil {
		d.Network = supervisor.NodeNetwork{IP: "10.1.2.3"}
	}
	rt, err := New(Config{Root: t.TempDir()}, d)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// hostBinBox builds a minimal valid PodBox running a host-binary container.
func hostBinBox(podID string) *runtimev1.PodBox {
	return &runtimev1.PodBox{
		PodId:     podID,
		Namespace: "default",
		Name:      "p",
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: "/var/lib/k3sm/pods/" + podID + "/rootfs",
		},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Containers: []*runtimev1.Container{
			{Name: "main", Image: "/bin/sleep", Args: nil, Command: nil},
		},
	}
}

// --- contract assertion --------------------------------------------------

// TestRuntimeImplementsServer is the compile-time + runtime contract assertion.
func TestRuntimeImplementsServer(t *testing.T) {
	var _ runtimev1.RuntimeServer = (*Runtime)(nil)
	rt := newTestRuntime(t, Deps{})
	var _ runtimev1.RuntimeServer = rt
}

// TestCreatePodLifecycle covers CreatePod → GetPodStatus → DeletePod, including
// idempotent re-create and DYLD env pass-through (the cross-repo enabler).
func TestCreatePodLifecycle(t *testing.T) {
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})

	box := hostBinBox("pod-1")
	box.Annotations = map[string]string{dyldInsertAnnotation: "/opt/k3sm/libdnsshim.dylib"}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod returned error: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
	if resp.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("phase = %v, want RUNNING", resp.GetStatus().GetPhase())
	}
	if resp.GetStatus().GetPodIp() != "10.1.2.3" {
		t.Errorf("pod IP = %q, want 10.1.2.3", resp.GetStatus().GetPodIp())
	}

	// DYLD_INSERT_LIBRARIES must be in the spawned env.
	foundDyld := false
	for _, e := range sp.lastEnv() {
		if e == dyldInsertEnv+"=/opt/k3sm/libdnsshim.dylib" {
			foundDyld = true
		}
	}
	if !foundDyld {
		t.Errorf("DYLD_INSERT_LIBRARIES not carried into spawn env: %v", sp.lastEnv())
	}

	// Idempotent re-create is a no-op returning current status.
	resp2, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil || resp2.GetError() != nil {
		t.Fatalf("idempotent CreatePod failed: %v / %v", err, resp2.GetError())
	}

	gs, err := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-1"})
	if err != nil {
		t.Fatal(err)
	}
	if gs.GetStatus().GetPhase() != runtimev1.PodPhase_POD_PHASE_RUNNING {
		t.Errorf("GetPodStatus phase = %v", gs.GetStatus().GetPhase())
	}

	// Delete: releases the pod (idempotent on unknown).
	w.release(1001)
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-1"}); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-1"}); err != nil {
		t.Fatalf("idempotent DeletePod (unknown) failed: %v", err)
	}
}

// TestCreatePodFailClosed asserts the runtime REFUSES to start a pod when the
// sandbox backend is unavailable (never runs unconfined) — the fail-closed
// requirement.
func TestCreatePodFailClosed(t *testing.T) {
	rt := newTestRuntime(t, Deps{Backend: fakeBackend{available: false}})
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-x")})
	if err != nil {
		t.Fatalf("CreatePod transport error: %v", err)
	}
	if resp.GetError() == nil {
		t.Fatal("CreatePod should fail closed when backend unavailable")
	}
	if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP {
		t.Errorf("failure reason = %v, want SANDBOX_SETUP", resp.GetFailureReason())
	}
}

// TestCreatePodValidation covers PodBox validation incl. fail-closed signature
// policy.
func TestCreatePodValidation(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	cases := []struct {
		name       string
		mutate     func(*runtimev1.PodBox)
		wantReason runtimev1.FailureReason
	}{
		{"no-pod-id", func(b *runtimev1.PodBox) { b.PodId = "" }, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX},
		{"no-sandbox-profile", func(b *runtimev1.PodBox) { b.SandboxProfile = nil }, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX},
		{"no-containers", func(b *runtimev1.PodBox) { b.Containers = nil }, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX},
		{"sig-unspecified", func(b *runtimev1.PodBox) {
			b.SignaturePolicy = runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED
		}, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			box := hostBinBox("pod-v")
			tc.mutate(box)
			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetError() == nil {
				t.Fatal("want validation error")
			}
			if resp.GetFailureReason() != tc.wantReason {
				t.Errorf("reason = %v, want %v", resp.GetFailureReason(), tc.wantReason)
			}
		})
	}
}

// TestCreatePodSignatureRejected drives the SignaturePolicy gate to a rejection
// through the runtime spine (before exec).
func TestCreatePodSignatureRejected(t *testing.T) {
	signer := &fakeSigner{checkErr: image.ErrSignatureRejected}
	rt := newTestRuntime(t, Deps{Signer: signer})
	box := hostBinBox("pod-sig")
	box.SignaturePolicy = runtimev1.SignaturePolicy_SIGNATURE_POLICY_REQUIRE_SIGNED
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED {
		t.Fatalf("reason = %v, want SIGNATURE_REJECTED", resp.GetFailureReason())
	}
}

// TestInitContainerSequencing runs an init container to completion before the
// main container starts.
func TestInitContainerSequencing(t *testing.T) {
	sp := &fakeSpawner{}
	// init waiter must return instantly; main must block. Use a waiter that
	// returns instantly for the first pid and blocks the rest.
	w := &seqWaiter{block: newBlockingWaiter()}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w})

	box := hostBinBox("pod-init")
	box.InitContainers = []*runtimev1.Container{{Name: "init", Image: "/bin/true"}}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod: %v", resp.GetError())
	}
	// init + main spawned => 2 specs.
	sp.mu.Lock()
	n := len(sp.specs)
	sp.mu.Unlock()
	if n != 2 {
		t.Errorf("spawned %d processes, want 2 (init + main)", n)
	}
}

// seqWaiter returns instantly for the first pid (init), blocks subsequent (main).
type seqWaiter struct {
	mu    sync.Mutex
	first bool
	block *blockingWaiter
}

func (w *seqWaiter) WaitExit(ctx context.Context, pid int) (int, int, error) {
	w.mu.Lock()
	if !w.first {
		w.first = true
		w.mu.Unlock()
		return 0, 0, nil // init exits cleanly
	}
	w.mu.Unlock()
	return w.block.WaitExit(ctx, pid)
}

// TestWatchPodStatus checks the watch stream emits the current snapshot on
// subscribe and a subsequent transition.
func TestWatchPodStatus(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-w")}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeWatchStream(ctx)
	go func() { _ = rt.WatchPodStatus(&runtimev1.WatchPodStatusRequest{PodId: "pod-w"}, stream) }()

	// Expect the initial snapshot.
	ev := stream.recv(t, 2*time.Second)
	if ev.GetStatus().GetPodId() != "pod-w" {
		t.Fatalf("first event pod = %q", ev.GetStatus().GetPodId())
	}

	// Trigger a transition (delete publishes a DELETED event).
	w.release(1001)
	if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-w"}); err != nil {
		t.Fatal(err)
	}
	gotDeleted := false
	for i := 0; i < 4; i++ {
		ev := stream.recv(t, 2*time.Second)
		if ev.GetType() == runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED {
			gotDeleted = true
			break
		}
	}
	if !gotDeleted {
		t.Error("did not observe a DELETED event after DeletePod")
	}
}

// TestGetLogs returns buffered container output.
func TestGetLogs(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox("pod-l")}); err != nil {
		t.Fatal(err)
	}
	// Inject a log line directly into the container buffer.
	rt.mu.Lock()
	p := rt.pods["pod-l"]
	rt.mu.Unlock()
	p.mu.Lock()
	p.containers[0].logs.write([]byte("log-line-1"))
	p.mu.Unlock()

	stream := newFakeLogStream(context.Background())
	if err := rt.GetLogs(&runtimev1.GetLogsRequest{PodId: "pod-l", Container: "main"}, stream); err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	if len(stream.entries) != 1 || string(stream.entries[0].GetLine()) != "log-line-1" {
		t.Fatalf("logs = %v", stream.entries)
	}
}

// TestUpdatePod allows annotation changes, rejects spec changes as NOT_UPDATABLE.
func TestUpdatePod(t *testing.T) {
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Waiter: w})
	box := hostBinBox("pod-u")
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box}); err != nil {
		t.Fatal(err)
	}

	t.Run("annotation-ok", func(t *testing.T) {
		nb := hostBinBox("pod-u")
		nb.Annotations = map[string]string{"k3sm.io/foo": "bar"}
		resp, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: nb})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetError() != nil {
			t.Fatalf("update annotation rejected: %v", resp.GetError())
		}
	})

	t.Run("spec-change-not-updatable", func(t *testing.T) {
		nb := hostBinBox("pod-u")
		nb.Uid = 501
		resp, err := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: nb})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE {
			t.Errorf("reason = %v, want NOT_UPDATABLE", resp.GetFailureReason())
		}
	})
}

// TestUnknownPodErrors covers NOT_FOUND on GetPodStatus/UpdatePod/GetLogs.
func TestUnknownPodErrors(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "nope"})
	if gs.GetError() == nil {
		t.Error("GetPodStatus(unknown) should set error")
	}
	up, _ := rt.UpdatePod(context.Background(), &runtimev1.UpdatePodRequest{Pod: &runtimev1.PodBox{PodId: "nope"}})
	if up.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_NOT_FOUND {
		t.Errorf("UpdatePod(unknown) reason = %v", up.GetFailureReason())
	}
}

// TestStreamingUnimplemented confirms Exec/Attach/PortForward report Unimplemented
// in M1.
func TestStreamingUnimplemented(t *testing.T) {
	rt := newTestRuntime(t, Deps{})
	if err := rt.Exec(nil); err == nil {
		t.Error("Exec should be Unimplemented in M1")
	}
	if err := rt.Attach(nil); err == nil {
		t.Error("Attach should be Unimplemented in M1")
	}
	if err := rt.PortForward(nil); err == nil {
		t.Error("PortForward should be Unimplemented in M1")
	}
}

// TestGetRuntimeInfo reflects backend health.
func TestGetRuntimeInfo(t *testing.T) {
	cases := []struct {
		name    string
		backend sandbox.Backend
		healthy bool
	}{
		{"available", fakeBackend{available: true}, true},
		{"unavailable", fakeBackend{available: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{Backend: tc.backend})
			info, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if info.GetHealthy() != tc.healthy {
				t.Errorf("healthy = %v, want %v", info.GetHealthy(), tc.healthy)
			}
			if info.GetRuntimeName() != RuntimeName {
				t.Errorf("runtime name = %q", info.GetRuntimeName())
			}
		})
	}
}

// fakeResolver serves canned ConfigMap/Secret data + a token for the volume
// materializer (the provider's apiserver-backed Resolver stands in here).
type fakeResolver struct{}

func (fakeResolver) ConfigMap(_ context.Context, _, name string) (map[string][]byte, error) {
	return map[string][]byte{"app.conf": []byte("k=v")}, nil
}
func (fakeResolver) Secret(_ context.Context, _, name string) (map[string][]byte, error) {
	return map[string][]byte{"id_rsa": []byte("PRIVATE")}, nil
}
func (fakeResolver) ServiceAccountToken(_ context.Context, _, _ string, _ int64) (string, error) {
	return "TOKEN", nil
}

// TestCreatePodMaterializesVolumesAndDrops ties M2.2 + M2.3 together through the
// CreatePod spine: a pod with a configMap + secret volume and a securityContext
// drop (1) materializes the volume files into the pod data volume, (2) gets the
// secret's read-only sub-scope into the generated SBPL, and (3) carries the
// run-as uid/gid through WrapCommand into the spawned exec-shim argv.
func TestCreatePodMaterializesVolumesAndDrops(t *testing.T) {
	dataVol := t.TempDir()
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, Resolver: fakeResolver{}})

	box := &runtimev1.PodBox{
		PodId:      "pod-vol",
		Namespace:  "default",
		Name:       "demo",
		RootfsPath: dataVol,
		// SBPL data volume == on-disk rootfs so the credential paths validate.
		SandboxProfile:  &runtimev1.SandboxProfile{DataVolumePath: dataVol},
		SignaturePolicy: runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK,
		Volumes: []*runtimev1.Volume{
			{Name: "cfg", ConfigMap: &runtimev1.ConfigMapVolumeSource{Name: "app-config"}},
			{Name: "sec", Secret: &runtimev1.SecretVolumeSource{SecretName: "git-key"}},
		},
		Containers: []*runtimev1.Container{{
			Name:  "main",
			Image: "/bin/sleep",
			VolumeMounts: []*runtimev1.VolumeMount{
				{Name: "cfg", MountPath: "/etc/cfg"},
				{Name: "sec", MountPath: "/etc/sec", ReadOnly: true},
			},
			SecurityContext: &runtimev1.SecurityContext{RunAsUser: 501, RunAsGroup: 20},
		}},
	}
	// fsGroup chown is exercised only when the test gid is a real (>0) group.
	if gid := os.Getgid(); gid > 0 {
		box.PodSecurityContext = &runtimev1.PodSecurityContext{FsGroup: int64(gid)}
	}

	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}

	// (1) materialized files landed inside the pod data volume.
	if got, _ := os.ReadFile(filepath.Join(dataVol, "etc/cfg/app.conf")); string(got) != "k=v" {
		t.Errorf("configMap not materialized: %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(dataVol, "etc/sec/id_rsa")); string(got) != "PRIVATE" {
		t.Errorf("secret not materialized: %q", got)
	}

	// (2) the generated SBPL carries the secret's read-only sub-scope.
	rt.mu.Lock()
	profile := rt.pods["pod-vol"].profile
	rt.mu.Unlock()
	secPath := filepath.Join(dataVol, "etc/sec")
	if !strings.Contains(profile, "(deny file-write*\n  (subpath \""+secPath+"\")") {
		t.Errorf("SBPL missing secret read-only sub-scope for %s:\n%s", secPath, profile)
	}

	// (3) the run-as identity reached the spawned exec-shim argv (fakeBackend
	// mirrors the shim arg shape [shim, uid, gid, groups, profile, argv...]).
	argv := sp.specs[len(sp.specs)-1].Argv
	if len(argv) < 4 || argv[1] != "501" || argv[2] != "20" {
		t.Errorf("drop credential not in spawn argv: %v", argv)
	}

	// (4) the status mirrors the volume mounts + effective user.
	gs, _ := rt.GetPodStatus(context.Background(), &runtimev1.GetPodStatusRequest{PodId: "pod-vol"})
	cs := gs.GetStatus().GetContainerStatuses()
	if len(cs) != 1 || len(cs[0].GetVolumeMounts()) != 2 {
		t.Fatalf("container status volume_mounts mirror missing: %+v", cs)
	}
	if u := cs[0].GetUser().GetLinux(); u.GetUid() != 501 || u.GetGid() != 20 {
		t.Errorf("container status user mirror = %+v, want uid 501 gid 20", u)
	}

	w.release(1001)
}

// guard against accidentally importing a real registry in unit tests.
var _ = errors.New
