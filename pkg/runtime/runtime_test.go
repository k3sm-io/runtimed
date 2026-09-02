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
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
func (f fakeBackend) WrapCommand(_ context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	if err := sandbox.Validate(profile); err != nil {
		return "", nil, nil, err
	}
	// Mirror the production shim argv shape:
	// [shim, <uid>, <gid>, <groups>, <rlimits>, <qos>, profile, argv...].
	wrapped := append([]string{"/fake/shim"}, spec.Cred.ShimArgs()...)
	wrapped = append(wrapped, supervisor.EncodeRlimits(spec.Rlimits), supervisor.EncodeQoS(spec.BgQoS))
	wrapped = append(wrapped, "/tmp/profile.sb")
	wrapped = append(wrapped, argv...)
	return "/fake/shim", wrapped, func() error { return nil }, nil
}

// recordingBackend is a sandbox.Backend that records whether WrapCommand was
// called, so a test can assert the VM-routed path never touches the host-process
// exec-shim seam. It otherwise behaves like fakeBackend.
type recordingBackend struct {
	available bool
	mu        sync.Mutex
	wrapped   int
	specs     []supervisor.LaunchSpec
}

func (b *recordingBackend) Available() bool { return b.available }
func (b *recordingBackend) Name() string    { return "recording" }
func (b *recordingBackend) WrapCommand(ctx context.Context, profile string, argv []string, spec supervisor.LaunchSpec) (string, []string, func() error, error) {
	b.mu.Lock()
	b.wrapped++
	b.specs = append(b.specs, spec)
	b.mu.Unlock()
	return fakeBackend{available: b.available}.WrapCommand(ctx, profile, argv, spec)
}

func (b *recordingBackend) wrapCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wrapped
}

func (b *recordingBackend) lastSpec() supervisor.LaunchSpec {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.specs[len(b.specs)-1]
}

// fakeVMBackend is the runtime.VMBackend seam: its availability is settable and
// CreateVM records the call + the spec it received.
//
// It FAILS the BOOT BY DEFAULT (sandbox.ErrVMBootNotImplemented), which is not
// "the old stub behaviour" but a deliberate test default: most cases here assert
// ROUTING — that a vm-requested pod reaches this backend and never touches the
// host-process spine — and a default-succeeding fake would make each of them
// additionally assemble a running vm pod with supervision goroutines they do not
// mean to exercise. A case that wants a booted pod sets bootOK.
type fakeVMBackend struct {
	available bool
	// rosettaShare is the B229 seam: whether the guests this node's VM host would
	// build carry a Rosetta directory share. It defaults to false, matching the
	// shipped helper (sandbox.VMHostRosettaShareSupported), so a test that means to
	// exercise the guest-Rosetta advertisement must say so explicitly.
	rosettaShare bool

	// bootOK makes CreateVM succeed, so the pod assembly and teardown paths can
	// be driven with no VM anywhere.
	bootOK bool

	// stopHook runs inside StopVM / StopAllVMs, before the exit edge fires. It is
	// how a test observes the daemon's state AT the MOMENT it asks a helper to
	// stop — which is the only way to pin the cancel-before-stop ordering
	// deterministically rather than by racing a goroutine. Set before CreatePod.
	stopHook func(podID string)

	mu          sync.Mutex
	createCalls int
	lastSpec    sandbox.VMSpec
	err         error
	stopCalls   []fakeVMStop
	stopAllReq  int
	reapCalls   int
	done        map[string]chan struct{}
}

// fakeVMStop records one StopVM call: which pod, and with what grace.
type fakeVMStop struct {
	podID string
	grace time.Duration
}

func (b *fakeVMBackend) Available() bool                  { return b.available }
func (b *fakeVMBackend) Name() string                     { return "fake-vm" }
func (b *fakeVMBackend) GuestRosettaShareSupported() bool { return b.rosettaShare }
func (b *fakeVMBackend) CreateVM(_ context.Context, spec sandbox.VMSpec) error {
	b.mu.Lock()
	b.createCalls++
	b.lastSpec = spec
	err := b.err
	ok := b.bootOK
	if ok {
		if b.done == nil {
			b.done = map[string]chan struct{}{}
		}
		if _, exists := b.done[spec.PodID]; !exists {
			b.done[spec.PodID] = make(chan struct{})
		}
	}
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return sandbox.ErrVMBootNotImplemented
}

func (b *fakeVMBackend) StopVM(_ context.Context, podID string, grace time.Duration) error {
	b.mu.Lock()
	b.stopCalls = append(b.stopCalls, fakeVMStop{podID: podID, grace: grace})
	ch := b.done[podID]
	hook := b.stopHook
	delete(b.done, podID)
	b.mu.Unlock()
	if hook != nil {
		hook(podID)
	}
	if ch != nil {
		select {
		case <-ch:
		default:
			close(ch) // a stopped helper's exit edge fires, as the real one's does
		}
	}
	return nil
}

func (b *fakeVMBackend) StopAllVMs(_ context.Context) error {
	b.mu.Lock()
	b.stopAllReq++
	chans := make([]chan struct{}, 0, len(b.done))
	pods := make([]string, 0, len(b.done))
	for podID, ch := range b.done {
		chans = append(chans, ch)
		pods = append(pods, podID)
	}
	hook := b.stopHook
	b.done = map[string]chan struct{}{}
	b.mu.Unlock()
	if hook != nil {
		for _, podID := range pods {
			hook(podID)
		}
	}
	for _, ch := range chans {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	return nil
}

func (b *fakeVMBackend) ReapOrphanVMs() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reapCalls++
	return nil
}

func (b *fakeVMBackend) VMDone(podID string) (<-chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch, ok := b.done[podID]
	return ch, ok
}

func (b *fakeVMBackend) VMHelperOutput(string) string { return "(fake helper)" }

// killHelper simulates the helper dying on its own — a hypervisor crash or a
// guest panic — without a StopVM, which is the case the exit watch exists for.
//
// It closes the exit edge but does not deregister the pod, matching the real
// backend: a dead helper stays in the handle map until a teardown removes it,
// which is what lets the exit watch still read VMHelperOutput for the diagnosis.
// Deregistering here would also make the fake racy — a watch that called VMDone
// after the delete would see no helper and return silently.
func (b *fakeVMBackend) killHelper(podID string) {
	b.mu.Lock()
	ch := b.done[podID]
	b.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

// stops returns the recorded StopVM calls.
func (b *fakeVMBackend) stops() []fakeVMStop {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]fakeVMStop(nil), b.stopCalls...)
}

// stopAlls / reaps return the shutdown and startup sweep call counts.
func (b *fakeVMBackend) stopAlls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopAllReq
}

func (b *fakeVMBackend) reaps() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reapCalls
}

func (b *fakeVMBackend) created() (int, sandbox.VMSpec) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.createCalls, b.lastSpec
}

// recordingNetwork is a supervisor.PodNetwork that records each Setup and
// Teardown call — the /32 lo0-alias allocation/release a host-process pod gets.
// The vm (guest) route must never call it: a NAT-attached guest is reached over
// the VZNATNetworkDeviceAttachment, not a host lo0 alias. So a test asserts
// setupCount()==0 on the vm route and a host pod still allocates exactly one
// alias; the M10.1 tests assert Teardown fires on delete and on create-unwind.
type recordingNetwork struct {
	ip          string
	setupErr    error
	teardownErr error

	mu        sync.Mutex
	setups    []string
	teardowns []string
}

func (n *recordingNetwork) Setup(_ context.Context, podID string) (string, error) {
	n.mu.Lock()
	n.setups = append(n.setups, podID)
	n.mu.Unlock()
	if n.setupErr != nil {
		return "", n.setupErr
	}
	if n.ip == "" {
		return "10.1.2.3", nil
	}
	return n.ip, nil
}

func (n *recordingNetwork) Teardown(podID string) error {
	n.mu.Lock()
	n.teardowns = append(n.teardowns, podID)
	n.mu.Unlock()
	return n.teardownErr
}

func (n *recordingNetwork) setupCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.setups)
}

func (n *recordingNetwork) teardownCalls() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string{}, n.teardowns...)
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

// lastSpec returns the whole SpawnSpec of the most recent spawn, so a test can
// assert on the seam's other fields (SpawnSpec.Dir — the pod cwd) and not only
// on the environment.
func (f *fakeSpawner) lastSpec() supervisor.SpawnSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.specs) == 0 {
		return supervisor.SpawnSpec{}
	}
	return f.specs[len(f.specs)-1]
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
// (M2.6) and the last platform policy (B99) so a test can assert both reach the
// pull client.
type fakePuller struct {
	err error
	// manifest, when set, is what Pull returns — so a test can control the
	// resolved CONFIG digest a status must publish as image_id (B132). Nil keeps
	// the historical empty manifest.
	manifest *runtimev1.ImageManifest
	// descriptor and platform are the manifest's own content descriptor and the
	// index KEY the pull resolved to, which the real Puller reports and the
	// operator-facing PullImage RPC reads back. platform must be complete —
	// recording an operator root under an empty platform is refused — so a zero
	// value defaults to the native one rather than propagating a hole.
	descriptor *runtimev1.Descriptor
	platform   image.Platform

	mu             sync.Mutex
	lastCred       *image.RegistryCredential
	lastRef        string
	lastPolicy     image.PlatformPolicy
	lastPullPolicy runtimev1.ImagePullPolicy
}

func (f *fakePuller) Pull(_ context.Context, ref string, cred *image.RegistryCredential, policy image.PlatformPolicy, pull runtimev1.ImagePullPolicy) (*image.PullResult, error) {
	f.mu.Lock()
	f.lastRef = ref
	f.lastCred = cred
	f.lastPolicy = policy
	f.lastPullPolicy = pull
	mfst := f.manifest
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if mfst == nil {
		mfst = &runtimev1.ImageManifest{}
	}
	plat := f.platform
	if plat.OS == "" || plat.Architecture == "" {
		plat = image.Platform{OS: "darwin", Architecture: "arm64"}
	}
	return &image.PullResult{
		Manifest:   mfst,
		CacheHit:   true,
		Descriptor: f.descriptor,
		Platform:   plat.Normalize(),
	}, nil
}

// policy returns the last platform policy passed to Pull, so a test can assert
// the host-process spine pulls a native (never a defaulted linux/amd64) image.
func (f *fakePuller) policy() image.PlatformPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPolicy
}

// pullPolicy returns the last stamped imagePullPolicy passed to Pull, so a test
// can assert the PodBox value reaches the puller unmodified.
func (f *fakePuller) pullPolicy() runtimev1.ImagePullPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPullPolicy
}

func (f *fakePuller) credential() *image.RegistryCredential {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCred
}

// ref returns the last image ref passed to Pull ("" if Pull was never called), so
// a test can assert the native-sentinel path skips the registry entirely.
func (f *fakePuller) ref() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRef
}

// fakeUnpacker is the runtime.Unpacker seam: it records what MaterializeTree was
// asked to do and, unless told to fail, reports a tree without touching a blob
// store. Every unit test that drives a pulled image gets this by default (see
// newTestRuntimeCfg) — a fakePuller returns a manifest naming blobs that were
// never committed, so the real unpacker could not serve it.
type fakeUnpacker struct {
	err error
	// runCfg is what ImageRunConfig serves, and cfgErr fails that half
	// independently of MaterializeTree — the two are separate seam methods and a
	// test that needs one to fail must not be forced to fail the other.
	runCfg image.ImageRunConfig
	cfgErr error

	mu       sync.Mutex
	calls    int
	lastMfst *runtimev1.ImageManifest
	lastPol  image.UnpackPolicy
	lastDst  string
}

func (f *fakeUnpacker) MaterializeTree(_ context.Context, mfst *runtimev1.ImageManifest, policy image.UnpackPolicy, dst string) (*image.MaterializeResult, error) {
	f.mu.Lock()
	f.calls++
	f.lastMfst = mfst
	f.lastPol = policy
	f.lastDst = dst
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &image.MaterializeResult{Tree: &image.Tree{Key: "sha256:fake", Rootfs: dst, Policy: policy}}, nil
}

// ImageRunConfig serves the fake's configured image run config. The zero value
// is an image that declares nothing — no Entrypoint, no Cmd, no Env — which is
// the shape every pre-M11.2-d1 test implicitly assumed, so those tests keep
// asserting on a pod-supplied command alone.
func (f *fakeUnpacker) ImageRunConfig(_ *runtimev1.ImageManifest) (image.ImageRunConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cfgErr != nil {
		return image.ImageRunConfig{}, f.cfgErr
	}
	return f.runCfg, nil
}

// observed returns the call count and the last (policy, destination) pair, so a
// test can assert the spine materializes exactly once per pulled container and
// into the pod's own rootfs.
func (f *fakeUnpacker) observed() (int, image.UnpackPolicy, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastPol, f.lastDst
}

// manifest returns the last manifest handed to MaterializeTree.
func (f *fakeUnpacker) manifest() *runtimev1.ImageManifest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastMfst
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
	return newTestRuntimeCfg(t, Config{}, d)
}

// newTestRuntimeCfg is newTestRuntime with a caller-supplied Config (an empty
// Root defaults to a test temp dir), so a test can exercise Config-level knobs
// (e.g. the per-pod SBPL egress VIPs) over the same fake subsystem seams.
func newTestRuntimeCfg(t *testing.T, cfg Config, d Deps) *Runtime {
	t.Helper()
	d = testDeps(t, d)
	if d.Puller == nil {
		d.Puller = &fakePuller{}
	}
	// Defaulted here and not in testDeps for the same reason Puller is:
	// pull_wiring_test.go's TestDefaultPullerPlatformWiring calls
	// New(..., testDeps(t, Deps{})) to reach the daemon's real image wiring, and
	// that is the one test that would go green against a New which never builds
	// an unpacker at all.
	if d.Unpacker == nil {
		d.Unpacker = &fakeUnpacker{}
	}
	// Default the two Rosetta probe seams to deterministic fail-closed fakes. Left
	// nil they fall through in New to the real sandbox.ProbeHostRosetta, which stats
	// a SIP path and — on a Rosetta-2-installed host — forks /usr/bin/arch, once per
	// construction: ~85 real stats and up to ~85 real forks per run of this package,
	// i.e. host-dependent wall time in the unit tier (GO-STANDARDS §Testing: fake at
	// seams, no real privilege). Fail-closed states are the deterministic choice for
	// the same reason fakeVMBackend defaults to unavailable.
	//
	// They are defaulted here and not in testDeps for exactly the reason Puller is:
	// rosetta_test.go's default_probe_wiring subtest calls New(…, testDeps(t, Deps{}))
	// directly to reach the real nil-deps wiring, and that is the one test that would
	// go green against a New which never wires the real probes at all.
	if d.HostRosetta == nil {
		d.HostRosetta = func(context.Context) sandbox.HostRosettaState { return sandbox.HostRosettaAbsent }
	}
	if d.GuestRosetta == nil {
		d.GuestRosetta = func() sandbox.GuestRosettaState { return sandbox.GuestRosettaQueryFailed }
	}
	if cfg.Root == "" {
		cfg.Root = t.TempDir()
	}
	rt, err := New(cfg, d)
	if err != nil {
		t.Fatal(err)
	}
	// Shrink the post-SIGKILL exit-observation bound for the unit tier. Every
	// escalating stop now waits for the reaper to report the exit (B40), and most
	// tests here drive a fake waiter they never release for a killed container —
	// which is the bound's timeout arm, at its production 2s, once per such stop.
	// The production default is pinned by TestExitObservationGraceDefault and the
	// waiting behaviour itself is gated in pkg/supervisor, so shrinking it here
	// hides nothing; a test that needs the real value sets the field back.
	rt.exitObsGrace = 50 * time.Millisecond
	return rt
}

// testDeps fills the deterministic fake subsystem seams every pkg/runtime unit
// test shares. It deliberately does not default Puller, HostRosetta or GuestRosetta:
// newTestRuntimeCfg adds fakes for those three, while the production-wiring tests
// (pull_wiring_test.go, and rosetta_test.go's default_probe_wiring) call
// New(…, testDeps(t, Deps{})) directly and leave them nil so New builds the daemon's
// own image.NewPuller(cache, image.RemoteFetch) / sandbox.Probe*Rosetta.
//
// It also does not default Cache — New builds one rooted at Config.Root, which is
// the PRODUCTION wiring (runtime.go; the daemon and the k3sm provider both pass
// Deps without a Cache). The old default handed the runtime a cache at a second
// t.TempDir(), so Config.Root and the pod layout disagreed and every guard bounded
// to <Config.Root>/pods was unsatisfiable in the unit tier: B136 and B140 each had
// to hand-build a shared-root harness to reach their sink at all, vmshareplan_test
// states the alignment locally for the share planner, and B142's data-volume bound
// (Posture.WorkDir is Config.Root, the data volume is cache-derived) would have
// refused every pod.
// A test that wants the two split still injects its own Cache.
func testDeps(t *testing.T, d Deps) Deps {
	t.Helper()
	if d.Backend == nil {
		d.Backend = fakeBackend{available: true}
	}
	// Default the vm backend UNavailable so existing host-process tests are
	// deterministic regardless of the test host's real VZ capability (the routing
	// test opts in with an available fake). Unit tests never use real privilege.
	if d.VMBackend == nil {
		d.VMBackend = &fakeVMBackend{available: false}
	}
	if d.Spawner == nil {
		d.Spawner = &fakeSpawner{}
	}
	if d.Waiter == nil {
		d.Waiter = newBlockingWaiter()
	}
	if d.Signer == nil {
		d.Signer = &fakeSigner{}
	}
	if d.Network == nil {
		d.Network = supervisor.NodeNetwork{IP: "10.1.2.3"}
	}
	// Default the startup-reap seams to deterministic fakes so pod-lifecycle unit
	// tests never fall through to the real kern.proc.* sysctls (nondeterministic,
	// and a unit-tier dependency on the live process table). ProcStartTime reports
	// a fixed non-zero identity; ProcGroup reports an empty-but-inspectable group
	// (ok=true), which watchContainerExit reads as "group drained" so a completed
	// container's reap record is cleaned up. Tests that exercise the reap decision
	// (podreap_test.go) inject their own fake tables over these.
	if d.ProcStartTime == nil {
		d.ProcStartTime = func(int) (int64, bool) { return 1, true }
	}
	if d.ProcGroup == nil {
		d.ProcGroup = func(int) ([]supervisor.ProcMember, bool) { return nil, true }
	}
	// Default the GPU probe to a deterministic "no usable GPU" observation, for the
	// same reason the vm backend defaults unavailable: otherwise every runtime unit
	// test would run the real Metal compile+dispatch probe and its result would
	// depend on the test host's hardware. The GPU tests inject their own.
	if d.GPUProbe == nil {
		d.GPUProbe = func() sandbox.GPUProbeResult {
			return sandbox.GPUProbeResult{Metal: sandbox.MetalStatus{Reason: sandbox.MetalReasonNoDevice}}
		}
	}
	return d
}

// derivedRootfs is the one way a test spells a pod's on-disk data volume.
//
// Since B140 a box's rootfs_path is accepted only when it is byte-equal to this
// derivation, so a test that wants an on-disk pod dir asks the runtime for it
// instead of inventing a t.TempDir(). Callers that set box.rootfs_path must set
// SandboxProfile.data_volume_path to the same value: sandbox.Generate carves the
// credential read-only sub-scope only out of paths under the data volume, and
// the pods root is otherwise in the protected deny-set — so moving one field
// without the other makes credential-path validation fail for reasons that have
// nothing to do with the test's subject.
func derivedRootfs(t *testing.T, rt *Runtime, podID string) string {
	t.Helper()
	id, err := image.ParsePodID(podID)
	if err != nil {
		t.Fatalf("ParsePodID(%q): %v", podID, err)
	}
	return rt.cache.PodRootfs(id)
}

// hostBinBox builds a minimal valid PodBox running a host-binary container,
// against rt's own derived pod layout.
//
// It takes the runtime because since B142 sandbox_profile.data_volume_path is
// accepted only when it is byte-equal to <Config.Root>/pods/<pod_id>{,/rootfs},
// and the runtime under test is rooted at a t.TempDir() — the hard-coded
// /var/lib/k3sm spelling this used to carry named a tree no test ever touched.
// Deriving it in this one helper is what keeps ~60 call sites out of the layout.
//
// An id ParsePodID rejects gets the naive spelling: the hostile-id tests pass one
// deliberately, and their subject is the id check (which runs first), so the box
// must stay valid in every other respect for those tests to be about anything.
func hostBinBox(rt *Runtime, podID string) *runtimev1.PodBox {
	dataVol := filepath.Join(rt.cache.PodsRoot(), podID, "rootfs")
	if id, err := image.ParsePodID(podID); err == nil {
		dataVol = rt.cache.PodRootfs(id)
	}
	return &runtimev1.PodBox{
		PodId:     podID,
		Namespace: "default",
		Name:      "p",
		SandboxProfile: &runtimev1.SandboxProfile{
			DataVolumePath: dataVol,
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

	box := hostBinBox(rt, "pod-1")
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

// TestCreatePodFailClosed asserts the runtime refuses to start a pod when the
// sandbox backend is unavailable (never runs unconfined) — the fail-closed
// requirement.
func TestCreatePodFailClosed(t *testing.T) {
	rt := newTestRuntime(t, Deps{Backend: fakeBackend{available: false}})
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-x")})
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

// TestCreatePodVMRoutingBypassesHostProcessSteps is the M5.1 routing proof: a pod
// whose SandboxProfile.backend is SANDBOX_BACKEND_VM, on a host where the vm
// backend is available, routes to vmBackend.CreateVM and runs none of the
// host-process (Mach-O) steps — no resolveBinary, no ad-hoc sign /
// gateSignature, no WrapCommand exec-shim, no posix_spawn. It does pull, since
// M11.2-d11: the guest merges nothing, so each container's image config is read
// host-side — but nothing downstream of the pull on the host-process spine runs. The symmetric control
// case proves an UNSPECIFIED (host-process) pod still drives exactly those steps
// (byte-unchanged), and a vm-requested pod on a host without the vm backend fails
// closed (never downgrades, never routes to CreateVM).
func TestCreatePodVMRoutingBypassesHostProcessSteps(t *testing.T) {
	t.Run("vm-routed-bypasses-host-process-steps", func(t *testing.T) {
		signer := &fakeSigner{}
		sp := &fakeSpawner{}
		backend := &recordingBackend{available: true}
		vmb := &fakeVMBackend{available: true}
		// vmPodConfig: the share planner requires the pod dir under
		// <Config.Root>/pods, so the cache must be rooted at Config.Root as
		// production wires it.
		cfg, d := vmPodConfig(t, Deps{Signer: signer, Spawner: sp, Backend: backend, VMBackend: vmb})
		rt := newTestRuntimeCfg(t, cfg, d)

		box := vmPodBox(rt, "pod-vm", 0)
		box.SandboxProfile.VmVcpus = 2
		box.SandboxProfile.VmMemoryBytes = 1 << 30

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatalf("CreatePod transport error: %v", err)
		}
		// The vm boot is a lab-gated stub, so the pod surfaces a SANDBOX_SETUP error.
		if resp.GetError() == nil {
			t.Fatal("vm-routed pod should surface the lab-gated boot error")
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP {
			t.Errorf("reason = %v, want SANDBOX_SETUP", resp.GetFailureReason())
		}

		// It routed to CreateVM with the stamped sizing.
		n, spec := vmb.created()
		if n != 1 {
			t.Fatalf("CreateVM called %d times, want 1", n)
		}
		if spec.Vcpus != 2 || spec.MemoryBytes != 1<<30 || spec.PodID != "pod-vm" {
			t.Errorf("VMSpec = %+v, want {PodID:pod-vm Vcpus:2 MemoryBytes:%d}", spec, int64(1<<30))
		}

		// And it touched none of the host-process steps.
		if got := backend.wrapCalls(); got != 0 {
			t.Errorf("vm path called WrapCommand %d times; must be 0 (no exec-shim)", got)
		}
		signer.mu.Lock()
		nsigned := len(signer.signed)
		signer.mu.Unlock()
		if nsigned != 0 {
			t.Errorf("vm path ad-hoc signed %d binaries; must be 0 (no host-process codesign)", nsigned)
		}
		sp.mu.Lock()
		nspawn := len(sp.specs)
		sp.mu.Unlock()
		if nspawn != 0 {
			t.Errorf("vm path posix_spawned %d processes; must be 0 (no host-process exec)", nspawn)
		}
	})

	t.Run("vm-requested-unavailable-fails-closed", func(t *testing.T) {
		vmb := &fakeVMBackend{available: false} // no Virtualization.framework / entitlement
		rt := newTestRuntime(t, Deps{VMBackend: vmb})

		box := hostBinBox(rt, "pod-vm-noavail")
		box.SandboxProfile.Backend = runtimev1.SandboxBackend_SANDBOX_BACKEND_VM

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatalf("CreatePod transport error: %v", err)
		}
		if resp.GetError() == nil {
			t.Fatal("vm-requested pod on a host without the vm backend must fail closed")
		}
		if resp.GetFailureReason() != runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP {
			t.Errorf("reason = %v, want SANDBOX_SETUP", resp.GetFailureReason())
		}
		// Fail-closed means it never even reached the (stubbed) boot.
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("CreateVM called %d times on an unavailable vm backend; must be 0 (fail closed before routing)", n)
		}
	})

	t.Run("host-process-path-unaffected", func(t *testing.T) {
		signer := &fakeSigner{}
		sp := &fakeSpawner{}
		backend := &recordingBackend{available: true}
		vmb := &fakeVMBackend{available: true} // available, but NOT requested
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Signer: signer, Spawner: sp, Backend: backend, VMBackend: vmb, Waiter: w})

		// UNSPECIFIED backend (the host-process default) — the byte-unchanged path.
		box := hostBinBox(rt, "pod-host")

		resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
		if err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		if resp.GetError() != nil {
			t.Fatalf("host-process pod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
		}
		// It drove the host-process steps and never routed to the vm backend.
		if got := backend.wrapCalls(); got == 0 {
			t.Error("host-process path did not call WrapCommand (exec-shim seam)")
		}
		// The signature was gated (gateSignature ran — CreatePod would have failed
		// above otherwise), but a HOST binary (hostBinBox runs /bin/sleep) is already
		// signed and read-only, so it must never be ad-hoc re-signed (`codesign -s -
		// -f /bin/sleep` fails on a SIP platform binary — the M2-hardware bug).
		signer.mu.Lock()
		nsigned := len(signer.signed)
		signer.mu.Unlock()
		if nsigned != 0 {
			t.Errorf("host-process path ad-hoc signed a host binary %d time(s); a signed, read-only host binary must never be re-signed", nsigned)
		}
		sp.mu.Lock()
		nspawn := len(sp.specs)
		sp.mu.Unlock()
		if nspawn == 0 {
			t.Error("host-process path did not posix_spawn")
		}
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("host-process path called CreateVM %d times; must be 0", n)
		}
		w.release(1001)
	})
}

// TestCreateVMPod_GuestNetworkPlumbing proves the runtimed-side guest-network seam
// (B2): a vm-RuntimeClass pod's GuestNetworkConfig (the DNS configuration + the NAT
// advisory fields) reaches the VMSpec the vm backend's CreateVM receives, while the
// host-process path never sees it and a NAT-attached guest binds NO lo0 alias.
//
// It asserts the behavioral FORK, not a tautology: the same producer — a
// Deps.Network implementing the M11.2-d8 GuestNetworker seam, holding one populated
// config — serves both a vm pod and a host pod. For the vm pod the config reaches
// VMSpec.Network (resolv.conf nameserver+search+ndots and the NAT fields intact)
// and the route allocates zero lo0 aliases; for the host pod the producer is never
// even consulted, nothing reaches createVMPod (CreateVM call count 0), and the route
// allocates its one lo0 alias.
func TestCreateVMPod_GuestNetworkPlumbing(t *testing.T) {
	// The rendered /etc/resolv.conf the guest provisioner pins (pkg/dns.GuestResolvConf
	// shape): nameserver + search + options ndots: — the operative Linux-guest DNS
	// artifact that must survive the seam intact.
	const resolvConf = "nameserver 10.43.0.10\n" +
		"search default.svc.cluster.local svc.cluster.local cluster.local\n" +
		"options ndots:5\n"
	netCfg := sandbox.GuestNetworkConfig{
		Nameservers: []string{"10.43.0.10"},
		Searches:    []string{"default.svc.cluster.local", "svc.cluster.local", "cluster.local"},
		Options:     []string{"ndots:5"},
		ResolvConf:  resolvConf,
		PodIP:       netip.MustParseAddr("10.42.0.7"),
		Gateway:     netip.MustParseAddr("192.168.66.1"),
		NATSubnet:   netip.MustParsePrefix("192.168.66.0/24"),
		DNSVIP:      netip.MustParseAddr("10.43.0.10"),
	}

	t.Run("vm-pod-carries-config-no-lo0-alias", func(t *testing.T) {
		vmb := &fakeVMBackend{available: true}
		net := &guestNetworkerNetwork{cfg: netCfg, ok: true}
		// vmPodConfig: the share planner requires the pod dir under
		// <Config.Root>/pods, so the cache must be rooted at Config.Root as
		// production wires it.
		cfg, d := vmPodConfig(t, Deps{VMBackend: vmb, Network: net})
		rt := newTestRuntimeCfg(t, cfg, d)

		box := vmPodBox(rt, "pod-vm-net", 0)

		// The producer holds the config; createVMPod pulls it through the seam. The
		// lab-gated boot stub then surfaces an error, which is expected and orthogonal
		// to the plumbing assertion.
		if _, _, err := rt.createPod(context.Background(), box); err == nil {
			t.Fatal("vm createPod should surface the lab-gated boot error")
		}

		// X reached CreateVM: the recorded VMSpec.Network is the config we fed in.
		n, spec := vmb.created()
		if n != 1 {
			t.Fatalf("CreateVM called %d times, want 1", n)
		}
		if spec.Network.ResolvConf != resolvConf {
			t.Errorf("VMSpec.Network.ResolvConf = %q, want %q", spec.Network.ResolvConf, resolvConf)
		}
		// nameserver + search + ndots survived the seam intact.
		for _, frag := range []string{"nameserver 10.43.0.10", "search default.svc.cluster.local", "options ndots:5"} {
			if !strings.Contains(spec.Network.ResolvConf, frag) {
				t.Errorf("resolv.conf missing %q:\n%s", frag, spec.Network.ResolvConf)
			}
		}
		// The NAT advisory fields survived too.
		if spec.Network.PodIP != netCfg.PodIP || spec.Network.Gateway != netCfg.Gateway ||
			spec.Network.NATSubnet != netCfg.NATSubnet || spec.Network.DNSVIP != netCfg.DNSVIP {
			t.Errorf("VMSpec.Network NAT fields = %+v, want %+v", spec.Network, netCfg)
		}
		// A NAT-attached guest binds NO lo0 alias: the vm route never calls network.Setup.
		if got := net.setupCount(); got != 0 {
			t.Errorf("vm route allocated %d lo0 aliases; must be 0 (guest is NAT-attached)", got)
		}
	})

	t.Run("host-pod-never-gets-config-binds-lo0-alias", func(t *testing.T) {
		vmb := &fakeVMBackend{available: true} // available, but NOT requested
		net := &guestNetworkerNetwork{cfg: netCfg, ok: true}
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{VMBackend: vmb, Network: net, Waiter: w})

		// UNSPECIFIED backend → the host-process route, over the same populated producer.
		box := hostBinBox(rt, "pod-host-net")

		p, _, err := rt.createPod(context.Background(), box)
		if err != nil {
			t.Fatalf("host createPod failed: %v", err)
		}
		if p == nil {
			t.Fatal("host createPod returned nil pod")
		}
		// It never routed to createVMPod, so the config never reached a VMSpec.
		if n, _ := vmb.created(); n != 0 {
			t.Errorf("host route called CreateVM %d times; must be 0 (config must not reach the guest seam)", n)
		}
		// The producer is not even consulted: a host process is served by
		// PodNetwork.Setup and wants no guest config, so no absent-config warning
		// can ever be emitted for it either.
		if got := net.guestNetworkCalls(); len(got) != 0 {
			t.Errorf("host route consulted the GuestNetworker for %v; must consult it for nothing", got)
		}
		// The host process binds its one /32 lo0 alias (network.Setup fires here).
		if got := net.setupCount(); got != 1 {
			t.Errorf("host route allocated %d lo0 aliases; want 1", got)
		}
		w.release(1001)
	})
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
			box := hostBinBox(rt, "pod-v")
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
	box := hostBinBox(rt, "pod-sig")
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

	box := hostBinBox(rt, "pod-init")
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
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-w")}); err != nil {
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
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: hostBinBox(rt, "pod-l")}); err != nil {
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
	box := hostBinBox(rt, "pod-u")
	if _, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box}); err != nil {
		t.Fatal(err)
	}

	t.Run("annotation-ok", func(t *testing.T) {
		nb := hostBinBox(rt, "pod-u")
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
		nb := hostBinBox(rt, "pod-u")
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

// TestGetRuntimeInfo_VMAvailability asserts GetRuntimeInfo advertises the vm
// backend's availability as a VMBackendAvailable RuntimeCondition, driven by the
// injectable VMBackend seam (fakeVMBackend): probe available => true, else false.
// No real VZ hardware (B1 — the node reads this to set k3sm.io/virtualization).
func TestGetRuntimeInfo_VMAvailability(t *testing.T) {
	cases := []struct {
		name        string
		vmAvailable bool
		want        runtimev1.ConditionStatus
	}{
		{"vm available", true, runtimev1.ConditionStatus_CONDITION_STATUS_TRUE},
		{"vm unavailable", false, runtimev1.ConditionStatus_CONDITION_STATUS_FALSE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newTestRuntime(t, Deps{VMBackend: &fakeVMBackend{available: tc.vmAvailable}})
			info, err := rt.GetRuntimeInfo(context.Background(), &runtimev1.GetRuntimeInfoRequest{})
			if err != nil {
				t.Fatal(err)
			}
			got := findCondition(info, ConditionVMBackendAvailable)
			if got == nil {
				t.Fatalf("GetRuntimeInfo did not advertise a VMBackendAvailable condition; conditions = %v", info.GetConditions())
			}
			if got.GetStatus() != tc.want {
				t.Errorf("VMBackendAvailable status = %v, want %v", got.GetStatus(), tc.want)
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
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, Resolver: fakeResolver{}})
	dataVol := derivedRootfs(t, rt, "pod-vol")

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

// TestCreatePodThreadsRlimitQoSLaunchSpec is the B7 WIRING proof that kills the
// resolveRlimitPlan dead-path: a PodBox with explicit rlimits[] and a BestEffort
// qos_class (1) reaches WrapCommand as a resolved supervisor.LaunchSpec (the
// resolver runs LIVE in the spawn path), (2) produces a spawned shim argv
// carrying the encoded rlimit + qos tokens at their fixed positions before the
// profile path, and (3) the rlimit token decodes — via the same ParseRlimits the
// shim's main() performs — back to the non-nil numeric plan, so the shim hands
// RunLaunchSequence a non-nil plan (never the historical plan=nil).
func TestCreatePodThreadsRlimitQoSLaunchSpec(t *testing.T) {
	sp := &fakeSpawner{}
	w := newBlockingWaiter()
	be := &recordingBackend{available: true}
	rt := newTestRuntime(t, Deps{Spawner: sp, Waiter: w, Backend: be})

	box := hostBinBox(rt, "pod-rlimit-qos")
	box.Rlimits = []*runtimev1.ResourceLimit{
		{Type: "RLIMIT_NOFILE", Soft: 1024, Hard: 4096},
		{Type: "RLIMIT_NPROC", Soft: 64, Hard: 128},
	}
	box.QosClass = runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT
	mustCreatePod(t, rt, box)
	defer w.release(1001)

	wantPlan := []supervisor.PlannedRlimit{
		{Resource: unix.RLIMIT_NOFILE, Lim: unix.Rlimit{Cur: 1024, Max: 4096}},
		{Resource: unix.RLIMIT_NPROC, Lim: unix.Rlimit{Cur: 64, Max: 128}},
	}

	// (1) the backend received the resolved LaunchSpec — resolveRlimitPlan and
	// resolveBgQoS ran live in startContainer.
	spec := be.lastSpec()
	if !reflect.DeepEqual(spec.Rlimits, wantPlan) {
		t.Errorf("WrapCommand spec.Rlimits = %+v, want %+v", spec.Rlimits, wantPlan)
	}
	if !spec.BgQoS {
		t.Error("WrapCommand spec.BgQoS = false, want true for a BestEffort pod")
	}

	// (2) the spawned argv carries the encoded tokens at the fixed positions
	// (fakeBackend mirrors the production shape [shim, uid, gid, groups, rlimits,
	// qos, profile, argv...]).
	argv := sp.specs[len(sp.specs)-1].Argv
	if len(argv) < 7 {
		t.Fatalf("spawn argv too short: %v", argv)
	}
	if want := supervisor.EncodeRlimits(wantPlan); argv[4] != want {
		t.Errorf("rlimit argv token = %q, want %q", argv[4], want)
	}
	if argv[5] != "q=bg" {
		t.Errorf("qos argv token = %q, want %q", argv[5], "q=bg")
	}

	// (3) the token decodes — the shim-side decode — to the non-nil plan.
	decoded, err := supervisor.ParseRlimits(argv[4])
	if err != nil {
		t.Fatalf("ParseRlimits(%q): %v", argv[4], err)
	}
	if decoded == nil || !reflect.DeepEqual(decoded, wantPlan) {
		t.Errorf("decoded plan = %+v, want non-nil %+v", decoded, wantPlan)
	}
}

// TestRuntimeConfigThreadsPostureVIPs pins the M10.1 posture: the cluster VIPs
// set on runtime.Config still thread into sandbox.Posture (pod.go — the DNS
// env/status plumbing reads them) but are PLUMBING-only and must render NO SBPL
// rule, because per-IP network filters do not compile on macOS 26 — the
// pre-M10.1 VIP-scoped stanza failed sandbox_apply and no networked pod could
// spawn. A networked pod's profile instead carries the unfiltered
// (allow network-outbound) / (allow network-bind), VIPs set or not.
func TestRuntimeConfigThreadsPostureVIPs(t *testing.T) {
	const (
		resolverVIP = "10.43.0.10"
		apiVIP      = "10.43.0.1"
	)
	cases := []struct {
		name        string
		cfg         Config
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name:        "vips-set-plumbing-only",
			cfg:         Config{ResolverVIP: resolverVIP, APIServerVIP: apiVIP},
			wantPresent: []string{"(allow network-outbound)", "(allow network-bind)"},
			// The VIPs must not leak into the SBPL in any form (no per-IP filter).
			wantAbsent: []string{"(remote ip", "(local ip", resolverVIP, apiVIP},
		},
		{
			name:        "vips-unset-same-profile",
			cfg:         Config{},
			wantPresent: []string{"(allow network-outbound)", "(allow network-bind)"},
			wantAbsent:  []string{"(remote ip", "(local ip"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newBlockingWaiter()
			rt := newTestRuntimeCfg(t, tc.cfg, Deps{Waiter: w})

			box := hostBinBox(rt, "pod-vip")
			box.SandboxProfile.AllowNetwork = true // egress rules are gated on allow_network

			resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
			if err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if resp.GetError() != nil {
				t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
			}

			rt.mu.Lock()
			profile := rt.pods["pod-vip"].profile
			rt.mu.Unlock()

			for _, frag := range tc.wantPresent {
				if !strings.Contains(profile, frag) {
					t.Errorf("SBPL missing %q (Config VIP not threaded into Posture):\n%s", frag, profile)
				}
			}
			for _, frag := range tc.wantAbsent {
				if strings.Contains(profile, frag) {
					t.Errorf("SBPL unexpectedly contains %q:\n%s", frag, profile)
				}
			}

			w.release(1001)
		})
	}
}

// guard against accidentally importing a real registry in unit tests.
var _ = errors.New
