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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
	"k3sm.io/runtimed/pkg/volume"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// Ensure Runtime implements the apis runtime/v1 server contract. The M2 daemon
// split registers this same type with a gRPC server — making the split a
// relocation, not a redesign.
var _ runtimev1.RuntimeServer = (*Runtime)(nil)

// RuntimeName and apiVersion identify this implementation in GetRuntimeInfo.
const (
	RuntimeName = "k3sm-runtimed"
	apiVersion  = "runtime.v1"
)

// Puller is the image-pull seam the Runtime consumes (the concrete *image.Puller
// satisfies it). Defined at the consumer per the standards so tests can inject a
// fake that never touches a registry. cred (M2.6) is the imagePullSecret
// credential, consumed only by the pull client; nil = anonymous pull.
//
// policy (B99) chooses which platform of a multi-platform image is pulled. It
// rides on the CALL, not on the Puller, because the sandbox backend that decides
// it is resolved per pod (sandbox.SelectBackend in createPod).
type Puller interface {
	Pull(ctx context.Context, ref string, cred *image.RegistryCredential, policy image.PlatformPolicy) (*image.PullResult, error)
}

// Signer ad-hoc signs a pulled binary and gates it against a SignaturePolicy
// before exec. The image package provides both halves; the Runtime consumes them
// as one seam (fakeable in tests). gateSignature orders the two correctly per
// policy (M2.6): ad-hoc sign ONLY for adhoc-ok; check-without-sign for
// require-signed/require-notarized so a real signature is never silently
// downgraded.
type Signer interface {
	// Sign ad-hoc signs the Mach-O at path (codesign -s - -f, no hardened
	// runtime) so a later DYLD insert can load.
	Sign(ctx context.Context, path string) error
	// Check enforces policy against path's signature, fail-closed on UNSPECIFIED.
	Check(ctx context.Context, policy runtimev1.SignaturePolicy, path string) error
}

// CredentialResolver resolves the registry pull credential for an image from the
// pod's imagePullSecrets (M2.6). Like mount.Resolver it is a consumer-side seam:
// runtimed never reads the apiserver, so the provider (k3sm) supplies one backed
// by its client (it reads the referenced docker-config Secrets); unit tests fake
// it. A nil resolver, an empty imagePullSecrets list, or an ok==false result means
// an anonymous pull (public images).
//
// The resolved credential is consumed ONLY by the image pull client and is NEVER
// written into the pod dir / materialized filesystem — the M2.6 security invariant.
type CredentialResolver interface {
	// PullCredential returns the credential for pulling ref given the pod's
	// namespace-local imagePullSecret references, or ok=false for an anonymous pull.
	PullCredential(ctx context.Context, namespace string, secrets []*runtimev1.LocalObjectReference, ref string) (cred *image.RegistryCredential, ok bool, err error)
}

// VMBackend is the consumer-side seam for the Virtualization.framework micro-VM
// isolation backend (M5.1). The Runtime queries Available() during fail-closed
// backend selection — a pod that requested the vm backend on a host without it is
// REFUSED, never downgraded to Seatbelt — and, when the vm rung is selected,
// routes the pod to CreateVM instead of the host-process exec-shim path. The
// concrete *sandbox.VMBackend satisfies it; tests inject a fake. It is
// intentionally NARROWER than sandbox.Backend: the vm path never uses WrapCommand
// (a Linux guest is not a confined host process).
type VMBackend interface {
	// Available reports whether the vm backend can run a guest on this host
	// (Virtualization.framework supported + the com.apple.security.virtualization
	// entitlement). It is a SAFE probe — it never constructs or boots a VM.
	Available() bool
	// Name identifies the backend for logging/diagnostics.
	Name() string
	// CreateVM boots the pod's Linux guest from spec. In M5.1 it is a lab-gated
	// stub returning sandbox.ErrVMBootNotImplemented (the live boot needs a
	// VZ-capable, entitled Mac).
	CreateVM(ctx context.Context, spec sandbox.VMSpec) error
}

// Ensure the concrete vm backend satisfies the consumer seam.
var _ VMBackend = (*sandbox.VMBackend)(nil)

// Config configures a Runtime. Zero values get sensible defaults via New.
type Config struct {
	// Root is the on-disk root (image cache + pod dirs). Defaults to
	// image.DefaultRoot (/var/lib/k3sm); tests pass a temp dir.
	Root string
	// RuntimeVersion is reported by GetRuntimeInfo.
	RuntimeVersion string
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
	// SampleInterval is the memory sampler's polling period (M2.5). Defaults to
	// 1s (the ~1 Hz the design calls for); tests set it small.
	SampleInterval time.Duration
	// ResolverVIP is the cluster DNS Service VIP for this node, threaded into
	// sandbox.Posture.ResolverVIP. PLUMBING-ONLY since M10.1: it renders NO SBPL
	// rule (per-IP network filters do not compile on macOS 26 — see
	// sandbox.Generate); it is the node-level DNS configuration the env/status
	// plumbing reads. The control plane (k3sm) sets it from the service CIDR;
	// empty falls back to sandbox.DefaultResolverVIP.
	ResolverVIP string
	// APIServerVIP is the in-cluster Kubernetes API Service VIP (the `kubernetes`
	// ClusterIP), threaded into sandbox.Posture.APIServerVIP. PLUMBING-ONLY since
	// M10.1: like ResolverVIP it renders NO SBPL rule — an allow_network pod has
	// unfiltered egress. The control plane (k3sm) sets it from the service CIDR.
	APIServerVIP string
	// PathShimPath is the on-disk path of the path-rebase DYLD interpose shim
	// (shim/pathrebase_shim.c). When set, containerEnv injects it into a mounting
	// container's DYLD_INSERT_LIBRARIES with K3SM_ROOTFS + K3SM_MOUNT_PATHS so an
	// absolute volume mount resolves to its materialized copy under the pod data
	// volume (no chroot — see pod.go containerEnv). Empty disables the rebase (a
	// pod's absolute mount path then reaches the host, the pre-shim behavior). The
	// shim cannot load into a SIP platform binary (/bin/sh) — only custom Go/C
	// workloads — a documented ceiling.
	PathShimPath string
}

// Runtime is the in-process node runtime implementing runtimev1.RuntimeServer.
//
// Concurrency: mu guards pods. Subsystem seams (puller, signer, backend,
// spawner, waiter, network, broker) are set at construction and are themselves
// concurrency-safe. Status changes are published through broker OUTSIDE mu.
type Runtime struct {
	runtimev1.UnimplementedRuntimeServer

	cfg Config
	// home is the daemon user's home when the work-dir (cfg.Root) lives under it
	// (the unprivileged user-space posture); else "". It is passed to the SBPL
	// generator as the work-dir containment bound (sandbox.Posture.Home) so a
	// misconfigured work-dir cannot point a pod's writable re-allow outside the
	// daemon's data area. Empty disables the check (legacy root work-dir / tests).
	home        string
	log         *slog.Logger
	cache       *image.Cache
	puller      Puller
	signer      Signer
	credentials CredentialResolver
	backend     sandbox.Backend
	// vmBackend is the Virtualization.framework micro-VM rung (M5.1). createPod
	// queries Available() so a vm-requested pod fails closed when it is absent, and
	// routes a selected vm pod to CreateVM (away from the host-process path).
	vmBackend   VMBackend
	spawner     supervisor.Spawner
	waiter      supervisor.ExitWaiter
	network     supervisor.PodNetwork
	resolver    mount.Resolver
	binder      *volume.Binder
	footprinter supervisor.Footprinter
	broker      *broker

	// signalGroup signals a pod's process GROUP (supervisor.SignalGroup in
	// production); it is a field so the graceful-stop (M2.4) and OOM-kill (M2.5)
	// paths are unit-testable with a recorder.
	signalGroup func(pgid int, sig os.Signal) error

	// drainGrace bounds watchContainerExit's wait for a terminated container's log
	// pump to reach EOF before snapshotting the FallbackToLogsOnError message; 0
	// selects defaultDrainGrace. It is a field (not a const) so tests can shrink it
	// for fast, deterministic runs — there is no clock seam in this package.
	drainGrace time.Duration

	// netReconcileOnce/netReconcileErr make the optional network startup
	// reconcile (NetworkReconciler) run exactly once per Runtime, BEFORE any
	// CreatePod is served. Once.Do provides the happens-before for the error
	// read; a repeated Serve re-reports the sticky first result.
	netReconcileOnce sync.Once
	netReconcileErr  error

	// procStart reports a live process's kernel start time — the leader
	// identity recorded at spawn for the startup pod reap (podreap.go).
	// Production wires supervisor.ProcStartTimeNano; tests inject a fake table.
	procStart procStartTime

	// procGroup reports the live members (pid + start time) of a process group —
	// the startup reap probes the GROUP so it can match the leader member
	// (Pid == pgid) exactly and see a leaked group whose leader has exited
	// (podreap.go). Production wires supervisor.ProcGroupMembers; tests inject a
	// fake group table.
	procGroup procGroupInspector

	// podReapOnce/podReapErr make the startup pod reap run exactly once per
	// Runtime, BEFORE any CreatePod is served (same shape as the network
	// startup reconcile above, and like it sticky/fail-closed).
	podReapOnce sync.Once
	podReapErr  error

	mu   sync.Mutex
	pods map[string]*pod
}

// NetworkReconciler is the OPTIONAL startup-reconcile seam a Deps.Network may
// additionally implement. The real IPAM adapter (k3sm-injected, over
// darwin-net's podnet) keeps its allocation state IN MEMORY while the /32 lo0
// aliases it binds are DURABLE on the interface — so after a daemon restart
// (`launchctl kickstart -k`) the fresh allocator and the surviving aliases
// disagree: new allocations collide with stale aliases and orphaned aliases
// leak pool addresses. ReconcileStartup runs once, before the runtime serves
// CreatePod, to sweep stale aliases / reattach state (implemented adapter-side;
// runtimed only provides the hook). The no-op NodeNetwork does not implement it.
type NetworkReconciler interface {
	// ReconcileStartup reconciles durable node network state (lo0 aliases)
	// with the adapter's allocator before any pod is created.
	ReconcileStartup(ctx context.Context) error
}

// reconcileNetworkStartup runs the network's optional startup reconcile exactly
// once (see NetworkReconciler). A Network that does not implement the seam is a
// nil hook: the call is a no-op returning nil. The first result is sticky — a
// failed reconcile keeps failing every Serve rather than serving CreatePod over
// an inconsistent alias table (fail closed).
func (r *Runtime) reconcileNetworkStartup(ctx context.Context) error {
	r.netReconcileOnce.Do(func() {
		nr, ok := r.network.(NetworkReconciler)
		if !ok {
			return
		}
		r.log.Info("reconciling pod network startup state")
		r.netReconcileErr = nr.ReconcileStartup(ctx)
	})
	return r.netReconcileErr
}

// Deps are the swappable subsystem seams a Runtime is built from. New fills any
// nil field with its production default (real image puller/signer, the exec-shim
// sandbox backend, posix_spawn/kqueue, single-node network).
type Deps struct {
	Cache   *image.Cache
	Puller  Puller
	Signer  Signer
	Backend sandbox.Backend
	// VMBackend is the Virtualization.framework micro-VM backend (M5.1). Defaults
	// to sandbox.NewVMBackend(), whose Available() is false unless the host has
	// Virtualization.framework + the com.apple.security.virtualization entitlement
	// (so a vm-requested pod fails closed off a capable host). Tests inject a fake.
	VMBackend VMBackend
	Spawner   supervisor.Spawner
	Waiter    supervisor.ExitWaiter
	Network   supervisor.PodNetwork
	// Resolver supplies ConfigMap/Secret data and SA tokens for volume
	// materialization (M2.2). It has NO production default: runtimed never talks
	// to the apiserver, so the provider (k3sm) wires one backed by its apiserver
	// client. A pod with a data-backed volume and no Resolver fails closed.
	Resolver mount.Resolver
	// Credentials resolves imagePullSecret registry credentials (M2.6). Like
	// Resolver it has NO production default (runtimed never reads the apiserver):
	// the provider wires one. nil means anonymous pulls only.
	Credentials CredentialResolver
	// Binder materializes APFS-backed persistent volumes (PVCs) for a pod (M3.1).
	// Defaults to a volume.Binder rooted at <Config.Root>/storage with the default
	// local-path class and empty-create only (no seed template). Tests inject one
	// with a custom class/template; the provider may wire a TemplateResolver.
	Binder *volume.Binder
	// Footprinter samples per-PID memory footprints for the OOM/metering sampler
	// (M2.5). Defaults to supervisor.PhysFootprinter (proc_pid_rusage); tests
	// inject a fake.
	Footprinter supervisor.Footprinter
	// SignalGroup signals a process group (M2.4 graceful stop / M2.5 OOM kill).
	// Defaults to supervisor.SignalGroup; tests inject a recorder.
	SignalGroup func(pgid int, sig os.Signal) error
	// ProcStartTime reports a live process's kernel start time (the leader
	// identity recorded at spawn). Defaults to supervisor.ProcStartTimeNano;
	// tests inject a fake process table.
	ProcStartTime func(pid int) (startUnixNano int64, ok bool)
	// ProcGroup reports a process group's live members (pid + start time — the
	// startup reap's group probe). Defaults to supervisor.ProcGroupMembers; tests
	// inject a fake group table.
	ProcGroup func(pgid int) (members []supervisor.ProcMember, ok bool)
}

// New constructs a Runtime from cfg and deps, filling production defaults for any
// unset dep. It returns an error if a required default cannot be built (e.g. the
// image cache dir).
func New(cfg Config, deps Deps) (*Runtime, error) {
	if cfg.Root == "" {
		cfg.Root = image.DefaultRoot
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	cache := deps.Cache
	if cache == nil {
		c, err := image.NewCache(cfg.Root)
		if err != nil {
			return nil, fmt.Errorf("init image cache: %w", err)
		}
		cache = c
	}
	puller := deps.Puller
	if puller == nil {
		puller = image.NewPuller(cache, nil)
	}
	signer := deps.Signer
	if signer == nil {
		signer = defaultSigner{}
	}
	backend := deps.Backend
	if backend == nil {
		b, err := sandbox.NewExecShimBackend("", cfg.Root)
		if err != nil {
			return nil, fmt.Errorf("init sandbox backend: %w", err)
		}
		backend = b
	}
	vmBackend := deps.VMBackend
	if vmBackend == nil {
		// Available() is false unless this host has Virtualization.framework + the
		// com.apple.security.virtualization entitlement, so a vm-requested pod fails
		// closed off a capable host (and the live boot is the lab-gated remainder).
		vmBackend = sandbox.NewVMBackend()
	}
	spawner := deps.Spawner
	if spawner == nil {
		spawner = supervisor.PosixSpawner{}
	}
	waiter := deps.Waiter
	if waiter == nil {
		waiter = supervisor.KqueueReaper{}
	}
	network := deps.Network
	if network == nil {
		network = supervisor.NodeNetwork{}
	}
	footprinter := deps.Footprinter
	if footprinter == nil {
		footprinter = supervisor.PhysFootprinter{}
	}
	signalGroup := deps.SignalGroup
	if signalGroup == nil {
		signalGroup = supervisor.SignalGroup
	}
	procStart := deps.ProcStartTime
	if procStart == nil {
		procStart = supervisor.ProcStartTimeNano
	}
	procGroup := deps.ProcGroup
	if procGroup == nil {
		procGroup = supervisor.ProcGroupMembers
	}
	binder := deps.Binder
	if binder == nil {
		// The PV storage root is a sibling of the pods root under the runtime root
		// (so it shares the APFS volume but is NOT under the pod dir removePodDir
		// tears down — that is the lifecycle decoupling). With the default
		// Config.Root this is storagev1.DefaultBasePath (/var/lib/k3sm/storage).
		class := storagev1.DefaultLocalPathClass()
		class.BasePath = filepath.Join(cfg.Root, "storage")
		binder = volume.NewBinder(class, image.APFSCloner{}, nil, log)
	}

	return &Runtime{
		cfg:         cfg,
		home:        daemonHome(cfg.Root),
		log:         log,
		cache:       cache,
		puller:      puller,
		signer:      signer,
		credentials: deps.Credentials,
		backend:     backend,
		vmBackend:   vmBackend,
		spawner:     spawner,
		waiter:      waiter,
		network:     network,
		resolver:    deps.Resolver,
		binder:      binder,
		footprinter: footprinter,
		signalGroup: signalGroup,
		procStart:   procStart,
		procGroup:   procGroup,
		broker:      newBroker(),
		pods:        make(map[string]*pod),
	}, nil
}

// sampleInterval is the memory sampler's polling period (Config.SampleInterval,
// default 1s ≈ the ~1 Hz the M2.5 design calls for).
func (r *Runtime) sampleInterval() time.Duration {
	if r.cfg.SampleInterval > 0 {
		return r.cfg.SampleInterval
	}
	return time.Second
}

// defaultDrainGrace bounds the log-drain wait when a leaked/inherited stdout+stderr
// pipe write-end (a forked grandchild that outlives the direct child) defers the
// supervisor pump's EOF indefinitely. It is small: the terminated-status path must
// finalize promptly with whatever tail is buffered, not wedge the pod in Running.
const defaultDrainGrace = 2 * time.Second

// drainGraceDuration is the bounded wait (Runtime.drainGrace, default
// defaultDrainGrace) watchContainerExit gives the log pump to reach EOF before it
// snapshots the terminated container's log tail.
func (r *Runtime) drainGraceDuration() time.Duration {
	if r.drainGrace > 0 {
		return r.drainGrace
	}
	return defaultDrainGrace
}

// defaultSigner is the production Signer backed by the image package's codesign
// tooling and the SignaturePolicy gate.
type defaultSigner struct{}

func (defaultSigner) Sign(ctx context.Context, path string) error {
	return image.AdHocSign(ctx, path)
}

func (defaultSigner) Check(ctx context.Context, policy runtimev1.SignaturePolicy, path string) error {
	return image.CheckSignaturePolicy(ctx, image.CodesignTool{}, policy, path)
}

// nowProto returns the current time as a proto timestamp (indirected for tests).
var nowProto = func() *timestamppb.Timestamp { return timestamppb.New(time.Now()) }

// daemonHome returns the daemon user's home directory when workDir lives under
// it (the unprivileged user-space posture, where the runtime work-dir is inside
// the _k3sm home), enabling the SBPL generator's work-dir containment check
// (sandbox.Posture.Home). It returns "" — disabling the check — when the home
// cannot be determined or workDir is elsewhere (the legacy /var/lib root work-dir
// or a test temp dir), where the generator falls back to its intrinsic work-dir
// sanity check (absolute, clean, not the filesystem root).
func daemonHome(workDir string) string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return ""
	}
	h = filepath.Clean(h)
	wd := filepath.Clean(workDir)
	if wd == h || strings.HasPrefix(wd, h+string(filepath.Separator)) {
		return h
	}
	return ""
}
