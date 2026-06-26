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
type Puller interface {
	Pull(ctx context.Context, ref string, cred *image.RegistryCredential) (*image.PullResult, error)
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

	mu   sync.Mutex
	pods map[string]*pod
}

// Deps are the swappable subsystem seams a Runtime is built from. New fills any
// nil field with its production default (real image puller/signer, the exec-shim
// sandbox backend, posix_spawn/kqueue, single-node network).
type Deps struct {
	Cache   *image.Cache
	Puller  Puller
	Signer  Signer
	Backend sandbox.Backend
	Spawner supervisor.Spawner
	Waiter  supervisor.ExitWaiter
	Network supervisor.PodNetwork
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
		spawner:     spawner,
		waiter:      waiter,
		network:     network,
		resolver:    deps.Resolver,
		binder:      binder,
		footprinter: footprinter,
		signalGroup: signalGroup,
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
