package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
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
// fake that never touches a registry.
type Puller interface {
	Pull(ctx context.Context, ref string) (*image.PullResult, error)
}

// Signer ad-hoc signs a pulled binary and gates it against a SignaturePolicy
// before exec. The image package provides both halves; the Runtime consumes them
// as one seam (fakeable in tests).
type Signer interface {
	// Sign ad-hoc signs the Mach-O at path (codesign -s - -f, no hardened
	// runtime) so a later DYLD insert can load.
	Sign(ctx context.Context, path string) error
	// Check enforces policy against path's signature, fail-closed on UNSPECIFIED.
	Check(ctx context.Context, policy runtimev1.SignaturePolicy, path string) error
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
}

// Runtime is the in-process node runtime implementing runtimev1.RuntimeServer.
//
// Concurrency: mu guards pods. Subsystem seams (puller, signer, backend,
// spawner, waiter, network, broker) are set at construction and are themselves
// concurrency-safe. Status changes are published through broker OUTSIDE mu.
type Runtime struct {
	runtimev1.UnimplementedRuntimeServer

	cfg     Config
	log     *slog.Logger
	cache   *image.Cache
	puller  Puller
	signer  Signer
	backend sandbox.Backend
	spawner supervisor.Spawner
	waiter  supervisor.ExitWaiter
	network supervisor.PodNetwork
	broker  *broker

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

	return &Runtime{
		cfg:     cfg,
		log:     log,
		cache:   cache,
		puller:  puller,
		signer:  signer,
		backend: backend,
		spawner: spawner,
		waiter:  waiter,
		network: network,
		broker:  newBroker(),
		pods:    make(map[string]*pod),
	}, nil
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
