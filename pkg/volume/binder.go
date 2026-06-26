package volume

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// TemplateResolver reports the seed-template source directory for a PVC, if one is
// configured on its StorageClass. It is a consumer-side seam (like
// mount.Resolver): runtimed never reads the apiserver, so the provider — which
// holds the StorageClass — wires one, and tests fake it. A nil TemplateResolver,
// or an ok==false result, means EMPTY-CREATE (the M3 default-class hot path, no
// clonefile). The returned dir is a host path cloned (CoW) into the fresh PVC dir
// exactly once, on first create.
type TemplateResolver interface {
	// Template returns the seed-source dir for namespace/claimName, or ok=false
	// when the claim's class has no template (empty-create).
	Template(ctx context.Context, namespace, claimName string) (dir string, ok bool, err error)
}

// Binder materializes a pod's PVC-backed volumes as stable, lifecycle-decoupled
// dirs on the APFS storage root and links them into the pod rootfs. It holds the
// local-path class (its BasePath is the storage root), a Cloner used only to seed
// from a template, an optional TemplateResolver, and a logger.
//
// A Binder is safe for concurrent use: it owns no mutable state (os.MkdirAll and
// the seed clone are idempotent, and distinct pods bind distinct dirs; two pods
// sharing one (ns,claim) RWX volume share the dir by design).
type Binder struct {
	class    storagev1.LocalPathClass
	cloner   image.Cloner
	template TemplateResolver
	log      *slog.Logger
}

// Binding is one PVC bound for a pod.
type Binding struct {
	// VolumeName is the PodBox Volume.name the binding satisfies.
	VolumeName string
	// ClaimName is the PersistentVolumeClaim name (in the pod's namespace).
	ClaimName string
	// DataDir is the stable on-APFS dir (storagev1 DataDir) the claim resolves to.
	// It lives outside the pod tree and SURVIVES pod teardown (Retain). It is the
	// path the caller adds to the pod's SBPL read/write scope.
	DataDir string
	// ReadOnly is the claim's read-only intent: the dir gets a read-only SBPL scope
	// (no write allow) rather than read+write.
	ReadOnly bool
	// Seeded is true iff THIS call seeded the dir from a template (first create);
	// false on empty-create and on every reuse (seed-once).
	Seeded bool
	// Links are the symlink paths created inside the pod rootfs (one per container
	// mount of the volume) that point at DataDir, so the confined pod reaches the
	// persistent dir at its mount path.
	Links []string
}

// ErrInvalid reports a PVC binding that cannot be materialized (a mount path that
// escapes the pod rootfs, a missing claim name, or a non-PVC path conflict). Wrap
// it with %w; test for it with errors.Is.
var ErrInvalid = errors.New("volume: invalid persistent-volume binding")

// NewBinder constructs a Binder. class carries the APFS storage root (BasePath);
// it is defaulted via WithDefaults so a zero-value BasePath falls back to
// storagev1.DefaultBasePath. cloner CoW-seeds from a template (image.APFSCloner in
// production); a nil cloner defaults to image.APFSCloner. template resolves the
// optional per-claim seed source (nil = empty-create only, the M3 hot path). log
// may be nil (a discard logger is used).
func NewBinder(class storagev1.LocalPathClass, cloner image.Cloner, template TemplateResolver, log *slog.Logger) *Binder {
	if cloner == nil {
		cloner = image.APFSCloner{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Binder{
		class:    class.WithDefaults(),
		cloner:   cloner,
		template: template,
		log:      log,
	}
}

// Class returns the binder's resolved local-path class (BasePath defaulted).
func (b *Binder) Class() storagev1.LocalPathClass { return b.class }

// Bind ensures every PVC-backed volume in box has its stable per-claim dir on the
// APFS storage root — EMPTY-CREATED, or SEEDED-once from a template — and symlinks
// each container mount of it into rootfs so the confined pod reaches the persistent
// dir at its mount path. The returned bindings' DataDirs are the SBPL read/write
// scope the caller widens the profile with.
//
// Bind NEVER deletes anything: a PV dir is lifecycle-decoupled from the pod
// (ReclaimPolicy Retain), so a pod restart / delete leaves it intact and the next
// pod that mounts the same claim reuses it. A box with no PVC volumes returns nil.
func (b *Binder) Bind(ctx context.Context, box *runtimev1.PodBox, rootfs string) ([]Binding, error) {
	rootfs = filepath.Clean(rootfs)

	// Index the PVC volumes (name → source) and bind each to its stable dir once,
	// even if mounted by several containers.
	bindings := make([]Binding, 0)
	byName := make(map[string]int) // volume name → index into bindings
	for _, v := range box.GetVolumes() {
		pvc := v.GetPersistentVolumeClaim()
		if pvc == nil {
			continue
		}
		dataDir, seeded, err := b.materialize(ctx, box.GetNamespace(), pvc.GetClaimName())
		if err != nil {
			return nil, err
		}
		byName[v.GetName()] = len(bindings)
		bindings = append(bindings, Binding{
			VolumeName: v.GetName(),
			ClaimName:  pvc.GetClaimName(),
			DataDir:    dataDir,
			ReadOnly:   pvc.GetReadOnly(),
			Seeded:     seeded,
		})
	}
	if len(bindings) == 0 {
		return nil, nil
	}

	// Link each container mount of a bound volume into the pod rootfs.
	containers := make([]*runtimev1.Container, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	containers = append(containers, box.GetInitContainers()...)
	containers = append(containers, box.GetContainers()...)
	for _, c := range containers {
		for _, vm := range c.GetVolumeMounts() {
			idx, ok := byName[vm.GetName()]
			if !ok {
				continue // not a PVC mount (configMap/secret/etc. handled by pkg/mount)
			}
			link, err := b.linkInto(rootfs, vm.GetMountPath(), vm.GetSubPath(), bindings[idx].DataDir)
			if err != nil {
				return nil, fmt.Errorf("link pvc %q into pod: %w", vm.GetName(), err)
			}
			bindings[idx].Links = append(bindings[idx].Links, link)
		}
	}
	return bindings, nil
}

// materialize resolves the stable dir for (namespace, claimName) and ensures it
// exists: a reuse (dir already present) is returned untouched (seed-once); a fresh
// claim is SEEDED-once from a template when one is configured, else EMPTY-CREATED
// (never a clonefile on the empty hot path).
func (b *Binder) materialize(ctx context.Context, namespace, claimName string) (dataDir string, seeded bool, err error) {
	dataDir, err = b.class.DataDir(namespace, claimName)
	if err != nil {
		return "", false, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, statErr := os.Stat(dataDir); statErr == nil {
		return dataDir, false, nil // reuse: NEVER re-seed (durable, lifecycle-decoupled)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", false, fmt.Errorf("stat pv dir %s: %w", dataDir, statErr)
	}

	// Fresh claim. Seed-once from a template if one is configured; the clonefile
	// path is reached ONLY here, never on the empty-PVC hot path.
	if b.template != nil {
		src, ok, terr := b.template.Template(ctx, namespace, claimName)
		if terr != nil {
			return "", false, fmt.Errorf("resolve seed template for %s/%s: %w", namespace, claimName, terr)
		}
		if ok {
			if err := os.MkdirAll(dataDir, 0o755); err != nil {
				return "", false, fmt.Errorf("create pv dir %s: %w", dataDir, err)
			}
			if _, err := image.MaterializeTree(b.cloner, src, dataDir); err != nil {
				return "", false, fmt.Errorf("seed pv %s/%s from %s: %w", namespace, claimName, src, err)
			}
			b.log.Info("seeded persistent volume from template",
				"namespace", namespace, "claim", claimName, "template", src, "dir", dataDir)
			return dataDir, true, nil
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", false, fmt.Errorf("create pv dir %s: %w", dataDir, err)
	}
	b.log.Info("created empty persistent volume", "namespace", namespace, "claim", claimName, "dir", dataDir)
	return dataDir, false, nil
}

// linkInto creates a symlink at the pod's (rebased) mount path that points to
// dataDir. Because k3sm has no mount namespace, an absolute mountPath is
// interpreted relative to the pod rootfs (mirroring pkg/mount); a path that would
// escape the rootfs is rejected. A pre-existing symlink at the target is replaced
// (idempotent re-bind); a pre-existing real file/dir is a conflict (fail closed).
func (b *Binder) linkInto(rootfs, mountPath, subPath, dataDir string) (string, error) {
	if strings.TrimSpace(mountPath) == "" {
		return "", fmt.Errorf("%w: empty mount path", ErrInvalid)
	}
	target := filepath.Join(rootfs, mountPath, subPath)
	if !isUnder(target, rootfs) {
		return "", fmt.Errorf("%w: mount path %q escapes the pod rootfs", ErrInvalid, filepath.Join(mountPath, subPath))
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("create mount parent %s: %w", filepath.Dir(target), err)
	}
	if fi, lerr := os.Lstat(target); lerr == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return "", fmt.Errorf("%w: %q already exists and is not a symlink", ErrInvalid, target)
		}
		if err := os.Remove(target); err != nil { // stale link (ephemeral, in the pod dir)
			return "", fmt.Errorf("replace stale pv link %s: %w", target, err)
		}
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return "", fmt.Errorf("lstat pv link %s: %w", target, lerr)
	}
	if err := os.Symlink(dataDir, target); err != nil {
		return "", fmt.Errorf("symlink %s -> %s: %w", target, dataDir, err)
	}
	return target, nil
}

// isUnder reports whether path is base or a descendant of it (both cleaned).
func isUnder(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}
