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

package volume

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"k3sm.io/runtimed/pkg/image"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// TemplateResolver reports the seed-template source directory for a PVC, if one is
// configured on its StorageClass. It is a consumer-side seam (like
// mount.Resolver): runtimed never reads the apiserver, so the provider — which
// holds the StorageClass — wires one, and tests fake it. A nil TemplateResolver,
// or an ok==false result, means empty-CREATE (the default-class hot path, no
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
// A Binder is safe for concurrent use: os.MkdirAll is idempotent, distinct pods
// bind distinct dirs, and its one piece of mutable state, seedMu, serializes
// template seeds (two pods sharing one (ns,claim) RWX volume share the dir by
// design, and must not seed it twice). seedMu is in-process only: a create by
// another creator outside it (the no-template MkdirAll path) or by a second
// process is handled at the final rename, which reuses the dir that won.
type Binder struct {
	class    storagev1.LocalPathClass
	cloner   image.Cloner
	template TemplateResolver
	log      *slog.Logger
	seedMu   sync.Mutex
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
	// Seeded is true iff this call seeded the dir from a template (first create);
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
// optional per-claim seed source (nil = empty-create only, the default hot path). log
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

// Provision ensures every PVC-backed volume in box has its stable per-claim dir on
// the APFS storage root — empty-created, or SEEDED-once from a template — and
// returns one Binding per PVC volume, with no Links. A box with no PVC volumes
// returns nil.
//
// It is the half of Bind that both pod spines need, and it is separate from the
// linking half because the two spines reach a claim by different mechanisms. The
// host-process spine has no mount namespace, so a confined process reaches the
// claim through a SYMLINK planted in its rootfs (Bind, below). A vm pod reaches
// the same claim through its own virtiofs share device: the share plan already
// roots a k3sm.pvc<i> device at exactly this DataDir, so the guest mounts it
// directly. Planting a symlink for a vm pod would be worse than useless — it would
// land inside <podDir>/rootfs, which is exported to the guest READ-ONLY as the
// image's lower layer, so it would appear in the container's filesystem pointing at
// a host path that does not exist in the guest's namespace.
//
// So the vm spine calls Provision and the host-process spine calls Bind. Neither
// re-derives a claim path: DataDir stays the class's, here, in its one home.
//
// Provision never deletes and never re-seeds. A PV dir is lifecycle-decoupled from
// the pod (ReclaimPolicy Retain), so an existing claim dir is returned untouched
// with its contents intact — which is the whole point of a persistent volume, and
// is asserted rather than assumed (see materialize's reuse branch).
func (b *Binder) Provision(ctx context.Context, box *runtimev1.PodBox) ([]Binding, error) {
	bindings, _, err := b.provision(ctx, box)
	return bindings, err
}

// Plan returns one Binding per PVC-backed volume in box — VolumeName,
// ClaimName, DataDir and ReadOnly — without touching the filesystem: no dir is
// created, stat'ed or seeded, and Seeded and Links are always zero. A box with
// no PVC volumes returns nil.
//
// It is the pure half of Provision and Bind, which call it and then do the I/O,
// so the DataDir a caller derives from the spec alone (a daemon re-deriving a
// pod's SBPL read/write scope after a restart) is the one the bind produced, by
// construction. A claim name the class cannot map to a dir is ErrInvalid.
func (b *Binder) Plan(box *runtimev1.PodBox) ([]Binding, error) {
	var bindings []Binding
	for _, v := range box.GetVolumes() {
		pvc := v.GetPersistentVolumeClaim()
		if pvc == nil {
			continue
		}
		dataDir, err := b.class.DataDir(box.GetNamespace(), pvc.GetClaimName())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		bindings = append(bindings, Binding{
			VolumeName: v.GetName(),
			ClaimName:  pvc.GetClaimName(),
			DataDir:    dataDir,
			ReadOnly:   pvc.GetReadOnly(),
		})
	}
	return bindings, nil
}

// provision materializes each PVC volume's dir once, even when several containers
// mount it, and returns the bindings plus a volume-name index into them. The
// bindings are Plan's; this adds only the I/O.
func (b *Binder) provision(ctx context.Context, box *runtimev1.PodBox) ([]Binding, map[string]int, error) {
	bindings, err := b.Plan(box)
	if err != nil {
		return nil, nil, err
	}
	if len(bindings) == 0 {
		return nil, nil, nil
	}
	byName := make(map[string]int, len(bindings)) // volume name → index into bindings
	for i := range bindings {
		seeded, err := b.materialize(ctx, box.GetNamespace(), bindings[i].ClaimName, bindings[i].DataDir)
		if err != nil {
			return nil, nil, err
		}
		bindings[i].Seeded = seeded
		byName[bindings[i].VolumeName] = i
	}
	return bindings, byName, nil
}

// Bind is Provision plus the host-process spine's linking half: it symlinks each
// container mount of a bound volume into rootfs so the confined pod reaches the
// persistent dir at its mount path. The returned bindings' DataDirs are the SBPL
// read/write scope the caller widens the profile with.
//
// Bind never deletes anything: a PV dir is lifecycle-decoupled from the pod
// (ReclaimPolicy Retain), so a pod restart / delete leaves it intact and the next
// pod that mounts the same claim reuses it. A box with no PVC volumes returns nil.
//
// The vm spine calls Provision instead; see its doc for why a symlink is the wrong
// mechanism there.
func (b *Binder) Bind(ctx context.Context, box *runtimev1.PodBox, rootfs string) ([]Binding, error) {
	rootfs = filepath.Clean(rootfs)

	bindings, byName, err := b.provision(ctx, box)
	if err != nil {
		return nil, err
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

// materialize ensures the stable dir Plan resolved for (namespace, claimName)
// exists: a reuse (dir already present) is left untouched (seed-once); a fresh
// claim is SEEDED-once from a template when one is configured, else
// empty-created (never a clonefile on the empty hot path).
func (b *Binder) materialize(ctx context.Context, namespace, claimName, dataDir string) (seeded bool, err error) {
	if _, statErr := os.Stat(dataDir); statErr == nil {
		return false, nil // reuse: NEVER re-seed (durable, lifecycle-decoupled)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat pv dir %s: %w", dataDir, statErr)
	}

	// Fresh claim. Seed-once from a template if one is configured; the clonefile
	// path is reached only here, never on the empty-PVC hot path.
	if b.template != nil {
		src, ok, terr := b.template.Template(ctx, namespace, claimName)
		if terr != nil {
			return false, fmt.Errorf("resolve seed template for %s/%s: %w", namespace, claimName, terr)
		}
		if ok {
			return b.seed(namespace, claimName, src, dataDir)
		}
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return false, fmt.Errorf("create pv dir %s: %w", dataDir, err)
	}
	b.log.Info("created empty persistent volume", "namespace", namespace, "claim", claimName, "dir", dataDir)
	return false, nil
}

// seed creates dataDir as a whole copy of the template src, or not at all.
// image.MaterializeTree is not all-or-nothing, and a dataDir that exists is
// reused without re-seeding, so seeding straight into dataDir would let a failed
// seed's half-filled dir be reported as bound on the retry. Instead the tree is
// materialized into a sibling staging dir and renamed onto dataDir only after it
// completes; on error the staging dir is removed and dataDir never appears.
//
// The staging name is fixed per claim, so a stale one (left by a crash mid-seed)
// is removed before seeding, and seedMu serializes seeds so two binds of one
// shared claim never interleave in it. The second bind re-checks dataDir under
// the lock and reuses what the first one seeded.
//
// Any dataDir another creator makes during the seed, empty or not, is reused
// (Seeded=false): os.Rename refuses to replace an existing directory (EEXIST)
// even though rename(2) itself would replace an empty one on Darwin.
func (b *Binder) seed(namespace, claimName, src, dataDir string) (seeded bool, err error) {
	b.seedMu.Lock()
	defer b.seedMu.Unlock()

	if _, statErr := os.Stat(dataDir); statErr == nil {
		return false, nil // a concurrent bind of the same claim seeded it first
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("stat pv dir %s: %w", dataDir, statErr)
	}
	if err := os.MkdirAll(filepath.Dir(dataDir), 0o755); err != nil {
		return false, fmt.Errorf("create pv parent %s: %w", filepath.Dir(dataDir), err)
	}
	staging := stagingDir(dataDir)
	if err := os.RemoveAll(staging); err != nil {
		return false, fmt.Errorf("remove stale pv staging dir %s: %w", staging, err)
	}
	if err := os.Mkdir(staging, 0o755); err != nil {
		return false, fmt.Errorf("create pv staging dir %s: %w", staging, err)
	}
	// The deferred cleanup is the single owner of staging removal: it runs on
	// every error and when the rename lost the race (lostRace), so a removal
	// failure is reported once.
	lostRace := false
	defer func() {
		if err != nil || lostRace {
			if rmErr := os.RemoveAll(staging); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("remove pv staging dir %s: %w", staging, rmErr))
			}
		}
	}()
	if _, err := image.MaterializeTree(b.cloner, src, staging); err != nil {
		return false, fmt.Errorf("seed pv %s/%s from %s: %w", namespace, claimName, src, err)
	}
	if err := os.Rename(staging, dataDir); err != nil {
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			// Lost the race to another creator: reuse its dir, never re-seed.
			lostRace = true
			return false, nil
		}
		return false, fmt.Errorf("move seeded pv into place at %s: %w", dataDir, err)
	}
	b.log.Info("seeded persistent volume from template",
		"namespace", namespace, "claim", claimName, "template", src, "dir", dataDir)
	return true, nil
}

// stagingDir is the sibling dir a fresh volume is seeded into before it is
// renamed onto dataDir. It shares dataDir's parent, so the rename is atomic on
// one filesystem, and its leading dot keeps it out of the claim-name space (a
// claim name is a DNS subdomain, which must start with an alphanumeric), so it
// can never collide with another claim's dir.
func stagingDir(dataDir string) string {
	return filepath.Join(filepath.Dir(dataDir), "."+filepath.Base(dataDir)+".seeding")
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
