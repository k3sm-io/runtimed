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

package mount

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/pathsafe"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// defaultFileMode is the file permission applied to a materialized volume file
// when neither the item mode nor the source default_mode is set (mirrors the
// corev1 default 0644). Credential read-only-ness is enforced by the SBPL
// sub-scope, not these bits.
const defaultFileMode os.FileMode = 0o644

// Layout describes the volumes materialized for one pod: the per-mount roots, and
// which of them are credentials (secrets / SA-token) that must get the SBPL
// read-only sub-scope.
type Layout struct {
	// Mounts is one entry per unique materialized mount path.
	Mounts []Mount
	// State is the refresh state the create-time render leaves behind: which
	// volumes are wholly immutable and when each ServiceAccount token was
	// issued. The caller hands it to the first Refresh.
	State RefreshState
}

// Mount is one materialized volume mount root.
type Mount struct {
	// Name is the Volume/VolumeMount name.
	Name string
	// Path is the absolute host path the volume was materialized at (always under
	// the pod data volume — see the package doc).
	Path string
	// ReadOnly is the effective read-only intent (true for secrets, SA-token, and
	// projected volumes, or when the VolumeMount sets read_only).
	ReadOnly bool
	// Credential marks a secret / SA-token (or a projected volume containing one):
	// it gets the SBPL read-only sub-scope, so the pod cannot write the files
	// at its path (not integrity against the pod: see the package doc).
	Credential bool
}

// CredentialPaths returns the materialized paths that are credentials, sorted —
// the input to sandbox.GenerateOptions.ReadOnlyPaths (the read-only sub-scope).
func (l *Layout) CredentialPaths() []string {
	var out []string
	for _, m := range l.Mounts {
		if m.Credential {
			out = append(out, m.Path)
		}
	}
	sort.Strings(out)
	return out
}

// CredentialPaths returns, without rendering anything, the paths Materialize
// would report as credentials for box under dataVol — exactly what
// Materialize(ctx, box, dataVol, ...).CredentialPaths() returns on success, and
// sorted the same way. It is the pure half of the credential verdict: the same
// walk (planMounts) and the same predicate (credentialSource) the render path
// uses, so a caller that must re-derive a pod's SBPL read-only sub-scope from
// its spec alone (a daemon re-attaching to a pod another run created) gets the
// verdict the create-time render reached, by construction rather than by a
// parallel copy.
func CredentialPaths(box *runtimev1.PodBox, dataVol string) ([]string, error) {
	plans, err := planMounts(box, filepath.Clean(dataVol))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pm := range plans {
		if credentialSource(pm.vol) {
			out = append(out, pm.dest)
		}
	}
	sort.Strings(out)
	return out, nil
}

// credentialSource reports whether vol's source is a credential that gets the
// SBPL read-only sub-scope: a secret, or a projected volume carrying a secret
// or a ServiceAccount token. It is the ONE credential predicate: the render
// (render.volume) reports it and CredentialPaths reads it, so the two cannot
// disagree about which mounts a pod may not overwrite.
func credentialSource(vol *runtimev1.Volume) bool {
	switch {
	case vol.GetSecret() != nil:
		return true
	case vol.GetProjected() != nil:
		for _, p := range vol.GetProjected().GetSources() {
			if p.GetSecret() != nil || p.GetServiceAccountToken() != nil {
				return true
			}
		}
	}
	return false
}

// seenMount is the identity that claimed a rebased destination in the conflict
// guard: the volume name plus its subPath selection (a destination holds exactly
// one selection on k3sm's mount-namespace-free shared tree).
type seenMount struct {
	name    string
	subPath string
}

// mountClass is how a volume mount is materialized, and therefore whether
// Refresh may touch it. It is decided in one place (classify) and read by both
// Materialize and Refresh, so the two cannot disagree about which mounts are
// generation-backed.
type mountClass int

const (
	// classGeneration is a non-subPath configMap / secret / downwardAPI /
	// projected mount: rendered as kubelet atomic-writer generations, and
	// refreshable.
	classGeneration mountClass = iota
	// classSubPath is any mount with a subPath: cloned once at create, never
	// refreshed (kubelet parity: a subPath mount does not receive updates).
	classSubPath
	// classEmptyDir is an emptyDir: a writable directory with nothing to render.
	classEmptyDir
	// classOther is any other source (hostPath, or none this materializer
	// knows). Materialize renders it flat, which refuses it; Refresh skips it.
	classOther
	// classImage is an image volume (an OCI artifact's read-only view), with or
	// without a subPath. Materialize skips it, as it skips a PVC: the view is
	// linked into place by LinkImageVolumes, never rendered into the pod.
	classImage
)

// classify returns vol's mountClass for a mount selecting subPath.
func classify(vol *runtimev1.Volume, subPath string) mountClass {
	switch {
	case vol.GetImage() != nil:
		return classImage
	case subPath != "":
		return classSubPath
	case vol.GetEmptyDir() != nil:
		return classEmptyDir
	case vol.GetConfigMap() != nil, vol.GetSecret() != nil, vol.GetDownwardApi() != nil, vol.GetProjected() != nil:
		return classGeneration
	default:
		return classOther
	}
}

// plannedMount is one de-duplicated volume mount of a pod: the mount, its
// volume, the rebased destination, and its class.
type plannedMount struct {
	mount *runtimev1.VolumeMount
	vol   *runtimev1.Volume
	dest  string
	class mountClass
}

// planMounts walks every container VolumeMount of box (init containers first)
// and returns the mounts to materialize under dataVol, applying the undefined-
// volume check, the escape check, and the destination conflict guard. PVC
// mounts are omitted: pkg/volume binds them. It is the one walk Materialize and
// Refresh share.
func planMounts(box *runtimev1.PodBox, dataVol string) ([]plannedMount, error) {
	volumes := make(map[string]*runtimev1.Volume, len(box.GetVolumes()))
	for _, v := range box.GetVolumes() {
		volumes[v.GetName()] = v
	}

	// conflict guard: rebased destination -> the (volume, subPath) that claimed it.
	// The subPath is part of the identity because k3sm has no mount namespace, so a
	// single on-disk destination can hold exactly one selection.
	seen := make(map[string]seenMount)

	containers := make([]*runtimev1.Container, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	containers = append(containers, box.GetInitContainers()...)
	containers = append(containers, box.GetContainers()...)

	var plans []plannedMount
	for _, c := range containers {
		for _, vm := range c.GetVolumeMounts() {
			vol, ok := volumes[vm.GetName()]
			if !ok {
				return nil, fmt.Errorf("container %s: volume_mount %q references undefined volume", c.GetName(), vm.GetName())
			}
			// PVC sources are durable and lifecycle-decoupled: pkg/volume binds them
			// to a stable dir OUTSIDE the pod tree and symlinks them into the rootfs.
			// They are not materialized (rebased) here.
			if vol.GetPersistentVolumeClaim() != nil {
				continue
			}
			// A hostPath source is a host share: it is never materialized or
			// rebased, because the pod reaches it at its own host path. The
			// runtime decides it against the node's allowlist when it compiles
			// the pod's profile (pkg/hostshare), and a share that is not admitted
			// fails the pod there, before any container starts.
			if vol.GetHostPath() != nil {
				continue
			}
			// An exposure is bound by pkg/volume (BindExposures): a pod-lifetime
			// dir under <data root>/expose, outside the pod tree, that one host
			// account is granted by ACL and the pod reaches through a symlink
			// at its mount path, as a PVC. It is not materialized here.
			if vol.GetExpose() != nil {
				continue
			}
			// The destination is the rebased mount path ONLY — subPath selects a
			// source element (applied at materialization), it is NOT folded into
			// the destination.
			dest, err := resolveTarget(dataVol, vm.GetMountPath())
			if err != nil {
				return nil, fmt.Errorf("volume %s: %w", vm.GetName(), err)
			}
			// The conflict guard keys on the destination (rebased mount path, no
			// subPath): two subPaths of one volume at DIFFERENT mount paths do not
			// false-conflict. A repeat of the SAME (volume, subPath) at the same path
			// de-dups (the same volume mounted into multiple containers). But two
			// mounts that target one destination with DIFFERENT selections — a distinct
			// volume, OR the same volume with a different subPath — cannot both be
			// materialized on the shared tree, so that is a hard error rather than a
			// silent first-wins.
			if prev, dup := seen[dest]; dup {
				if prev.name == vm.GetName() && prev.subPath == vm.GetSubPath() {
					continue // identical selection into multiple containers at one path
				}
				return nil, fmt.Errorf("mounts %q(subPath %q) and %q(subPath %q) both target %q",
					prev.name, prev.subPath, vm.GetName(), vm.GetSubPath(), dest)
			}
			seen[dest] = seenMount{name: vm.GetName(), subPath: vm.GetSubPath()}
			plans = append(plans, plannedMount{mount: vm, vol: vol, dest: dest, class: classify(vol, vm.GetSubPath())})
		}
	}
	return plans, nil
}

// Materialize renders every volume referenced by a container VolumeMount in box
// into the pod's data volume, returning the resulting Layout. dataVol is the pod
// data volume (its rootfs); podIP is the resolved pod IP (for status.podIP
// downward-API projections); r supplies ConfigMap/Secret data and SA tokens.
//
// A non-subPath configMap / secret / downwardAPI / projected mount is written
// in the kubelet atomic-writer layout (see writeGeneration) — the same code path
// Refresh later uses to replace it. A subPath mount is cloned once and never
// refreshed; an emptyDir is an empty directory.
//
// A mount that needs data (configMap / secret / projected-with-data) requires a
// non-nil Resolver; emptyDir and pure-downwardAPI volumes do not. A volume_mount
// that names no PodBox.volume, or whose mount path would escape the data volume,
// is rejected (fail closed). A persistentVolumeClaim mount is SKIPPED here — it is
// durable and lifecycle-decoupled, bound by pkg/volume to a stable dir outside the
// pod tree, not materialized into the pod data volume. An image volume mount is
// skipped too (it takes part in the conflict guard): LinkImageVolumes links its
// read-only view into place.
func Materialize(ctx context.Context, box *runtimev1.PodBox, dataVol, podIP string, r Resolver) (*Layout, error) {
	dataVol = filepath.Clean(dataVol)
	plans, err := planMounts(box, dataVol)
	if err != nil {
		return nil, err
	}

	layout := &Layout{State: RefreshState{Immutable: map[string]bool{}, Tokens: map[string]TokenIssue{}, Mounts: map[string]MountIdentity{}}}
	for _, pm := range plans {
		if pm.class == classImage {
			continue // linked by LinkImageVolumes, never materialized
		}
		// The data volume itself is the daemon's path and is created by path
		// like the pod dir; everything below it is reached from it without
		// following a link (openUnder), which also refuses a data volume that
		// is a symlink. See openAnchor for what that trusts: a profile whose
		// dataVolumePath is the pod dir lets the pod replace the data volume.
		if err := os.MkdirAll(dataVol, 0o755); err != nil {
			return nil, fmt.Errorf("create pod data volume %s: %w", dataVol, err)
		}
		var credential bool
		switch pm.class {
		case classSubPath:
			credential, err = materializeSubPath(ctx, podIP, pm.vol, dataVol, pm.dest, pm.mount.GetSubPath(), box, r)
		case classGeneration:
			// The mount dir is created and opened from the data volume one
			// component at a time without following a link, and refused when
			// a component is a symlink or not a directory: the pod owns every
			// directory below the data volume.
			var dir *dirTarget
			if dir, err = openUnder(dataVol, pm.dest, true); err != nil {
				err = fmt.Errorf("create mount dir %s: %w", pm.dest, err)
				break
			}
			rd := newRender(box, podIP, r, time.Now, pm.dest, nil)
			credential, _, err = rd.generation(ctx, pm, dir)
			dir.close()
			if err == nil {
				layout.State.record(pm, rd)
			}
		default:
			var dir *dirTarget
			if dir, err = openUnder(dataVol, pm.dest, true); err != nil {
				err = fmt.Errorf("create mount dir %s: %w", pm.dest, err)
				break
			}
			credential, err = newRender(box, podIP, r, time.Now, "", nil).volume(ctx, pm.vol, dir)
			dir.close()
		}
		if err != nil {
			return nil, fmt.Errorf("materialize volume %s: %w", pm.mount.GetName(), err)
		}
		layout.Mounts = append(layout.Mounts, Mount{
			Name:       pm.mount.GetName(),
			Path:       pm.dest,
			ReadOnly:   pm.mount.GetReadOnly() || credential || pm.vol.GetProjected() != nil,
			Credential: credential,
		})
	}
	return layout, nil
}

// resolveTarget rebases mountPath under dataVol, returning the container-visible
// destination. Because k3sm has no mount namespace, an absolute mountPath like
// "/etc/config" is interpreted relative to the pod data volume, not the host root.
// A path that would escape dataVol (via "..") is rejected. subPath is deliberately
// NOT folded in here: a subPath selects an element of the source (see
// materializeSubPath), it does not change the destination level.
func resolveTarget(dataVol, mountPath string) (string, error) {
	if mountPath == "" {
		return "", errors.New("mount_path is empty")
	}
	target := filepath.Join(dataVol, mountPath)
	if !isUnder(target, dataVol) {
		return "", fmt.Errorf("mount_path %q escapes the pod data volume", mountPath)
	}
	return target, nil
}

// render carries what rendering one volume needs, and collects what the render
// learned: whether every fetched source was immutable, and the ServiceAccount
// tokens it minted or reused. One render renders one volume once.
type render struct {
	ns    string
	podIP string
	box   *runtimev1.PodBox
	r     Resolver
	now   func() time.Time

	// tokenBase is the mount dir token records are keyed under ("" for a flat
	// render, which records nothing). prev is the previous records; live the
	// volume's current generation dir, open, set by generation() (nil when
	// there is none). A token whose record is still fresh is re-read from live
	// instead of re-minted.
	tokenBase string
	prev      map[string]TokenIssue
	live      *dirTarget

	// expect is the mount's identity the previous render left (nil at create
	// or after a daemon restart); identity is the one this render leaves.
	expect   *MountIdentity
	identity MountIdentity

	// fetched / allImmutable: at least one ConfigMap/Secret was fetched, and
	// every one fetched reported Immutable. volatile: the volume has a token or
	// downward-API source, whose content can change regardless.
	fetched      bool
	allImmutable bool
	volatile     bool
	tokens       map[string]TokenIssue
}

// newRender returns a render for one volume of box.
func newRender(box *runtimev1.PodBox, podIP string, r Resolver, now func() time.Time, tokenBase string, prev map[string]TokenIssue) *render {
	return &render{
		ns:           box.GetNamespace(),
		podIP:        podIP,
		box:          box,
		r:            r,
		now:          now,
		tokenBase:    tokenBase,
		prev:         prev,
		allImmutable: true,
		tokens:       map[string]TokenIssue{},
	}
}

// immutable reports whether the rendered volume may be skipped by later
// refreshes: it fetched ConfigMap/Secret data, all of it immutable, and has no
// token or downward-API source.
func (rd *render) immutable() bool {
	return rd.fetched && rd.allImmutable && !rd.volatile
}

// generation renders pm's volume as a new atomic-writer generation in dir (the
// open mount dir pm.dest) and flips to it (writeGeneration), returning whether
// the volume is a credential and whether the flip happened (false: the content
// equalled the live generation, which is kept).
func (rd *render) generation(ctx context.Context, pm plannedMount, dir *dirTarget) (credential, flipped bool, err error) {
	flipped, rd.identity, err = writeGeneration(dir, rd.expect, func(gen, live *dirTarget) error {
		rd.live = live
		var rerr error
		credential, rerr = rd.volume(ctx, pm.vol, gen)
		return rerr
	})
	return credential, flipped, err
}

// volume writes vol's single source into target, an open directory, returning
// whether the volume is a credential (credentialSource: secret /
// projected-with-secret-or-token).
func (rd *render) volume(ctx context.Context, vol *runtimev1.Volume, target *dirTarget) (credential bool, err error) {
	credential = credentialSource(vol)
	switch {
	case vol.GetConfigMap() != nil:
		return credential, rd.configMap(ctx, vol.GetConfigMap(), target)
	case vol.GetSecret() != nil:
		return credential, rd.secret(ctx, vol.GetSecret(), target)
	case vol.GetEmptyDir() != nil:
		// Medium is deliberately not read here: this path is disk-backed
		// unconditionally, and a non-empty medium (e.g. Memory) is refused
		// earlier, at pkg/runtime's createPod (keyed on the resolved sandbox
		// backend), before materialization runs.
		return credential, nil // an empty writable dir is the whole job
	case vol.GetDownwardApi() != nil:
		rd.volatile = true
		return credential, renderDownwardAPI(vol.GetDownwardApi(), target, rd.box, rd.podIP)
	case vol.GetProjected() != nil:
		return credential, rd.projected(ctx, vol.GetProjected(), target)
	default:
		return false, fmt.Errorf("volume %s has no recognized source", vol.GetName())
	}
}

// materializeSubPath implements k8s subPath semantics: the container's mount path
// exposes ONLY the volume's <subPath> element (a single file or subdirectory
// WITHIN the volume), never the whole volume. It renders vol's full source into a
// STAGING directory OUTSIDE the pod's readable data volume (a sibling of dataVol),
// selects <staging>/<subPath>, CoW-clones ONLY that element into dest (the rebased
// mount path), then removes the staging dir — so no un-selected sibling (e.g. the
// other ConfigMap/Secret keys) is ever left readable under dataVol. Returns whether
// the source is a credential (so dest still gets the SBPL read-only sub-scope).
// The staging render is flat (no atomic-writer generations): a subPath mount is
// cloned once and never refreshed.
//
// subPath is CVE-2021-25741 class, so the selection is guarded twice: a lexical
// isUnder check (rejects a ".."-heavy subPath after Clean) and a symlink-safe
// EvalSymlinks + re-check (rejects an in-volume symlink pointing outside the
// volume root). A subPath naming a non-existent element fails closed, except for an
// emptyDir, whose missing subPath directory is created (kubelet parity for a
// writable ephemeral volume). The file-vs-dir branch below is load-bearing: a
// blanket MkdirAll(dest) for a file element would make the workload's open(2) hit
// EISDIR.
func materializeSubPath(ctx context.Context, podIP string, vol *runtimev1.Volume, dataVol, dest, subPath string, box *runtimev1.PodBox, r Resolver) (credential bool, err error) {
	// Stage OUTSIDE dataVol (a sibling of the pod data volume) so no un-selected
	// sibling element is ever readable under the pod tree, and on the same volume so
	// the clone into dest is CoW. Removed unconditionally afterwards.
	staging, err := os.MkdirTemp(filepath.Dir(dataVol), ".k3sm-subpath-*")
	if err != nil {
		return false, fmt.Errorf("create subPath staging dir: %w", err)
	}
	defer func() {
		if rmErr := os.RemoveAll(staging); rmErr != nil && err == nil {
			err = fmt.Errorf("remove subPath staging dir %s: %w", staging, rmErr)
		}
	}()

	stage, err := openAnchor(staging)
	if err != nil {
		return false, fmt.Errorf("open subPath staging dir: %w", err)
	}
	credential, err = newRender(box, podIP, r, time.Now, "", nil).volume(ctx, vol, stage)
	stage.close()
	if err != nil {
		return credential, err
	}

	// Source-side lexical guard: the selection must stay within the volume root.
	sel := filepath.Join(staging, subPath)
	if !isUnder(sel, staging) {
		return credential, fmt.Errorf("sub_path %q escapes the volume", subPath)
	}

	if _, statErr := os.Lstat(sel); errors.Is(statErr, os.ErrNotExist) {
		// A missing subPath fails closed, except for an emptyDir: kubelet creates a
		// missing subPath directory in a writable ephemeral volume.
		if vol.GetEmptyDir() == nil {
			return credential, fmt.Errorf("sub_path %q not found in volume", subPath)
		}
		if mkErr := os.MkdirAll(sel, 0o755); mkErr != nil {
			return credential, fmt.Errorf("create emptyDir sub_path %q: %w", subPath, mkErr)
		}
	} else if statErr != nil {
		return credential, fmt.Errorf("lstat sub_path %q: %w", subPath, statErr)
	}

	// Symlink-safe defense-in-depth: resolve any symlink and re-check containment so
	// an in-volume symlink cannot redirect the selection outside the volume root.
	// The staging root is resolved too (its parent may itself traverse a symlink,
	// e.g. macOS /var -> /private/var) so the comparison is resolved-vs-resolved.
	// (Materialize runs once, up front, before any container can write a symlink into
	// an emptyDir — no restart path re-invokes it — so this is cheap insurance today.)
	stagingResolved, evalErr := filepath.EvalSymlinks(staging)
	if evalErr != nil {
		return credential, fmt.Errorf("resolve staging dir: %w", evalErr)
	}
	resolved, evalErr := filepath.EvalSymlinks(sel)
	if evalErr != nil {
		return credential, fmt.Errorf("resolve sub_path %q: %w", subPath, evalErr)
	}
	if !isUnder(resolved, stagingResolved) {
		return credential, fmt.Errorf("sub_path %q resolves outside the volume", subPath)
	}
	kind, statErr := os.Stat(resolved)
	if statErr != nil {
		return credential, fmt.Errorf("stat sub_path %q: %w", subPath, statErr)
	}

	// Destination-side branch on element kind. A DIR element is the mount path's
	// tree (MaterializeTree); a FILE element IS the mount path (clone the file only,
	// after creating its parent) — never MkdirAll(dest) for a file (that is EISDIR).
	//
	// The selection is copied through descriptors at both ends: the staged
	// element is opened in the daemon-owned staging dir, the destination's
	// directories are created and opened from the data volume one component at
	// a time without following a link (a component that is a symlink or not a
	// directory is refused), and each file is cloned with clonefileat(2) and
	// CLONE_NOFOLLOW relative to the destination's descriptor (byte-copied
	// through descriptors where APFS cannot clone). A directory selection
	// holds regular files and directories only: anything else in it is
	// refused (cloneTreeAt), the CVE-2021-25741 class, since a symlink would
	// resolve against the host root at runtime (k3sm has no mount namespace).
	if kind.IsDir() {
		if err := cloneTreeAt(dataVol, resolved, dest); err != nil {
			return credential, fmt.Errorf("materialize sub_path dir %q: %w", subPath, err)
		}
		return credential, nil
	}
	if err := cloneFileTo(dataVol, resolved, dest); err != nil {
		return credential, fmt.Errorf("clone sub_path file %q: %w", subPath, err)
	}
	return credential, nil
}

// cloneFileTo copies the staged regular file src to dest under dataVol. src's
// directory is the daemon's own staging dir; dest's parent is reached from
// dataVol without following a link, and dest must not exist.
func cloneFileTo(dataVol, src, dest string) error {
	sp, err := openAnchor(filepath.Dir(src))
	if err != nil {
		return err
	}
	defer sp.close()
	dp, err := openUnder(dataVol, filepath.Dir(dest), true)
	if err != nil {
		return fmt.Errorf("create sub_path parent %s: %w", filepath.Dir(dest), err)
	}
	defer dp.close()
	return cloneFileAt(sp.fd, filepath.Base(src), dp.fd, filepath.Base(dest))
}

// cloneTreeAt copies the staged directory src into dest under dataVol, keeping
// its structure and modes. dest and every directory below it are reached from
// dataVol without following a link; a file already at a destination name is
// left in place (as image.MaterializeTree leaves it), and src may hold only
// regular files and directories.
func cloneTreeAt(dataVol, src, dest string) error {
	st, err := openAnchor(src)
	if err != nil {
		return err
	}
	defer st.close()
	dt, err := openUnder(dataVol, dest, true)
	if err != nil {
		return fmt.Errorf("create sub_path mount dir %s: %w", dest, err)
	}
	defer dt.close()
	return walkAt(st, func(rel string, sst *unix.Stat_t, parent int, name string) error {
		switch uint32(sst.Mode) & unix.S_IFMT {
		case unix.S_IFDIR:
			fd, err := pathsafe.OpenDirFrom(dt.fd, dt.path, rel, true, uint32(sst.Mode)&0o777|0o100)
			if err != nil {
				return err
			}
			unix.Close(fd)
			return nil
		case unix.S_IFREG:
			pfd, err := pathsafe.OpenDirFrom(dt.fd, dt.path, filepath.Dir(rel), false, 0)
			if err != nil {
				return err
			}
			defer unix.Close(pfd)
			var dst unix.Stat_t
			if unix.Fstatat(pfd, name, &dst, unix.AT_SYMLINK_NOFOLLOW) == nil {
				return nil // already there: left in place
			}
			return cloneFileAt(parent, name, pfd, name)
		default:
			return fmt.Errorf("sub_path entry %q is neither a regular file nor a directory", rel)
		}
	})
}

// cloneFileAt clones the regular file srcName under srcDir to dstName under
// dstDir (which must not exist), never following a link at either end, and
// byte-copies through descriptors where the volumes cannot clone.
func cloneFileAt(srcDir int, srcName string, dstDir int, dstName string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(srcDir, srcName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s is not a regular file", srcName)
	}
	err := clonefileAt(srcDir, srcName, dstDir, dstName)
	if err == nil || !image.IsCloneUnsupported(err) {
		return err
	}
	in, err := unix.Openat(srcDir, srcName, unix.O_RDONLY|fileOpenFlags, 0)
	if err != nil {
		return err
	}
	inf := os.NewFile(uintptr(in), srcName)
	defer inf.Close()
	out, err := unix.Openat(dstDir, dstName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|fileOpenFlags, 0o600)
	if err != nil {
		return err
	}
	outf := os.NewFile(uintptr(out), dstName)
	defer outf.Close()
	if _, err := io.Copy(outf, inf); err != nil {
		return err
	}
	return unix.Fchmod(out, uint32(st.Mode)&0o7777)
}

// configMap writes a ConfigMap's keys as files under target.
func (rd *render) configMap(ctx context.Context, src *runtimev1.ConfigMapVolumeSource, target *dirTarget) error {
	data, err := rd.fetchConfigMap(ctx, src.GetName(), src.GetOptional())
	if err != nil {
		return err
	}
	return writeKeyed(target, data, src.GetItems(), modeOr(src.GetDefaultMode()), src.GetOptional())
}

// secret writes a Secret's keys as files under target (read-only sub-scope
// applied SBPL-side by the caller).
func (rd *render) secret(ctx context.Context, src *runtimev1.SecretVolumeSource, target *dirTarget) error {
	data, err := rd.fetchSecret(ctx, src.GetSecretName(), src.GetOptional())
	if err != nil {
		return err
	}
	return writeKeyed(target, data, src.GetItems(), modeOr(src.GetDefaultMode()), src.GetOptional())
}

// renderEmptyDir is a no-op beyond the MkdirAll the caller already did.

// renderDownwardAPI writes each downward-API field projection as a file.
func renderDownwardAPI(src *runtimev1.DownwardAPIVolumeSource, target *dirTarget, box *runtimev1.PodBox, podIP string) error {
	dflt := modeOr(src.GetDefaultMode())
	for _, item := range src.GetItems() {
		val, err := resolveDownwardField(box, podIP, item.GetFieldRef().GetFieldPath())
		if err != nil {
			return err
		}
		mode := dflt
		if m := item.GetMode(); m != 0 {
			mode = os.FileMode(m)
		}
		if err := writeFile(target, item.GetPath(), []byte(val), mode); err != nil {
			return err
		}
	}
	return nil
}

// projected layers each projection source into the same target dir. Whether
// the volume is a credential is credentialSource's verdict, not this walk's.
func (rd *render) projected(ctx context.Context, src *runtimev1.ProjectedVolumeSource, target *dirTarget) error {
	dflt := modeOr(src.GetDefaultMode())
	for _, p := range src.GetSources() {
		switch {
		case p.GetConfigMap() != nil:
			cm := p.GetConfigMap()
			data, err := rd.fetchConfigMap(ctx, cm.GetName(), cm.GetOptional())
			if err != nil {
				return err
			}
			if err := writeKeyed(target, data, cm.GetItems(), dflt, cm.GetOptional()); err != nil {
				return err
			}
		case p.GetSecret() != nil:
			sec := p.GetSecret()
			data, err := rd.fetchSecret(ctx, sec.GetName(), sec.GetOptional())
			if err != nil {
				return err
			}
			if err := writeKeyed(target, data, sec.GetItems(), dflt, sec.GetOptional()); err != nil {
				return err
			}
		case p.GetDownwardApi() != nil:
			rd.volatile = true
			for _, item := range p.GetDownwardApi().GetItems() {
				val, err := resolveDownwardField(rd.box, rd.podIP, item.GetFieldRef().GetFieldPath())
				if err != nil {
					return err
				}
				mode := dflt
				if m := item.GetMode(); m != 0 {
					mode = os.FileMode(m)
				}
				if err := writeFile(target, item.GetPath(), []byte(val), mode); err != nil {
					return err
				}
			}
		case p.GetServiceAccountToken() != nil:
			if err := rd.token(ctx, p.GetServiceAccountToken(), dflt, target); err != nil {
				return err
			}
		}
	}
	return nil
}

// token writes a ServiceAccount token projection. A token whose issuance
// record (rd.prev) still has at least 20% of its lifetime left is re-read from
// the live generation rather than re-minted (the kubelet token manager's rule);
// any other — no record, a record past 80% of its lifetime, or a live file that
// cannot be read — is minted fresh and recorded.
func (rd *render) token(ctx context.Context, sat *runtimev1.ServiceAccountTokenProjection, mode os.FileMode, target *dirTarget) error {
	rd.volatile = true
	if rd.r == nil {
		return errNoResolver
	}
	var key string
	if rd.tokenBase != "" {
		key = filepath.Join(rd.tokenBase, sat.GetPath())
	}
	now := rd.now()
	if key != "" && rd.live != nil {
		if iss, ok := rd.prev[key]; ok && !iss.due(now) {
			if b, err := readFileAt(rd.live, sat.GetPath(), maxVolumeBytes); err == nil {
				rd.tokens[key] = iss
				return writeFile(target, sat.GetPath(), b, mode)
			}
		}
	}
	token, err := rd.r.ServiceAccountToken(ctx, rd.ns, sat.GetAudience(), sat.GetExpirationSeconds())
	if err != nil {
		return fmt.Errorf("mint SA token (audience %q): %w", sat.GetAudience(), err)
	}
	if key != "" {
		rd.tokens[key] = TokenIssue{IssuedAt: now, ExpirationSeconds: sat.GetExpirationSeconds()}
	}
	return writeFile(target, sat.GetPath(), []byte(token), mode)
}

// fetchConfigMap resolves a ConfigMap through the Resolver, recording its
// immutability.
func (rd *render) fetchConfigMap(ctx context.Context, name string, optional bool) (map[string][]byte, error) {
	return rd.fetch("configMap", name, optional, func() (SourceData, error) {
		return rd.r.ConfigMap(ctx, rd.ns, name)
	})
}

// fetchSecret resolves a Secret through the Resolver, recording its
// immutability.
func (rd *render) fetchSecret(ctx context.Context, name string, optional bool) (map[string][]byte, error) {
	return rd.fetch("secret", name, optional, func() (SourceData, error) {
		return rd.r.Secret(ctx, rd.ns, name)
	})
}

// fetch runs one ConfigMap/Secret fetch through resolveData and folds its
// immutability into the render. An optional source that is absent counts as
// mutable: it may appear later.
func (rd *render) fetch(kind, name string, optional bool, get func() (SourceData, error)) (map[string][]byte, error) {
	if rd.r == nil {
		return nil, errNoResolver
	}
	src, err := resolveData(kind, rd.ns, name, optional, get)
	if err != nil {
		return nil, err
	}
	rd.fetched = true
	rd.allImmutable = rd.allImmutable && src.Immutable
	return src.Data, nil
}

// errNoResolver reports a data-backed volume source with no Resolver wired.
var errNoResolver = errors.New("no volume Resolver configured (configMap/secret/SA-token require one)")

// resolveData fetches a ConfigMap/Secret's data, honoring optional: a source that
// reports os.ErrNotExist while optional yields empty, mutable data (skip),
// otherwise the error propagates.
func resolveData(kind, ns, name string, optional bool, fetch func() (SourceData, error)) (SourceData, error) {
	src, err := fetch()
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return SourceData{Data: map[string][]byte{}}, nil
		}
		return SourceData{}, fmt.Errorf("%s %s/%s: %w", kind, ns, name, err)
	}
	return src, nil
}

// writeKeyed writes data into target. With items set, only the named keys are
// projected (to their item paths/modes); otherwise every key is written to a file
// of the same name. A selected key absent from data is an error unless optional.
func writeKeyed(target *dirTarget, data map[string][]byte, items []*runtimev1.KeyToPath, dflt os.FileMode, optional bool) error {
	if len(items) > 0 {
		for _, item := range items {
			val, ok := data[item.GetKey()]
			if !ok {
				if optional {
					continue
				}
				return fmt.Errorf("key %q not found", item.GetKey())
			}
			mode := dflt
			if m := item.GetMode(); m != 0 {
				mode = os.FileMode(m)
			}
			if err := writeFile(target, item.GetPath(), val, mode); err != nil {
				return err
			}
		}
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := writeFile(target, k, data[k], dflt); err != nil {
			return err
		}
	}
	return nil
}

// resolveDownwardField resolves a downward-API field path against the PodBox.
// Supported: metadata.name/namespace/uid, status.podIP(s), and
// metadata.labels['k'] / metadata.annotations['k']. Fields the PodBox cannot
// carry (spec.nodeName, status.hostIP, spec.serviceAccountName) resolve to ""
// rather than failing the pod; a genuinely unknown path is an error.
func resolveDownwardField(box *runtimev1.PodBox, podIP, fieldPath string) (string, error) {
	if key, ok := subscript(fieldPath, "metadata.labels"); ok {
		return box.GetLabels()[key], nil
	}
	if key, ok := subscript(fieldPath, "metadata.annotations"); ok {
		return box.GetAnnotations()[key], nil
	}
	switch fieldPath {
	case "metadata.name":
		return box.GetName(), nil
	case "metadata.namespace":
		return box.GetNamespace(), nil
	case "metadata.uid":
		return box.GetPodId(), nil
	case "status.podIP", "status.podIPs":
		return podIP, nil
	case "status.hostIP", "spec.nodeName", "spec.serviceAccountName":
		return "", nil // not carried by PodBox; the provider supplies these via env
	default:
		return "", fmt.Errorf("unsupported downward-API field path %q", fieldPath)
	}
}

// subscript parses a "prefix['key']" downward-API field path, returning the key
// and true when fieldPath has that prefix-with-subscript shape.
func subscript(fieldPath, prefix string) (string, bool) {
	if !strings.HasPrefix(fieldPath, prefix+"[") || !strings.HasSuffix(fieldPath, "]") {
		return "", false
	}
	inner := fieldPath[len(prefix)+1 : len(fieldPath)-1]
	inner = strings.Trim(inner, `'"`)
	return inner, true
}

// modeOr converts a proto mode (0 = unset) to an os.FileMode, defaulting to
// defaultFileMode when unset.
func modeOr(m int32) os.FileMode {
	if m == 0 {
		return defaultFileMode
	}
	return os.FileMode(m)
}

// isUnder reports whether path is base itself or a descendant (both cleaned).
func isUnder(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	return path == base || strings.HasPrefix(path, base+string(filepath.Separator))
}

// IsStrictlyUnder reports whether path is a PROPER descendant of base (both
// cleaned): equality is FALSE — which is exactly why the share-plan containment
// guards cannot reuse isUnder above — and the check is separator-aware, so
// /a/b is under /a but the sibling /a/bc is NOT under /a/b.
func IsStrictlyUnder(path, base string) bool {
	path = filepath.Clean(path)
	base = filepath.Clean(base)
	if base == string(filepath.Separator) {
		return path != base && filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, base+string(filepath.Separator))
}
