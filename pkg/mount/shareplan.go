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
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// Virtiofs mount tags for the pooled shares of a vm-RuntimeClass pod's plan.
// VZ limits a virtiofs tag to 36 bytes, so tags are short fixed
// strings — never derived from user-supplied names (a PVC share is tagged by
// INDEX, ShareTagPVCPrefix+i, precisely so a claim name can never overflow or
// collide a tag).
const (
	// ShareTagRootfs is the pod rootfs share: read-only, and in this build the
	// single lower layer of the guest root. The multi-lower extension (one
	// share per OCI layer) is not built here.
	ShareTagRootfs = "k3sm.rootfs"
	// ShareTagProj is the read-only pooled share for the projected-class
	// volumes (configMap / secret / projected / downwardAPI), one subdir per
	// volume name.
	ShareTagProj = "k3sm.proj"
	// ShareTagVols is the writable pooled share for default-medium emptyDir
	// volumes, one subdir per volume name.
	ShareTagVols = "k3sm.vols"
	// ShareTagPVCPrefix prefixes the per-PVC share tags: "k3sm.pvc<i>" with i
	// the volume's index in sorted-volume-name order among the pod's PVC
	// volumes.
	ShareTagPVCPrefix = "k3sm.pvc"
)

// vmRootfsDirName / vmProjDirName / vmVolsDirName are the fixed on-disk
// directory names under the pod dir that the pod-dir shares export.
// vmRootfsDirName must stay the "rootfs" component of image.Cache.PodRootfs
// (podDir is its Dir, so Join(podDir, vmRootfsDirName) re-derives the same
// path). proj/vols coincide with their tags today but are separate constants:
// the tag is the guest-visible contract, the dir name the host-disk one.
// vmPodsDirName must stay the "pods" component of the same Cache layout
// (<workRoot>/pods/<podID>/rootfs): guardShareRoots bounds every planned
// podDir to sit strictly inside <workRoot>/pods, so a drift between this
// constant and the cache layout would reject every vm pod (fail closed, loud).
const (
	vmRootfsDirName = "rootfs"
	vmProjDirName   = "k3sm.proj"
	vmVolsDirName   = "k3sm.vols"
	vmPodsDirName   = "pods"
)

// emptyDirMediumMemory is the single non-default value of the closed emptyDir
// medium set ("" → a vols-share bind, "Memory" → guest tmpfs); any other value
// is rejected, never approximated.
const emptyDirMediumMemory = "Memory"

// SharePlan is the virtiofs share-device plan computed for a vm-RuntimeClass
// pod's volumes: which host directories become VZ shared-directory devices
// (Shares), how each container's declared volumeMounts bind into those shares
// (Binds), and which mounts are guest-RAM tmpfs instead (Tmpfs). It is pure
// DATA — ComputeSharePlan touches no filesystem and chowns nothing (the d5
// no-chown rule: the planner plans, ownership is never its job). Enforcement
// of a share's writability is the VZ device config the lab-gated boot builds,
// and composition of the binds/tmpfs is guest-init; neither happens in
// this build (see the sandbox.VMShare / sandbox.VMBind docs the plan is mapped
// onto).
type SharePlan struct {
	// Shares are the virtiofs share devices in deterministic order: rootfs,
	// proj, vols (each of the pooled shares emitted only when a declared
	// volume of its class exists; rootfs always), then one share per PVC
	// volume in sorted-volume-name order.
	Shares []Share
	// Binds are the per-container share-backed binds, keyed by CONTAINER NAME
	// (init and main containers alike, each container's own declared
	// volumeMounts only — never a pod-wide union). A container with no
	// share-backed mount has no entry.
	Binds map[string][]Bind
	// Tmpfs are the per-container Memory-medium emptyDir mounts, keyed by
	// container name.
	Tmpfs map[string][]Tmpfs
}

// Share is one virtiofs share device: the host directory Root exported into
// the guest under Tag. The Writable field polarity makes the zero value
// READ-only (fail-closed); its enforcement point is the VZ device config, not
// anything in this build (see sandbox.VMShare, the DTO this maps onto, for the
// full enforcement contract).
type Share struct {
	// Tag is the virtiofs mount tag (one of the ShareTag* values).
	Tag string
	// Root is the host directory the share exports.
	Root string
	// Writable marks the share host-writable; zero value read-only.
	Writable bool
}

// Bind is one container volumeMount realized from a share: the guest path
// MountPath binds to SourceRel under the share tagged ShareTag, optionally
// narrowed by SubPath (carried verbatim after lexical validation). Composed by
// guest-init.
type Bind struct {
	// VolumeName is the PodBox volume the bind realizes.
	VolumeName string
	// ShareTag names the Share the bind sources from.
	ShareTag string
	// SourceRel is the source relative to the share root: the volume name on
	// the pooled proj/vols shares, "" (the share root itself) on a PVC share.
	SourceRel string
	// MountPath is the guest path the container sees the volume at.
	MountPath string
	// SubPath is the volumeMount sub_path, verbatim (lexically validated:
	// relative, clean, no ".." segment).
	SubPath string
	// ReadOnly is the effective read-only intent: the volumeMount's read_only
	// OR a class that forces read-only (mirrors Materialize's derivation —
	// credentials and projected volumes always, a PVC when its source is
	// read_only).
	ReadOnly bool
}

// Tmpfs is one Memory-medium emptyDir mount: guest-RAM tmpfs at MountPath,
// never a virtiofs share (the contents must live in guest memory, not on the
// host filesystem). Composed by guest-init. It carries the same
// per-mount SubPath/ReadOnly intent a Bind does — upstream permits both on a
// Memory emptyDir, so dropping either here would be a silent narrowing the
// native path (materialize.go) does not have.
type Tmpfs struct {
	// VolumeName is the PodBox volume the tmpfs realizes.
	VolumeName string
	// MountPath is the guest path the container sees the tmpfs at.
	MountPath string
	// SubPath is the volumeMount sub_path, verbatim (lexically validated
	// exactly like Bind.SubPath); guest-init applies it inside the tmpfs.
	SubPath string
	// SizeLimit is the emptyDir size_limit verbatim (the proto's
	// resource.Quantity string, e.g. "64Mi"; "" = unset). No parsing here.
	SizeLimit string
	// ReadOnly is the volumeMount's read_only intent for this container's
	// mount of the tmpfs (no class term: an emptyDir source carries no
	// read_only of its own, mirroring Materialize's derivation).
	ReadOnly bool
}

// ComputeSharePlan computes the virtiofs share-device plan for a
// vm-RuntimeClass pod from the PodBox's declared volumes and volumeMounts.
// podDir is the pod's on-disk directory (the runtime-derived
// <root>/pods/<podID> — never box.rootfs_path, which is caller-supplied; the
// runtime now also refuses any rootfs_path that is not byte-equal to that same
// derivation, so the two agree, but the planner still derives its own
// rather than trusting the box). workRoot is the runtime work dir (Config.Root),
// and class is the local-path storage class PVC roots derive from. podDir is ENFORCED to
// sit strictly inside <workRoot>/pods (guardShareRoots): a caller-derived pod
// dir relocated wholesale — e.g. by a traversing pod_id surviving a future
// derivation change — rejects instead of anchoring every pod-dir share at the
// relocated tree. It is pure data: no filesystem access, no chown. Any box
// the planner cannot prove safe is rejected with an error (fail closed).
func ComputeSharePlan(box *runtimev1.PodBox, podDir, workRoot string, class storagev1.LocalPathClass) (SharePlan, error) {
	if box == nil {
		return SharePlan{}, errors.New("nil pod box")
	}
	podDir = filepath.Clean(podDir)
	workRoot = filepath.Clean(workRoot)
	if !filepath.IsAbs(podDir) {
		return SharePlan{}, fmt.Errorf("pod dir %q must be absolute", podDir)
	}
	if !filepath.IsAbs(workRoot) {
		return SharePlan{}, fmt.Errorf("work root %q must be absolute", workRoot)
	}
	class = class.WithDefaults()

	// Classify the DECLARATION set — every volume in box.volumes, mounted or
	// not — so an unknown-source volume rejects even before (or without) any
	// container mounting it.
	vols := make(map[string]vmVolume, len(box.GetVolumes()))
	haveProj, haveVols := false, false
	var pvcNames []string
	for _, v := range box.GetVolumes() {
		name := v.GetName()
		if name == "" {
			return SharePlan{}, errors.New("volume with empty name")
		}
		if _, dup := vols[name]; dup {
			return SharePlan{}, fmt.Errorf("duplicate volume name %q", name)
		}
		info, err := classifyVMVolume(v)
		if err != nil {
			return SharePlan{}, fmt.Errorf("volume %s: %w", name, err)
		}
		vols[name] = info
		switch info.class {
		case vmClassProj:
			haveProj = true
		case vmClassVols:
			haveVols = true
		case vmClassPVC:
			pvcNames = append(pvcNames, name)
		}
	}

	// Assemble the shares in the plan's deterministic order: rootfs always,
	// proj/vols only when a declared volume of the class exists, then the PVC
	// shares in sorted-volume-name order. Every pod-dir root derives from
	// podDir + a fixed literal; the PVC root is exactly the class DataDir over
	// single-COMPONENT names (validated + re-derivation-asserted below).
	shares := []Share{{Tag: ShareTagRootfs, Root: filepath.Join(podDir, vmRootfsDirName)}}
	if haveProj {
		shares = append(shares, Share{Tag: ShareTagProj, Root: filepath.Join(podDir, vmProjDirName)})
	}
	if haveVols {
		shares = append(shares, Share{Tag: ShareTagVols, Root: filepath.Join(podDir, vmVolsDirName), Writable: true})
	}
	podDirShares := len(shares)
	sort.Strings(pvcNames)
	pvcTags := make(map[string]string, len(pvcNames))
	if len(pvcNames) > 0 {
		// The namespace becomes a PATH COMPONENT of every PVC root below, so
		// it is validated here — where it turns into a path — not at box
		// ingress (the non-PVC classes never use it as one).
		if err := validateVMPathComponent("namespace", box.GetNamespace()); err != nil {
			return SharePlan{}, err
		}
	}
	for i, name := range pvcNames {
		src := vols[name].vol.GetPersistentVolumeClaim()
		claim := src.GetClaimName()
		if err := validateVMPathComponent("claim_name", claim); err != nil {
			return SharePlan{}, fmt.Errorf("volume %s: %w", name, err)
		}
		root, err := class.DataDir(box.GetNamespace(), claim)
		if err != nil {
			return SharePlan{}, fmt.Errorf("volume %s: %w", name, err)
		}
		// The R24(b) "equality-derived" property, asserted rather than trusted:
		// the root must re-derive as exactly <BasePath>/<namespace>/<claim>.
		// Redundant with the single-component validation above BY DESIGN — a
		// future DataDir change (a different join, a hashed layout) cannot
		// silently widen what a box-supplied name addresses.
		if filepath.Dir(root) != filepath.Join(class.BasePath, box.GetNamespace()) || filepath.Base(root) != claim {
			return SharePlan{}, fmt.Errorf("volume %s: pvc share root %q does not re-derive as %q/<namespace>/<claim_name>", name, root, class.BasePath)
		}
		tag := fmt.Sprintf("%s%d", ShareTagPVCPrefix, i)
		pvcTags[name] = tag
		shares = append(shares, Share{Tag: tag, Root: root, Writable: !src.GetReadOnly()})
	}

	// Binds and tmpfs per container — init and main lists alike, each keyed by
	// ITS name over ITS declared volumeMounts only (never a pod-wide union: in
	// the guest each container has its own mount namespace, so what container
	// A mounts must never leak into container B's view).
	binds := make(map[string][]Bind)
	tmpfs := make(map[string][]Tmpfs)
	containers := make([]*runtimev1.Container, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	containers = append(containers, box.GetInitContainers()...)
	containers = append(containers, box.GetContainers()...)
	seenContainer := make(map[string]bool, len(containers))
	for _, c := range containers {
		cname := c.GetName()
		if cname == "" {
			return SharePlan{}, errors.New("container with empty name")
		}
		if seenContainer[cname] {
			// The per-container keying below would silently merge two
			// same-named containers' mounts — reject instead (fail closed;
			// Kubernetes forbids duplicate container names pod-wide anyway).
			return SharePlan{}, fmt.Errorf("duplicate container name %q", cname)
		}
		seenContainer[cname] = true
		seenPath := make(map[string]bool, len(c.GetVolumeMounts()))
		for _, m := range c.GetVolumeMounts() {
			info, ok := vols[m.GetName()]
			if !ok {
				return SharePlan{}, fmt.Errorf("container %s: volume_mount %q references undeclared volume", cname, m.GetName())
			}
			mp := m.GetMountPath()
			if mp == "" {
				return SharePlan{}, fmt.Errorf("container %s: volume_mount %q has an empty mount_path", cname, m.GetName())
			}
			// Mirror the native seenMount conflict discipline at this path's
			// scope: within one container a guest mount path holds exactly one
			// selection, so a repeated mount_path is a hard error.
			if seenPath[mp] {
				return SharePlan{}, fmt.Errorf("container %s: duplicate mount_path %q", cname, mp)
			}
			seenPath[mp] = true
			sp := m.GetSubPath()
			if sp != "" {
				if err := validateVMSubPath(sp); err != nil {
					return SharePlan{}, fmt.Errorf("container %s: volume_mount %q: %w", cname, m.GetName(), err)
				}
			}
			switch info.class {
			case vmClassTmpfs:
				tmpfs[cname] = append(tmpfs[cname], Tmpfs{
					VolumeName: m.GetName(),
					MountPath:  mp,
					SubPath:    sp,
					SizeLimit:  info.vol.GetEmptyDir().GetSizeLimit(),
					ReadOnly:   m.GetReadOnly(),
				})
			case vmClassPVC:
				binds[cname] = append(binds[cname], Bind{
					VolumeName: m.GetName(),
					ShareTag:   pvcTags[m.GetName()],
					MountPath:  mp,
					SubPath:    sp,
					ReadOnly:   m.GetReadOnly() || info.vol.GetPersistentVolumeClaim().GetReadOnly(),
				})
			default:
				tag := ShareTagProj
				if info.class == vmClassVols {
					tag = ShareTagVols
				}
				binds[cname] = append(binds[cname], Bind{
					VolumeName: m.GetName(),
					ShareTag:   tag,
					SourceRel:  m.GetName(),
					MountPath:  mp,
					SubPath:    sp,
					// Mirrors Materialize's read-only derivation
					// (materialize.go: read_only || credential || projected).
					ReadOnly: m.GetReadOnly() || info.credential || info.projected,
				})
			}
		}
	}

	if err := guardShareRoots(shares, podDirShares, podDir, workRoot, class.BasePath); err != nil {
		return SharePlan{}, err
	}
	if len(binds) == 0 {
		binds = nil
	}
	if len(tmpfs) == 0 {
		tmpfs = nil
	}
	return SharePlan{Shares: shares, Binds: binds, Tmpfs: tmpfs}, nil
}

// vmVolClass is the planner's classification of a declared volume.
type vmVolClass int

const (
	// vmClassProj — configMap / secret / projected / downwardAPI, bound from
	// the read-only pooled proj share.
	vmClassProj vmVolClass = iota
	// vmClassVols — default-medium emptyDir, bound from the writable pooled
	// vols share.
	vmClassVols
	// vmClassTmpfs — Memory-medium emptyDir, a guest tmpfs (never a share).
	vmClassTmpfs
	// vmClassPVC — persistentVolumeClaim, one share per volume.
	vmClassPVC
)

// vmVolume is one classified declared volume.
type vmVolume struct {
	vol   *runtimev1.Volume
	class vmVolClass
	// credential mirrors Materialize's classification: a secret, or a
	// projected volume containing a secret / serviceAccountToken source.
	credential bool
	// projected marks a projected volume (always read-only, mirroring
	// Materialize's `|| vol.GetProjected() != nil` term).
	projected bool
}

// classifyVMVolume ARITY-CHECKS a declared volume's source union and
// classifies the single set source. The union is not a proto oneof, so the
// dispatch COUNTS the set sources across the known source getters (proto
// fields 2–7) and rejects anything but exactly one:
//
//   - a FUTURE source field (host_path = 8, and 9, 10, … after it) is unknown
//     to this build, sets none of the known getters, and lands in the
//     count == 0 reject BY construction — where a first-match dispatch would
//     silently plan an empty/wrong device for it (fail open);
//   - a two-source volume (representable on the wire for the same non-oneof
//     reason) rejects as count == 2 instead of first-match-wins.
func classifyVMVolume(v *runtimev1.Volume) (vmVolume, error) {
	count := 0
	for _, set := range []bool{
		v.GetConfigMap() != nil,
		v.GetSecret() != nil,
		v.GetEmptyDir() != nil,
		v.GetDownwardApi() != nil,
		v.GetProjected() != nil,
		v.GetPersistentVolumeClaim() != nil,
	} {
		if set {
			count++
		}
	}
	if count != 1 {
		return vmVolume{}, fmt.Errorf("%d volume sources set, want exactly 1 (unknown or multi-source volumes fail closed)", count)
	}
	info := vmVolume{vol: v}
	switch {
	case v.GetConfigMap() != nil, v.GetDownwardApi() != nil:
		info.class = vmClassProj
	case v.GetSecret() != nil:
		info.class = vmClassProj
		info.credential = true
	case v.GetProjected() != nil:
		info.class = vmClassProj
		info.projected = true
		info.credential = projectedCredential(v.GetProjected())
	case v.GetEmptyDir() != nil:
		switch v.GetEmptyDir().GetMedium() {
		case "":
			info.class = vmClassVols
		case emptyDirMediumMemory:
			info.class = vmClassTmpfs
		default:
			return vmVolume{}, fmt.Errorf("emptyDir medium %q is not in the closed set (%q or %q)",
				v.GetEmptyDir().GetMedium(), "", emptyDirMediumMemory)
		}
	case v.GetPersistentVolumeClaim() != nil:
		info.class = vmClassPVC
	}
	return info, nil
}

// projectedCredential mirrors renderProjected's credential classification
// without rendering anything: a projected volume is a credential iff any of
// its sources is a secret or a serviceAccountToken.
func projectedCredential(src *runtimev1.ProjectedVolumeSource) bool {
	for _, p := range src.GetSources() {
		if p.GetSecret() != nil || p.GetServiceAccountToken() != nil {
			return true
		}
	}
	return false
}

// validateVMSubPath lexically validates a volumeMount sub_path carried on a
// bind: relative, already clean, no ".." segment. Both halves are
// load-bearing: "../x" IS already clean (Clean is a no-op on it), so the
// clean-invariance check alone would pass it — the segment scan catches it;
// "a/../b" cleans to "b", so the segment scan alone would run on the wrong
// string — the clean check catches it first. Purely lexical: the planner never
// resolves the path (guest-init applies it inside the guest, where its own
// containment applies).
func validateVMSubPath(sp string) error {
	if filepath.IsAbs(sp) {
		return fmt.Errorf("sub_path %q must be relative", sp)
	}
	if filepath.Clean(sp) != sp {
		return fmt.Errorf("sub_path %q is not a clean path", sp)
	}
	for _, seg := range strings.Split(sp, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("sub_path %q must not contain a %q segment", sp, "..")
		}
	}
	return nil
}

// validateVMPathComponent validates a PodBox-supplied name (namespace,
// claim_name) that becomes a single path component of a derived share root:
// non-empty, not "." or ".." (either addresses an ancestor of the intended
// root — a "." claim is the whole namespace tree), and free of "/" (a
// multi-component or absolute name addresses a sibling namespace's tree or an
// unrelated one) and of `\` (never a separator on darwin, but rejected so the
// name stays one component under any future path handling). The
// clean-invariance check is redundant with those for a separator-free string
// and kept as an explicit belt against future edits loosening the ones above.
//
// R24(b) is what this enforces structurally: the PVC root is
// <base>/<namespace>/<claim> and never <base>, an ancestor of it, or a lateral
// tree — single-component inputs make the DataDir join unable to produce
// those.
func validateVMPathComponent(field, v string) error {
	if v == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if v == "." || v == ".." || strings.ContainsAny(v, `/\`) {
		return fmt.Errorf("%s %q must be a single path component", field, v)
	}
	if filepath.Clean(v) != v {
		return fmt.Errorf("%s %q is not a clean path component", field, v)
	}
	return nil
}

// guardShareRoots is the fail-closed defence-in-depth over the assembled share
// roots. shares[:podDirShares] are the pod-dir shares (Join(podDir, <fixed
// literal>)); the rest are PVC shares (the class DataDir join).
//
// The comparisons are LEXICAL — no filepath.EvalSymlinks — and that is SOUND
// here only because of a load-bearing precondition: every compared path
// derives from a configured root string (podDir/workRoot from the runtime
// config, the PVC roots from class.BasePath) joined with fixed literals and
// PodBox NAME COMPONENTS, and no caller-supplied absolute PATH survives to the
// comparison (a hostPath source is outside the arity check's closed set and
// rejects; box.rootfs_path is ignored by the planner). Operands of one
// derivation cannot disagree about firmlink/symlink spellings (/var vs
// /private/var), which is the case lexical comparison cannot judge. Keep that
// precondition true when extending the planner.
func guardShareRoots(shares []Share, podDirShares int, podDir, workRoot, basePath string) error {
	// The pod dir must itself sit strictly inside the runtime pod tree
	// <workRoot>/pods before it may anchor any share root. The three pod-dir
	// roots are Join(podDir, <fixed literal>) — strictly under podDir BY
	// construction — so the per-share containment below holds for any podDir,
	// including one relocated wholesale (a traversing pod_id, a mis-wired
	// caller). Bounding podDir is what gives those checks their meaning.
	podsRoot := filepath.Join(workRoot, vmPodsDirName)
	if !IsStrictlyUnder(podDir, podsRoot) {
		return fmt.Errorf("pod dir %q is not strictly under the runtime pods root %q", podDir, podsRoot)
	}
	runDir := filepath.Join(workRoot, "run")
	for i, s := range shares {
		if s.Root == "" {
			return fmt.Errorf("share %s has an empty root", s.Tag)
		}
		if i < podDirShares {
			// A pod-dir share stays strictly inside the owning pod dir —
			// equality would export the whole pod dir, which is exactly why
			// this uses IsStrictlyUnder and not isUnder (equality-true).
			if !IsStrictlyUnder(s.Root, podDir) {
				return fmt.Errorf("share %s root %q escapes the pod dir %q", s.Tag, s.Root, podDir)
			}
		} else {
			// A PVC root is already re-derivation-asserted at build time
			// (single-component namespace/claim, root == <base>/<ns>/<claim>),
			// so no crafted box name reaches here — a lateral ../<other-ns>
			// or ancestor-addressing "." claim rejects at derivation, not
			// here. These checks stay as defence in depth for the inputs the
			// derivation assert does not see: a mis-rooted class, or a future
			// change to the root derivation itself.
			if s.Root == basePath {
				return fmt.Errorf("share %s root equals the storage base path %q", s.Tag, basePath)
			}
			if !IsStrictlyUnder(s.Root, basePath) {
				return fmt.Errorf("share %s root %q escapes the storage base path %q", s.Tag, s.Root, basePath)
			}
		}
		// R7: no share may export, sit inside, or contain the daemon socket
		// tree <workRoot>/run (netd.sock, runtimed.sock, run/keys) — a guest
		// handed any slice of it could reach the daemon control sockets.
		if s.Root == runDir || IsStrictlyUnder(s.Root, runDir) || IsStrictlyUnder(runDir, s.Root) {
			return fmt.Errorf("share %s root %q intersects the runtime socket tree %q", s.Tag, s.Root, runDir)
		}
	}
	// Pairwise disjoint (strict, separator-aware): a nested pair would alias
	// one host tree through two devices with potentially different
	// writability, and the sibling-prefix case (/a/b vs /a/bc) must not be
	// treated as nested.
	for i := 0; i < len(shares); i++ {
		for j := i + 1; j < len(shares); j++ {
			a, b := shares[i], shares[j]
			if a.Root == b.Root || IsStrictlyUnder(a.Root, b.Root) || IsStrictlyUnder(b.Root, a.Root) {
				return fmt.Errorf("share roots %q (%s) and %q (%s) are nested", a.Root, a.Tag, b.Root, b.Tag)
			}
		}
	}
	return nil
}
