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
	runtimev1 "k3sm.io/apis/runtime/v1"
	storagev1 "k3sm.io/apis/storage/v1"
)

// Virtiofs mount tags for the pooled shares of a vm-RuntimeClass pod's plan
// (B106). VZ limits a virtiofs tag to 36 bytes, so tags are short fixed
// strings — never derived from user-supplied names (a PVC share is tagged by
// INDEX, ShareTagPVCPrefix+i, precisely so a claim name can never overflow or
// collide a tag).
const (
	// ShareTagRootfs is the pod rootfs share: read-only, and in this build the
	// SINGLE lower layer of the guest root. The multi-lower extension (one
	// share per OCI layer) is owned by M11.2-d1, not here.
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

// SharePlan is the virtiofs share-device plan computed for a vm-RuntimeClass
// pod's volumes: which host directories become VZ shared-directory devices
// (Shares), how each container's declared volumeMounts bind into those shares
// (Binds), and which mounts are guest-RAM tmpfs instead (Tmpfs). It is PURE
// DATA — ComputeSharePlan touches no filesystem and chowns nothing (the d5
// no-chown rule: the planner plans, ownership is never its job). Enforcement
// of a share's writability is the VZ device config the lab-gated boot builds,
// and composition of the binds/tmpfs is guest-init (B102); neither happens in
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
	// volumeMounts ONLY — never a pod-wide union). A container with no
	// share-backed mount has no entry.
	Binds map[string][]Bind
	// Tmpfs are the per-container Memory-medium emptyDir mounts, keyed by
	// container name.
	Tmpfs map[string][]Tmpfs
}

// Share is one virtiofs share device: the host directory Root exported into
// the guest under Tag. The Writable field polarity makes the ZERO VALUE
// READ-ONLY (fail-closed); its enforcement point is the VZ device config, not
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
// guest-init (B102).
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
// host filesystem). Composed by guest-init (B102).
type Tmpfs struct {
	// VolumeName is the PodBox volume the tmpfs realizes.
	VolumeName string
	// MountPath is the guest path the container sees the tmpfs at.
	MountPath string
	// SizeLimit is the emptyDir size_limit VERBATIM (the proto's
	// resource.Quantity string, e.g. "64Mi"; "" = unset). No parsing here.
	SizeLimit string
}

// ComputeSharePlan computes the virtiofs share-device plan for a
// vm-RuntimeClass pod from the PodBox's declared volumes and volumeMounts.
// podDir is the pod's on-disk directory (the runtime-derived
// <root>/pods/<podID> — NEVER box.rootfs_path, which is caller-supplied and
// unvalidated), workRoot is the runtime work dir (Config.Root), and class is
// the local-path storage class PVC roots derive from. It is pure data: no
// filesystem access, no chown. Any box the planner cannot prove safe is
// rejected with an error (fail closed).
func ComputeSharePlan(box *runtimev1.PodBox, podDir, workRoot string, class storagev1.LocalPathClass) (SharePlan, error) {
	return SharePlan{}, nil
}
