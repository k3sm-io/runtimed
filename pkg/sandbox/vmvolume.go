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

package sandbox

// VMVolumePlan is the virtiofs share-device plan for a pod's Linux guest
// (B106): which host directories become VZ shared-directory devices (Shares),
// how each container's declared volumeMounts bind into those shares (Binds),
// and which mounts are guest-RAM tmpfs instead of a share (Tmpfs).
//
// It is PLAIN DATA on the same decoupling seam as GuestNetworkConfig: sandbox
// does NOT import pkg/mount (the volume/path authority that computes the plan)
// — the named mapper is createVMPod in pkg/runtime, which owns both sides and
// stamps this struct onto VMSpec.Volumes as data. The zero value plans nothing
// (no shares, no binds, no tmpfs), which is safe: a guest with no plan gets no
// volume devices.
type VMVolumePlan struct {
	// Shares are the virtiofs share devices, in the plan's deterministic order
	// (rootfs, proj, vols, then one share per PVC volume in sorted-volume-name
	// order).
	Shares []VMShare
	// Binds are the per-container volume binds, keyed by CONTAINER NAME (init
	// and main containers alike). A container absent from the map mounts no
	// share-backed volume.
	Binds map[string][]VMBind
	// Tmpfs are the per-container guest-tmpfs mounts (Memory-medium emptyDirs),
	// keyed by container name.
	Tmpfs map[string][]VMTmpfs
}

// VMShare is one virtiofs share device: the host directory Root exported into
// the guest under the mount tag Tag.
//
// The field is Writable — NOT ReadOnly — so the ZERO VALUE IS READ-ONLY
// (fail-closed): a share is writable only by affirmative decision. The
// ENFORCEMENT POINT for Writable is the VZ share-device configuration (the
// VZSharedDirectory readOnly: flag on the device the lab-gated boot builds);
// NOTHING in this build enforces it — CreateVM is a stub
// (ErrVMBootNotImplemented), so the plan is carried, not applied. A guest-side
// `mount -o ro` is NOT a substitute for the device-level flag: guest mount
// options are attacker-controlled in a vm pod (the guest runs the tenant's
// code as root), while the VZ device flag is applied host-side, outside the
// guest's reach.
type VMShare struct {
	// Tag is the virtiofs mount tag the guest addresses the device by
	// (VZ limits tags to 36 bytes; the planner's tag scheme respects that).
	Tag string
	// Root is the host directory exported by the share.
	Root string
	// Writable marks the share host-writable via the VZ device config; the
	// zero value is read-only (fail-closed). See the type doc for the
	// enforcement point.
	Writable bool
}

// VMBind is one container volumeMount realized from a virtiofs share: guest
// path MountPath is bound to SourceRel under the share tagged ShareTag. Binds
// are grouped per container name (VMVolumePlan.Binds) and are COMPOSED LATER
// by the guest init process (B102, the other consumer this build does not
// enforce for): guest-init mounts each share by tag and bind-mounts
// <share>/<SourceRel> (optionally narrowed by SubPath) at MountPath inside the
// container's mount namespace. Nothing in this build performs those mounts.
type VMBind struct {
	// VolumeName is the PodBox volume the bind realizes.
	VolumeName string
	// ShareTag names the VMShare the bind sources from.
	ShareTag string
	// SourceRel is the bind source relative to the share root ("" = the share
	// root itself, the PVC case; the volume name for the pooled shares).
	SourceRel string
	// MountPath is the guest path the container sees the volume at.
	MountPath string
	// SubPath is the volumeMount sub_path carried VERBATIM (lexically
	// validated by the planner); guest-init applies it under SourceRel.
	SubPath string
	// ReadOnly is the effective per-bind read-only intent (the volumeMount's
	// read_only OR a class that forces read-only — credentials always do).
	ReadOnly bool
}

// VMTmpfs is one Memory-medium emptyDir mount: guest-RAM tmpfs at MountPath,
// never a virtiofs share (the volume's contents must live in guest memory, not
// on the host filesystem). Grouped per container name (VMVolumePlan.Tmpfs) and
// composed by guest-init like VMBind.
type VMTmpfs struct {
	// VolumeName is the PodBox volume the tmpfs realizes.
	VolumeName string
	// MountPath is the guest path the container sees the tmpfs at.
	MountPath string
	// SizeLimit is the emptyDir size_limit carried VERBATIM as the proto's
	// resource.Quantity string (e.g. "64Mi"); empty means unset. The planner
	// does NO quantity parsing — translating it to tmpfs size= bytes is
	// guest-init's job (B102).
	SizeLimit string
}
