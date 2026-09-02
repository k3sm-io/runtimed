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

package guestinit

import (
	"fmt"
	"path"
	"sort"
	"strings"

	guestv1 "k3sm.io/apis/guest/v1"
)

// The guest's own scratch tree. Nothing below GuestRoot is ever visible inside
// a container except through an explicit bind: the per-container rootfs is
// composed here and the container is chrooted into ContainerRootDir, so a
// path under GuestRoot/etc (the pod-level rendered files) is reachable only at
// the target the /etc bind set puts it at.
const (
	// GuestRoot is the guest-private tree the init composes everything under.
	GuestRoot = "/run/k3sm"

	// SpecShareTag is the virtiofs device tag carrying the boot spec, mounted
	// read-only at SpecMountPoint. It is a host/guest convention, not a
	// guest/v1 field — the host-side VM builder must attach the share under
	// this exact tag.
	SpecShareTag = "k3sm.spec"

	// SpecMountPoint is where SpecShareTag is mounted, and SpecPath is the
	// proto-JSON GuestSpec the init reads as its first act after the
	// pseudo-filesystems are up.
	SpecMountPoint = GuestRoot + "/spec"
	SpecPath       = SpecMountPoint + "/guest-spec.json"

	// EtcDir holds the pod-level rendered /etc files (resolv.conf, hosts,
	// hostname) that the per-container bind set shadows each container's own
	// copies with.
	EtcDir = GuestRoot + "/etc"
)

// Linux mount flags, restated as portable constants.
//
// These are the kernel's MS_* ABI values. They are duplicated here rather than
// imported from golang.org/x/sys/unix on purpose (see the package doc): the
// symbolic-option -> flag-word mapping is behaviour, and behaviour that only
// exists in a linux-only file is behaviour no darwin test can reach. The
// values are part of the Linux syscall ABI and cannot change.
const (
	msRDONLY  uintptr = 0x1
	msNOSUID  uintptr = 0x2
	msNODEV   uintptr = 0x4
	msNOEXEC  uintptr = 0x8
	msREMOUNT uintptr = 0x20
	msNOATIME uintptr = 0x400
	msBIND    uintptr = 0x1000
	msREC     uintptr = 0x4000
)

// MountOption is a symbolic mount option. The plan carries symbols rather than
// a flag word so a plan stays readable, comparable in a test, and free of any
// linux-only import; LinuxMountFlags performs the translation.
type MountOption string

// The symbolic options a guest mount plan can carry.
const (
	OptionReadOnly MountOption = "ro"
	OptionNoSuid   MountOption = "nosuid"
	OptionNoDev    MountOption = "nodev"
	OptionNoExec   MountOption = "noexec"
	OptionNoAtime  MountOption = "noatime"
	OptionBind     MountOption = "bind"
	OptionRBind    MountOption = "rbind"
	OptionRemount  MountOption = "remount"
)

// linuxMountFlag is the MS_* value each symbolic option translates to.
var linuxMountFlag = map[MountOption]uintptr{
	OptionReadOnly: msRDONLY,
	OptionNoSuid:   msNOSUID,
	OptionNoDev:    msNODEV,
	OptionNoExec:   msNOEXEC,
	OptionNoAtime:  msNOATIME,
	OptionBind:     msBIND,
	OptionRBind:    msBIND | msREC,
	OptionRemount:  msREMOUNT,
}

// LinuxMountFlags translates a step's symbolic options into the flag word
// mount(2) takes. An unknown option is an error rather than a silently dropped
// flag: dropping OptionReadOnly would mount a credential share writable.
func LinuxMountFlags(opts []MountOption) (uintptr, error) {
	var flags uintptr
	for _, o := range opts {
		f, ok := linuxMountFlag[o]
		if !ok {
			return 0, fmt.Errorf("%w: unknown mount option %q", ErrInvalidSpec, o)
		}
		flags |= f
	}
	return flags, nil
}

// IDMap is an idmapped-mount request: files owned by HostUID/HostGID on the
// share appear inside the guest as ContainerUID/ContainerGID. It is how fsGroup
// is honoured with zero recursive chown on either side.
//
// It is PLAN DATA only. The executor does not apply it (see the package doc's
// ceilings) — it refuses a spec that asks for one.
type IDMap struct {
	HostUID      int64
	HostGID      int64
	ContainerUID int64
	ContainerGID int64
}

// MountStep is one mount the guest performs, plus the directory/file creation
// it needs first. Steps are applied in slice order and the order is
// significant: a lower layer is mounted before the overlay that stacks on it,
// and the Rosetta share is mounted before the binfmt registration that opens
// its interpreter.
type MountStep struct {
	// Source is the block device, virtiofs tag, or bind source. Empty for a
	// pseudo-filesystem that takes none.
	Source string

	// Target is the absolute guest path to mount at.
	Target string

	// FSType is the filesystem type; empty for a bind or a remount.
	FSType string

	// Options are the symbolic mount options (see LinuxMountFlags).
	Options []MountOption

	// Data is the filesystem-specific option string (tmpfs "size=", overlay
	// "lowerdir=", devpts "gid=").
	Data string

	// MkdirTarget creates Target as a directory (0755) before mounting.
	MkdirTarget bool

	// TouchTarget creates Target as an empty file before mounting. Binding a
	// FILE requires the target to exist as a file; MkdirAll on it would give
	// the workload's open(2) an EISDIR instead.
	TouchTarget bool

	// MkdirExtra are additional directories to create before this mount, in
	// slice order (an overlay's upper and work dirs live inside the tmpfs
	// mounted by the preceding step, so they cannot be created earlier).
	MkdirExtra []string

	// IDMap, when non-nil, is the idmapped-mount request this mount carries.
	IDMap *IDMap

	// ResolveRoot, when non-empty, is the container root Target must be resolved
	// inside with CHROOT semantics before the target is created or mounted.
	//
	// It is set on every step whose target lies inside a container's composed
	// rootfs, because that rootfs is the IMAGE's and the image decides what is a
	// symlink. Nearly every base image ships /var/run as an ABSOLUTE symlink to
	// /run, and the kernel resolves an absolute symlink against the mounting
	// process's root — the guest's — not the container's. Both the MkdirAll and
	// the mount then SUCCEED against a guest path that exists, and the container
	// sees nothing at its mountPath: this is why no vm pod could read its
	// ServiceAccount token. See guestinit.ResolveTarget.
	ResolveRoot string

	// Why is a one-line rationale for the boot log, so a failed mount is
	// legible without reading this package.
	Why string
}

// PseudoMounts is the fixed set of kernel filesystems the guest brings up
// before it can do anything else — including reading its own spec.
//
// binfmt_misc is mounted unconditionally even when the pod carries no
// linux/amd64 payload: it is a 4 KiB kernel filesystem, and mounting it here
// keeps the Rosetta registration a single write with no conditional mount to
// get wrong.
func PseudoMounts() []MountStep {
	hardened := []MountOption{OptionNoSuid, OptionNoDev, OptionNoExec}
	return []MountStep{
		{
			Source: "proc", Target: "/proc", FSType: "proc",
			Options: hardened, MkdirTarget: true,
			Why: "procfs: /proc/self/exe, /proc/sys/fs/binfmt_misc, meminfo",
		},
		{
			Source: "sysfs", Target: "/sys", FSType: "sysfs",
			Options: hardened, MkdirTarget: true,
			Why: "sysfs: the cgroup2 mount point's parent",
		},
		{
			Source: "devtmpfs", Target: "/dev", FSType: "devtmpfs",
			Options: []MountOption{OptionNoSuid}, Data: "mode=0755", MkdirTarget: true,
			Why: "devtmpfs: the kernel populates the device nodes the guest needs",
		},
		{
			Source: "devpts", Target: "/dev/pts", FSType: "devpts",
			Options: []MountOption{OptionNoSuid, OptionNoExec},
			Data:    "gid=5,mode=0620,ptmxmode=0666", MkdirTarget: true,
			Why: "devpts: the pty pairs a tty container needs",
		},
		{
			Source: "tmpfs", Target: "/dev/shm", FSType: "tmpfs",
			Options: []MountOption{OptionNoSuid, OptionNoDev},
			Data:    "mode=1777", MkdirTarget: true,
			Why: "the default /dev/shm; a pod-level Memory emptyDir at this target replaces it",
		},
		{
			Source: "cgroup2", Target: "/sys/fs/cgroup", FSType: "cgroup2",
			Options: append(append([]MountOption{}, hardened...), OptionNoAtime),
			Data:    "nsdelegate", MkdirTarget: true,
			Why: "cgroup2: the per-container leaf hierarchy and the OOM truth for a vm pod",
		},
		{
			Source: "binfmt_misc", Target: BinfmtMiscMountPoint, FSType: "binfmt_misc",
			Options: hardened,
			Why:     "binfmt_misc: the register file the Rosetta interpreter is written to",
		},
	}
}

// SpecMount is the read-only virtiofs share the boot spec is read from. It is
// separate from PseudoMounts because the spec is host-supplied rather than
// kernel-supplied, but it is mounted in the same breath: the init cannot plan
// anything until it has read the file.
func SpecMount() MountStep {
	return MountStep{
		Source: SpecShareTag, Target: SpecMountPoint, FSType: "virtiofs",
		Options:     []MountOption{OptionReadOnly, OptionNoSuid, OptionNoDev, OptionNoExec},
		MkdirTarget: true,
		Why:         "the host-written GuestSpec share",
	}
}

// readOnlyBind expands a read-only bind into the two mount(2) calls Linux
// actually requires. MS_BIND|MS_RDONLY in a single call is silently ignored
// for the read-only part — the new mount inherits the source's writability —
// so a bind that skipped the remount would expose a credential file writable
// while looking correct in the plan.
func readOnlyBind(step MountStep) []MountStep {
	// The remount targets the SAME path, so it needs the same chroot-semantics
	// resolution the bind does — otherwise it would remount a guest path.
	remount := MountStep{
		Source:      step.Source,
		Target:      step.Target,
		ResolveRoot: step.ResolveRoot,
		Options:     []MountOption{OptionBind, OptionRemount, OptionReadOnly},
		Why:         "remount: MS_BIND|MS_RDONLY in one call does not apply RDONLY on Linux",
	}
	return []MountStep{step, remount}
}

// writableBind is readOnlyBind's mirror: it expands a WRITABLE bind into the
// bind plus a remount that CLEARS MS_RDONLY.
//
// The inheritance runs both ways and only one direction was handled. A bind
// inherits its source mount's writability, so a bind out of a READ-ONLY mount
// comes up read-only however the plan describes it — and every default-medium
// emptyDir is exactly that, a writable bind out of the deliberately read-only
// pooled staging mount. The symptom was an init container reporting
// "can't create /shared/from-init.txt: Read-only file system" while the host
// device, the share plan and the guest spec all said writable.
//
// MS_REMOUNT|MS_BIND with no MS_RDONLY is the call that clears it, and it is a
// no-op on a bind that was already writable — which is why this is emitted
// whenever the source mount is read-only and never conditioned on a tag.
func writableBind(step MountStep) []MountStep {
	// The remount targets the SAME path, so it needs the same chroot-semantics
	// resolution the bind does — otherwise it would remount a guest path.
	remount := MountStep{
		Source:      step.Source,
		Target:      step.Target,
		ResolveRoot: step.ResolveRoot,
		Options:     []MountOption{OptionBind, OptionRemount},
		Why:         "remount: a bind inherits its source mount's MS_RDONLY and must be cleared explicitly",
	}
	return []MountStep{step, remount}
}

// perMountReadOnly makes a NON-bind mount read-only at the MOUNT rather than at
// the superblock: it mounts writable and then remounts the mount point
// read-only.
//
// The distinction is invisible in every other respect and load-bearing in one.
// MS_RDONLY in a fresh mount(2) sets SB_RDONLY on the new SUPERBLOCK, and a
// bind shares its source's superblock — so a writable bind out of such a mount
// cannot be made writable at all. Worse, the attempt SUCCEEDS: Linux's
// change_mount_ro_state clears the per-mount MNT_READONLY and returns 0 while
// sb_rdonly() keeps every write returning EROFS, so the plan looks applied and
// the container still cannot write.
//
// Mounting the stage writable and then remounting the mount point read-only
// leaves the stage exactly as read-only as before through its own path — a
// write to it still fails — while leaving the superblock writable so a bind out
// of it can carry its own writability. It is applied ONLY to a mount some
// writable bind sources from (see stagesAWritableBind); every other read-only
// mount keeps SB_RDONLY, which is the stronger posture and the right one for
// the rootfs lower layer and the spec share.
func perMountReadOnly(step MountStep) []MountStep {
	// The remount targets the SAME path, so it needs the same chroot-semantics
	// resolution the bind does — otherwise it would remount a guest path.
	remount := MountStep{
		Source:      step.Source,
		Target:      step.Target,
		ResolveRoot: step.ResolveRoot,
		Options:     []MountOption{OptionBind, OptionRemount, OptionReadOnly},
		Why:         "remount: read-only at the mount, not the superblock, so writable binds out of it stay writable",
	}
	return []MountStep{step, remount}
}

// mountPathUnder reports whether a bind source lies at or under a mount target.
func mountPathUnder(source, target string) bool {
	if source == target {
		return true
	}
	return strings.HasPrefix(source, strings.TrimSuffix(target, "/")+"/")
}

// stagesAWritableBind reports whether mounts[i] is a mount some WRITABLE bind in
// the same list sources from. That is the precise condition perMountReadOnly
// exists for, and it is derived from the plan rather than from a tag: a pooled
// share is the case today, and a PVC share staged the same way tomorrow would be
// caught by the same predicate with no change here.
func stagesAWritableBind(mounts []*guestv1.GuestMount, i int) bool {
	target := mounts[i].GetTarget()
	for j, m := range mounts {
		if j == i || m == nil {
			continue
		}
		if m.GetKind() != guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND || m.GetReadOnly() {
			continue
		}
		if mountPathUnder(m.GetTagOrSource(), target) {
			return true
		}
	}
	return false
}

// bindInheritsReadOnly reports whether mounts[i] is a bind whose source lies
// under a READ-ONLY mount in the same list — the condition that makes a
// writable bind come up read-only unless writableBind's remount clears it.
func bindInheritsReadOnly(mounts []*guestv1.GuestMount, i int) bool {
	source := mounts[i].GetTagOrSource()
	for j, m := range mounts {
		if j == i || m == nil || !m.GetReadOnly() {
			continue
		}
		if mountPathUnder(source, m.GetTarget()) {
			return true
		}
	}
	return false
}

// validTarget rejects a mount target that is not an absolute, lexically clean
// path. A "../" in a target would place a mount outside the tree the plan
// believes it is composing.
func validTarget(target string) error {
	if target == "" || !strings.HasPrefix(target, "/") {
		return fmt.Errorf("%w: mount target %q is not absolute", ErrInvalidSpec, target)
	}
	if path.Clean(target) != target {
		return fmt.Errorf("%w: mount target %q is not a clean path", ErrInvalidSpec, target)
	}
	return nil
}

// validTag rejects a virtiofs tag or bind source that could be read as a path
// escape. A tag crosses the host/guest boundary and is used verbatim as
// mount(2)'s source.
func validTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("%w: empty mount source", ErrInvalidSpec)
	}
	if strings.ContainsAny(tag, "\x00\n") {
		return fmt.Errorf("%w: mount source %q contains a control character", ErrInvalidSpec, tag)
	}
	return nil
}

// PodMounts expands the spec's pod-level mounts into ordered steps. It is
// applied once, before any container starts.
//
// fsGroup is threaded in because an idmapped mount's container-side owner IS
// the pod's fsGroup: that is the whole mechanism by which fsGroup is honoured
// without a recursive chown.
func PodMounts(mounts []*guestv1.GuestMount, fsGroup int64) ([]MountStep, error) {
	var out []MountStep
	for i, m := range mounts {
		if m == nil {
			return nil, fmt.Errorf("%w: mounts[%d] is nil", ErrInvalidSpec, i)
		}
		if err := validTarget(m.GetTarget()); err != nil {
			return nil, fmt.Errorf("mounts[%d]: %w", i, err)
		}
		step := MountStep{
			Target:      m.GetTarget(),
			MkdirTarget: true,
			Why:         fmt.Sprintf("pod mount %d (%s)", i, kindName(m.GetKind())),
		}
		if m.GetIdmap() {
			step.IDMap = &IDMap{ContainerUID: 0, ContainerGID: fsGroup}
		}
		switch m.GetKind() {
		case guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS:
			if err := validTag(m.GetTagOrSource()); err != nil {
				return nil, fmt.Errorf("mounts[%d]: %w", i, err)
			}
			step.Source, step.FSType = m.GetTagOrSource(), "virtiofs"
			step.Options = []MountOption{OptionNoSuid, OptionNoDev}
		case guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS:
			if m.GetTagOrSource() != "" {
				return nil, fmt.Errorf("%w: mounts[%d]: a tmpfs mount carries no source, got %q",
					ErrInvalidSpec, i, m.GetTagOrSource())
			}
			step.Source, step.FSType = "tmpfs", "tmpfs"
			step.Options = []MountOption{OptionNoSuid, OptionNoDev}
			step.Data = tmpfsData(m.GetSizeLimitBytes())
		case guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND:
			if err := validTag(m.GetTagOrSource()); err != nil {
				return nil, fmt.Errorf("mounts[%d]: %w", i, err)
			}
			step.Source = m.GetTagOrSource()
			step.Options = []MountOption{OptionBind}
		default:
			return nil, fmt.Errorf("%w: mounts[%d]: unhandled mount kind %v",
				ErrInvalidSpec, i, m.GetKind())
		}
		if m.GetReadOnly() {
			out = append(out, readOnlyBindOrDirect(step, stagesAWritableBind(mounts, i))...)
			continue
		}
		// A writable bind out of a read-only mount inherits read-only and needs an
		// explicit remount to clear it; a writable bind out of a writable mount
		// needs nothing, and gets nothing.
		if step.FSType == "" && bindInheritsReadOnly(mounts, i) {
			out = append(out, writableBind(step)...)
			continue
		}
		out = append(out, step)
	}
	return out, nil
}

// readOnlyBindOrDirect applies read-only the way the mount kind requires.
//
// A bind needs the separate remount call (readOnlyBind). A fresh mount normally
// takes MS_RDONLY directly, which is the stronger form — read-only at the
// superblock — and is what the rootfs lower layer and the spec share want. The
// exception is a mount that some writable bind sources from: SB_RDONLY there
// would make that bind unwritable no matter what its own remount says, so it
// takes the per-mount form instead (perMountReadOnly).
func readOnlyBindOrDirect(step MountStep, stagesWritableBind bool) []MountStep {
	if step.FSType == "" {
		return readOnlyBind(step)
	}
	if stagesWritableBind {
		return perMountReadOnly(step)
	}
	step.Options = append(step.Options, OptionReadOnly)
	return []MountStep{step}
}

// kindName is the short name of a mount kind for a step's Why line.
func kindName(k guestv1.GuestMountKind) string {
	switch k {
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_VIRTIOFS:
		return "virtiofs"
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_TMPFS:
		return "tmpfs"
	case guestv1.GuestMountKind_GUEST_MOUNT_KIND_BIND:
		return "bind"
	default:
		return "unspecified"
	}
}

// tmpfsData renders a tmpfs option string. A zero or negative size limit means
// unbounded, which is the tmpfs default (half of RAM) — the overlay upper is
// never left at that default; see UpperSizeBytes.
func tmpfsData(sizeLimitBytes int64) string {
	if sizeLimitBytes <= 0 {
		return "mode=1777"
	}
	return fmt.Sprintf("mode=1777,size=%d", sizeLimitBytes)
}

// Per-container rootfs composition paths.

// ContainerLowerDir is where a container's read-only virtiofs rootfs share is
// mounted.
func ContainerLowerDir(name string) string { return path.Join(GuestRoot, "lower", name) }

// ContainerUpperTmpfs is the tmpfs holding a container's overlay upper and
// work directories.
func ContainerUpperTmpfs(name string) string { return path.Join(GuestRoot, "upper", name) }

// ContainerUpperDir and ContainerWorkDir are the overlay's two writable
// directories, both inside ContainerUpperTmpfs (overlayfs requires them on the
// same filesystem).
func ContainerUpperDir(name string) string { return path.Join(ContainerUpperTmpfs(name), "upper") }

// ContainerWorkDir is overlayfs's private work directory.
func ContainerWorkDir(name string) string { return path.Join(ContainerUpperTmpfs(name), "work") }

// ContainerRootDir is the composed rootfs the container is chrooted into.
func ContainerRootDir(name string) string { return path.Join(GuestRoot, "root", name) }

// DefaultUpperSizeBytes bounds one container's overlay upper when the guest's
// RAM is unknown.
const DefaultUpperSizeBytes int64 = 64 << 20

// upperSizeFloor and upperSizeCap bound the derived per-container size.
const (
	upperSizeFloor int64 = 16 << 20
	upperSizeCap   int64 = 1 << 30
)

// UpperSizeBytes is the size bound for one container's overlay upper tmpfs,
// given the guest's total RAM and the number of containers sharing it.
//
// An unbounded upper is the failure this exists to prevent. tmpfs defaults to
// half of RAM and is charged to the guest's memory, so a container that writes
// a runaway file into its own rootfs consumes guest RAM until the kernel OOM
// killer fires — and the kill lands on the WORKLOAD, which is then reported as
// an OOMKill the pod's memory request cannot explain. Bounding the upper turns
// that into an ENOSPC at the write that caused it.
//
// The rule: half the guest's RAM, shared equally across the containers, clamped
// to [upperSizeFloor, upperSizeCap]. Half leaves the other half for the
// workloads and the kernel; equal shares mean one container cannot starve
// another's rootfs. An unknown RAM size falls back to DefaultUpperSizeBytes
// rather than to unbounded.
func UpperSizeBytes(memTotalBytes int64, containers int) int64 {
	if memTotalBytes <= 0 || containers <= 0 {
		return DefaultUpperSizeBytes
	}
	per := memTotalBytes / 2 / int64(containers)
	if per < upperSizeFloor {
		return upperSizeFloor
	}
	if per > upperSizeCap {
		return upperSizeCap
	}
	return per
}

// EtcBindFiles are the pod-level files bound into every container's /etc.
//
// A container is chrooted into its own composed rootfs, so the guest's /etc is
// invisible to it and the image's own /etc/resolv.conf (frequently a stale
// build-time copy) would win. The kubelet contract is that the pod's DNS
// configuration, hosts file, and hostname are what the container sees, so each
// is bound over the image's copy — read-only, because a workload rewriting its
// own resolv.conf must not be able to redirect the pod's DNS.
var EtcBindFiles = []string{"resolv.conf", "hosts", "hostname"}

// EtcBinds is the per-container /etc bind set: one read-only bind per
// EtcBindFiles entry, from the pod-level rendered copy under EtcDir onto the
// container's own path.
func EtcBinds(container string) []MountStep {
	root := ContainerRootDir(container)
	out := make([]MountStep, 0, 2*len(EtcBindFiles))
	for _, f := range EtcBindFiles {
		step := MountStep{
			Source:      path.Join(EtcDir, f),
			Target:      path.Join(root, "etc", f),
			Options:     []MountOption{OptionBind},
			TouchTarget: true,
			MkdirExtra:  []string{path.Join(root, "etc")},
			ResolveRoot: root,
			Why:         "the chroot shadows the guest /etc: " + f + " is the kubelet contract",
		}
		out = append(out, readOnlyBind(step)...)
	}
	return out
}

// RootfsMounts is a container's rootfs composition: the read-only virtiofs
// lower, the size-bounded tmpfs upper, and the overlay that stacks them, in
// the order they must be applied.
//
// metacopy=on is set because the lower layer is a virtiofs share of a host
// tree owned by the daemon's unprivileged uid: without it, a chown or chmod of
// a large file copies the whole file up into the tmpfs upper (guest RAM) just
// to change its metadata.
func RootfsMounts(name, rootfsTag string, upperSizeBytes int64) ([]MountStep, error) {
	if err := validTag(rootfsTag); err != nil {
		return nil, fmt.Errorf("container %q rootfs: %w", name, err)
	}
	lower, upperFS := ContainerLowerDir(name), ContainerUpperTmpfs(name)
	upper, work, root := ContainerUpperDir(name), ContainerWorkDir(name), ContainerRootDir(name)
	return []MountStep{
		{
			Source: rootfsTag, Target: lower, FSType: "virtiofs",
			Options:     []MountOption{OptionReadOnly, OptionNoSuid, OptionNoDev},
			MkdirTarget: true,
			Why:         "rootfs lower: read-only at the VZ device too, this mirrors it",
		},
		{
			Source: "tmpfs", Target: upperFS, FSType: "tmpfs",
			Options:     []MountOption{OptionNoSuid, OptionNoDev},
			Data:        fmt.Sprintf("mode=0755,size=%d", upperSizeBytes),
			MkdirTarget: true,
			Why:         "rootfs upper: bounded so a runaway write is ENOSPC, not a guest OOM",
		},
		{
			Source: "overlay", Target: root, FSType: "overlay",
			Options: []MountOption{OptionNoSuid, OptionNoDev},
			Data: fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=on",
				lower, upper, work),
			MkdirTarget: true,
			MkdirExtra:  []string{upper, work},
			Why:         "rootfs: the writable composition the container is chrooted into",
		},
	}, nil
}

// ContainerKernelFS plans the kernel filesystems a container needs beyond its
// rootfs and its /dev: a fresh procfs at /proc and a writable cgroup2 hierarchy
// at /sys/fs/cgroup.
//
// # Why every container needs these
//
// A container's rootfs comes out of an OCI image, and the chroot cuts it off
// from the guest's own /proc and /sys/fs/cgroup — so before this existed a vm
// container had NEITHER. That is not cosmetic: a runc-based build worker
// (buildkitd's default) reads /proc/self and mounts its own /proc inside each
// container it runs, and its cgroup manager writes the cgroup2 hierarchy to
// create per-build sub-cgroups; both fail outright against an empty chroot. The
// same is true of any workload that reads /proc/self/status or /proc/meminfo.
//
// # A FRESH proc, never the host's
//
// The mount is a fresh procfs instance, not a bind of the guest's /proc. There
// is no pid namespace here (containers are chroot-only — see the package doc's
// ceilings), so the instance still shows GUEST-WIDE pids: /proc/self and
// /proc/<pid> resolve, but a container sees every process in the guest. That is
// the honest state and it does NOT block buildkit's runc, which reads
// /proc/self and mounts its own private /proc inside the container it builds.
//
// # cgroup2 attaches WITHOUT a sysfs parent
//
// cgroup2 is an independent filesystem type; it does not need a sysfs mounted at
// /sys first. Only the mountpoint directory has to exist, which MkdirTarget
// creates (os.MkdirAll makes <root>/sys and <root>/sys/fs on the way). So no
// sysfs is mounted by default and the container's /sys is otherwise empty —
// matching the minimal-surface posture the rest of this plan keeps.
//
// # It carries NO fs data — a plain second mount, never "nsdelegate"
//
// This is the SECOND mount of cgroup2. There is exactly one unified cgroup2
// hierarchy per cgroup namespace (a single kernel superblock), and PseudoMounts
// already mounted it at the guest root /sys/fs/cgroup — the first mount, which
// is the one that carries "nsdelegate". A second mount that passes a
// cgroup-root flag ("nsdelegate", "memory_recursiveprot", …) comes up EMPTY:
// mountinfo lists a cgroup2 at the target, but the directory has no
// cgroup.controllers and no cgroup.procs, so runc reports "no cgroup mount
// found in mountinfo" and buildkitd's worker fails. Passing NO fs data roots
// the mount at the process's cgroup-namespace-root cgroup and exposes the full
// interface (cgroup.controllers, cgroup.procs, the delegated controller files).
// This was root-caused live 2026-09-02: a fresh `mount -t cgroup2 none
// /sys/fs/cgroup` with no data, stacked over the empty #119 mount, immediately
// showed the populated hierarchy — the same plain form the mudkitty prototype
// uses. The nsdelegate delegation semantics still apply to this view: they are a
// property of the single hierarchy, set once by the first (guest-root) mount,
// not re-declared per mount. Without a
// cgroup namespace the mount is a view of the guest-wide unified hierarchy, so
// it is a metering/build aid, not an isolation boundary; a container that can
// write cgroup.procs there could re-parent itself, exactly the chroot-only
// ceiling the package doc already records. A pod that needs a full /sys mounts
// its own sysfs (the guest root can) — the same escape hatch loop devices take.
//
// # Yielding to the pod
//
// Like ContainerDev, a pod-declared mount that covers /proc or /sys/fs/cgroup
// wins: the covered step is OMITTED here so the pod's mount is the only one at
// that path rather than a second mount stacked over a shadowed one. The pod's
// mount is then re-exposed inside the container by containerVisibleMounts.
func ContainerKernelFS(name string, podMounts []MountStep) []MountStep {
	root := ContainerRootDir(name)
	hardened := []MountOption{OptionNoSuid, OptionNoDev, OptionNoExec}
	var out []MountStep

	if !shadowedByPodMount(podMounts, "/proc") {
		out = append(out, MountStep{
			Source: "proc", Target: path.Join(root, "proc"), FSType: "proc",
			Options:     hardened,
			MkdirTarget: true,
			ResolveRoot: root,
			Why:         "a fresh procfs: /proc/self and /proc/meminfo the container and its runc worker read",
		})
	}

	if !shadowedByPodMount(podMounts, "/sys/fs/cgroup") {
		out = append(out, MountStep{
			Source: "cgroup2", Target: path.Join(root, "sys/fs/cgroup"), FSType: "cgroup2",
			Options: append(append([]MountOption{}, hardened...), OptionNoAtime),
			// No Data: this is the SECOND mount of the single unified cgroup2
			// hierarchy (PseudoMounts already mounted it at the guest root). A
			// second mount that passes a cgroup-root flag like "nsdelegate"
			// comes up EMPTY — mountinfo shows cgroup2 but the directory has no
			// cgroup.controllers or cgroup.procs, and runc then fails "no cgroup
			// mount found in mountinfo". A plain mount with no fs data roots
			// correctly at the cgroup-namespace root and shows the full
			// hierarchy. See the doc comment.
			MkdirTarget: true,
			ResolveRoot: root,
			Why:         "a writable cgroup2 hierarchy: buildkitd's runc worker creates per-build sub-cgroups here",
		})
	}

	return out
}

// containerVisibleMounts rebases the pod-level mounts that fall inside a
// container's rootfs so they are visible after the chroot, as recursive binds
// from the pod-level mount onto the container's path.
//
// A pod mount is performed once at the guest level and re-exposed per
// container, rather than mounted N times: a virtiofs share mounted twice is
// two independent mounts of one host tree, and a PVC mounted twice would have
// two page caches over the same files.
//
// Targets are ordered shortest-first so a nested mount is never shadowed by
// the mount that would otherwise be stacked over its parent afterwards, and
// the read-only expansion happens after that ordering so each bind keeps its
// remount immediately behind it. The recursive read-only remount applies to
// the top mount only; a submount of a read-only pod mount is read-only already
// because the pod-level mount it propagates from is.
func containerVisibleMounts(name string, pod []MountStep) []MountStep {
	root := ContainerRootDir(name)
	type rebase struct {
		target   string
		readOnly bool
	}
	var ordered []rebase
	at := map[string]int{} // target -> index into ordered
	for _, m := range pod {
		ro := hasOption(m.Options, OptionReadOnly)
		if i, seen := at[m.Target]; seen {
			// A target contributes SEVERAL steps — a bind and its remount, a
			// staged mount and the remount that makes it read-only — and the
			// read-only verdict belongs to the pair, not to whichever step came
			// first. Reading only the first step missed every bind whose
			// read-only lives on its remount, and re-exposed a credential bind
			// into each container with no explicit remount of its own, leaving it
			// read-only by inheritance alone.
			ordered[i].readOnly = ordered[i].readOnly || ro
			continue
		}
		at[m.Target] = len(ordered)
		ordered = append(ordered, rebase{target: m.Target, readOnly: ro})
	}
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i].target) < len(ordered[j].target) })

	var out []MountStep
	for _, r := range ordered {
		step := MountStep{
			Source:      r.target,
			Target:      path.Join(root, r.target),
			Options:     []MountOption{OptionRBind},
			MkdirTarget: true,
			ResolveRoot: root,
			Why:         "pod mount " + r.target + " re-exposed inside the container rootfs",
		}
		if r.readOnly {
			out = append(out, readOnlyBind(step)...)
			continue
		}
		out = append(out, step)
	}
	return out
}

// hasOption reports whether opts contains want.
func hasOption(opts []MountOption, want MountOption) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}
