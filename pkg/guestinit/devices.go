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
)

// DefaultDevices is the device set every container gets, and the ONLY one.
//
// It is the OCI runtime-spec default set: the five character devices any libc,
// shell or runtime assumes exist, plus /dev/tty. A container's rootfs comes out
// of an OCI image, whose /dev is empty by construction, and the chroot cuts it
// off from the guest's devtmpfs — so before this list existed a container had NO
// /dev at all. That is not a cosmetic gap: `echo x > /dev/null` CREATED A
// REGULAR FILE in the overlay upper and grew it forever, /dev/urandom was
// missing under every language runtime that seeds from it, and any program that
// opened /dev/tty failed.
//
// # The allowlist IS the security boundary
//
// The set is enumerated positively and the guest's /dev is never re-exposed
// wholesale. The device that must never appear is /dev/vsock: the guest agent is
// served on AF_VSOCK, the guest kernel is built with vsock loopback, and a
// container holding /dev/vsock could therefore DIAL ITS OWN POD'S AGENT — an
// interface that starts processes in any container of the pod, reads every
// container's logs, and stops the pod. Nothing in the container is supposed to
// be able to do any of that, and no capability check stands between it and the
// agent: the pod id is asserted, and the container is in that pod.
//
// The same reasoning retires the whole class rather than one node — /dev/mem,
// /dev/kmsg, the block devices, the virtio consoles. An additive list cannot
// leak one by omission the way a denylist can, which is why this is a list of
// what IS exposed.
var DefaultDevices = []string{"null", "zero", "full", "random", "urandom", "tty"}

// DefaultShmSizeBytes bounds a container's private /dev/shm.
//
// 64 MiB is the size every other runtime gives a container that did not ask for
// one, so a workload tuned against docker or containerd finds what it expects.
// It is BOUNDED for the reason UpperSizeBytes is: a guest's tmpfs is charged to
// guest RAM, an unbounded one defaults to half of it, and a runaway write into
// /dev/shm would be reported as an OOM kill of the workload with nothing to
// explain it. A pod that needs more declares a Memory emptyDir at /dev/shm,
// which replaces this one wholesale — see ContainerDev.
const DefaultShmSizeBytes int64 = 64 << 20

// LinkStep is one symlink the guest creates inside a container's composed
// rootfs. It is a separate step type from MountStep because a symlink is not a
// mount and the two differ in the one place that matters: how the path is
// resolved (see ResolveRoot).
type LinkStep struct {
	// Target is the absolute GUEST path of the symlink to create.
	Target string

	// LinkTo is the symlink's content, as the CONTAINER will read it — so it is
	// either relative, or absolute against the container's root.
	LinkTo string

	// ResolveRoot, when non-empty, is the container root Target lies inside.
	//
	// Only Target's PARENT DIRECTORY is resolved with chroot semantics; the
	// final component never is. That is the one way this differs from
	// MountStep.ResolveRoot, and it is not a detail: mount(2) follows a symlink
	// at the target, so resolving the last component is right there — while
	// symlink(2) does not, and an image that already ships /dev/ptmx as a link
	// to pts/ptmx would otherwise have that link followed, and the guest would
	// try to replace the devpts multiplexer itself.
	ResolveRoot string

	// Why is a one-line rationale for the boot log.
	Why string
}

// DevPlan is one container's minimal /dev: the device binds, the private devpts
// instance, the ptmx symlink, and the shm tmpfs.
type DevPlan struct {
	// Mounts are the mount steps, in application order.
	Mounts []MountStep

	// Links are the symlinks, created after Mounts.
	Links []LinkStep

	// PtsDir is the GUEST path of the container's private devpts instance, or
	// empty when the container has none because a pod mount covers it. It is
	// what ExecPTYOrigin decides an exec's pty origin from.
	PtsDir string
}

// ContainerDev plans the minimal /dev for one container.
//
// # Why a PRIVATE devpts instance
//
// Each container gets its own devpts mount rather than a bind of the guest's.
// Linux gives every devpts mount a separate instance with its own pty index
// space, so a container can only ever see, and only ever open, the ptys
// allocated within it. Sharing the guest's instance would put every container's
// terminals — and every exec's — in one namespace that any of them could open by
// index.
//
// ptmxmode=0666 is what lets a container process that is not root allocate a pty
// at all (the container runs as the image's user); mode=0620,gid=5 is the
// conventional tty-group slave mode every getty and shell expects.
//
// # Yielding to the pod
//
// A pod may declare a mount that covers one of these paths — a Memory emptyDir
// at /dev/shm is the common one, and it is how a pod asks for a bigger shm.
// Anything this function would place at a path the pod has claimed is OMITTED,
// so the pod's mount is the only one there rather than a second mount stacked
// over a shadowed one. The check is by PATH COVERAGE, not by equality: a pod
// mounting /dev itself takes the whole tree, which also means such a container
// has no private devpts and ExecPTYOrigin falls back to the guest's.
func ContainerDev(name string, podMounts []MountStep) DevPlan {
	root := ContainerRootDir(name)
	var plan DevPlan

	for _, dev := range DefaultDevices {
		guestPath := path.Join("/dev", dev)
		if shadowedByPodMount(podMounts, guestPath) {
			continue
		}
		plan.Mounts = append(plan.Mounts, MountStep{
			Source:      guestPath,
			Target:      path.Join(root, "dev", dev),
			Options:     []MountOption{OptionBind},
			TouchTarget: true,
			ResolveRoot: root,
			// A BIND, not a mknod: this init is not guaranteed to be able to
			// create device nodes inside the overlay upper (a tmpfs mounted
			// nodev refuses them outright), and binding the guest's own node is
			// the mechanism every other mount in this plan already uses.
			Why: "the OCI default device " + guestPath + "; without it the container has no /dev",
		})
	}

	if !shadowedByPodMount(podMounts, ContainerPtsDir) {
		plan.PtsDir = path.Join(root, ContainerPtsDir)
		plan.Mounts = append(plan.Mounts, MountStep{
			Source: "devpts", Target: plan.PtsDir, FSType: "devpts",
			Options:     []MountOption{OptionNoSuid, OptionNoExec},
			Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			MkdirTarget: true,
			ResolveRoot: root,
			Why:         "a devpts instance private to this container: its own pty index space",
		})
		plan.Links = append(plan.Links, LinkStep{
			Target: path.Join(root, "dev", "ptmx"),
			// RELATIVE, so it resolves to this container's own instance however
			// the path is reached, and cannot be made to point at the guest's.
			LinkTo:      "pts/ptmx",
			ResolveRoot: root,
			Why:         "/dev/ptmx is the container's own multiplexer, not the guest's",
		})
	}

	if !shadowedByPodMount(podMounts, "/dev/shm") {
		plan.Mounts = append(plan.Mounts, MountStep{
			Source: "tmpfs", Target: path.Join(root, "dev", "shm"), FSType: "tmpfs",
			Options:     []MountOption{OptionNoSuid, OptionNoDev},
			Data:        fmt.Sprintf("mode=1777,size=%d", DefaultShmSizeBytes),
			MkdirTarget: true,
			ResolveRoot: root,
			Why:         "the container's default /dev/shm; a pod-declared mount at this target replaces it",
		})
	}

	return plan
}

// shadowedByPodMount reports whether a pod-level mount covers guestPath — the
// path itself, or any ancestor of it.
//
// Coverage rather than equality is the point: a pod mounting /dev takes
// /dev/shm and /dev/pts with it, and a per-container mount placed underneath
// would be invisible to the container while still costing a mount.
func shadowedByPodMount(podMounts []MountStep, guestPath string) bool {
	for _, m := range podMounts {
		if mountPathUnder(guestPath, m.Target) {
			return true
		}
	}
	return false
}
