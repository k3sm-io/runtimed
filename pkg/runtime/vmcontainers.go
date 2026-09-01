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

package runtime

import (
	"context"
	"errors"
	"fmt"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// the VM POD'S CONTAINER mapper (M11.2-d11).
//
// It is the PRODUCER the guest-spec composer was written without: pkg/sandbox
// composes guest-spec.json from VMSpec.Containers, and until this file nothing
// stamped that field, so every vm pod booted with an empty container list and
// its guest init refused the pod with its own reason (guestinit.Plan: "the pod
// has no containers").
//
// every Kubernetes indirection is resolved here, on the host, because the guest
// has no cluster access: the argv is the four-quadrant merge of the pod spec
// against the image config, the environment is fully expanded "KEY=value"
// entries, and the identity is numeric. The merge is pkg/image.MergeRunSpec —
// the same function the host-process spine merges with (resolveBinary) — so a
// container's argv, env and working directory do not depend on which rung its
// pod was routed to.

// errVMHostBinaryImage reports a container whose image is the M0 absolute-path
// host-binary convention (or the "native" sentinel) on the vm path.
//
// The convention names a Mach-O on this Mac; a vm pod's process runs inside a
// Linux guest, which cannot exec one and cannot even see the host filesystem.
// So it is refused where the box is read, with the reference quoted, rather than
// crossing into a guest as an argv[0] that would fail as a bare ENOENT with no
// account of why. Compare with errors.Is.
var errVMHostBinaryImage = errors.New("the host-binary image convention has no meaning in a Linux guest")

// errVMUnresolvableUser reports an image whose USER directive is a NAME while
// the pod supplies no numeric runAsUser.
//
// It is a fail-closed refusal, and it is about a privilege question rather than
// an expressiveness one. The host will not resolve a name out of the image's own
// /etc/passwd (that file is registry-supplied content inside the very tree being
// run — the rule pkg/image.MergeRunSpec states for runAsNonRoot), and guest/v1's
// GuestContainer carries uid/gid as NUMBERS with no field for the name, so the
// guest cannot be told which user to resolve either. The remaining alternative
// would be to stamp uid 0 and run as root a container whose image asked to be
// someone else — a silent privilege promotion. Refusing names the gap instead.
//
// Closing it is an apis change (a user string on GuestContainer, resolved in the
// guest against the container rootfs at exec time); it is filed as B193 and is
// deliberately not carved here. Compare with errors.Is.
var errVMUnresolvableUser = errors.New("the image runs as a named user the host cannot resolve and the guest cannot be told")

// errVMSidecarUnexpressible reports a native sidecar (an init container with
// restartPolicy: Always) on the vm path.
//
// guest/v1 carries one ordering bit per container (GuestContainer.init), which
// the guest reads as "run to completion before the next container starts". A
// sidecar by definition never exits, so mapping one onto that bit would hang the
// pod's start sequence forever — a boot that never fails and never finishes,
// which is strictly worse to operate than a refusal. The ceiling is recorded on
// the guest's own side too (guestinit.StartStep); this is the host declining to
// walk into it. Compare with errors.Is.
var errVMSidecarUnexpressible = errors.New("a native sidecar cannot be expressed in the guest's start ordering")

// errVMNoRootfsShare reports a share plan carrying no container-rootfs share.
// Every container mounts its rootfs lower layer BY TAG, so a plan without one
// describes a pod no guest can compose. Compare with errors.Is.
var errVMNoRootfsShare = errors.New("the share plan carries no container rootfs share")

// vmContainer pairs a container with the list it was declared in.
type vmContainer struct {
	spec *runtimev1.Container
	init bool
}

// vmContainerOrder returns the pod's containers in START order: every init
// container, in declaration order, then every main container.
//
// The order is produced here and carried as a list, because that is the only
// ordering guest/v1 can express — GuestSpec.containers is documented as being in
// start order and GuestContainer.init is the single bit that says which phase a
// container belongs to. It matches the order mount.ComputeSharePlan walks its
// own container lists in, so the two host-side derivations of "the pod's
// containers" cannot disagree about membership.
func vmContainerOrder(box *runtimev1.PodBox) []vmContainer {
	out := make([]vmContainer, 0, len(box.GetInitContainers())+len(box.GetContainers()))
	for _, c := range box.GetInitContainers() {
		out = append(out, vmContainer{spec: c, init: true})
	}
	for _, c := range box.GetContainers() {
		out = append(out, vmContainer{spec: c})
	}
	return out
}

// vmRootfsShareTag returns the tag of the share carrying a container's read-only
// rootfs lower layer, AS the SHARE PLAN named IT.
//
// It reads the tag off the plan rather than restating the constant at the stamp
// site, so the two cannot drift: pkg/mount is the single authority on what a
// pod's shares are called, and a plan that stopped emitting the share fails here
// — where both the plan and the containers are in hand — instead of as a
// virtiofs mount failure inside a booted guest.
//
// ceiling, recorded rather than hidden: the plan carries one rootfs share for
// the whole pod (mount.ShareTagRootfs, rooted at the pod data volume), so every
// container of a vm pod is given the same lower layer today. A pod whose
// containers run different images therefore cannot yet be composed faithfully —
// per-container (and per-layer) rootfs shares are the rootfs-builder
// deliverable's to add, and when they arrive this function is the one place that
// has to learn to select among them.
func vmRootfsShareTag(plan mount.SharePlan) (string, error) {
	for _, s := range plan.Shares {
		if s.Tag == mount.ShareTagRootfs {
			return s.Tag, nil
		}
	}
	return "", errVMNoRootfsShare
}

// resolveVMContainers resolves every container of a vm pod into the plain-data
// carrier the guest boot spec is composed from (sandbox.VMContainer), in start
// order.
//
// what IT does and deliberately does not DO. Each container is pulled — the
// merge needs the image's own Entrypoint/Cmd/Env/WorkingDir/User, and a pull is
// the only way to hold a verified config for them — and its blobs are recorded
// as this pod's reachability roots before the pull lease is released, in that
// order, exactly as the host-process spine does it. It is not materialized:
// composing the guest's rootfs lower layer out of those blobs is the
// rootfs-builder deliverable (see vmRootfsShareTag for the share-plan ceiling it
// closes), and materializing every container's image into the one pod-wide
// rootfs share would have them overwrite each other.
//
// none OF the HOST-PROCESS RESOLUTION HAPPENS. argv[0] is not resolved against a
// host rootfs (resolveImageArgv0's containment check is about a path this daemon
// is about to exec; the guest execs inside its own chroot, and no host path ever
// crosses the boundary), nothing is ad-hoc signed or signature-gated (a Linux ELF
// is not a Mach-O), and the environment is the MERGE only — containerEnv's TMPDIR
// and DYLD inserts are macOS host-process facts that would be noise or worse
// inside a guest.
//
// backend is the pod's RESOLVED sandbox backend, threaded rather than restated so
// the image-platform policy of these pulls is the rung the pod is actually
// confined by (see pullPolicy).
func (r *Runtime) resolveVMContainers(ctx context.Context, box *runtimev1.PodBox, plan mount.SharePlan, backend runtimev1.SandboxBackend, rootfs string) ([]sandbox.VMContainer, runtimev1.FailureReason, error) {
	rootfsTag, err := vmRootfsShareTag(plan)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: pod %s: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	ordered := vmContainerOrder(box)
	// The plan carries ONE rootfs share for the whole pod (vmRootfsShareTag's
	// recorded ceiling), so exactly one image can be materialized into it: the
	// first container's, in start order. A pod naming a second image is a pod
	// this layout cannot represent — the second container would run its own
	// merged argv against the first container's tree. That is logged loudly
	// rather than overlaid: unpacking image N over image 1 would produce a tree
	// no manifest describes, which is strictly worse than a legible warning
	// beside the same broken pod the empty-rootfs build already produced.
	// Per-container rootfs shares are the layout change that lifts this, and
	// vmRootfsShareTag is where the selection would then live.
	if extra, ok := vmExtraRootfsImage(ordered); ok {
		r.log.Warn("vm pod names more than one image; only the first is materialized into the pod-wide rootfs share",
			"pod", box.GetPodId(), "rootfs_image", ordered[0].spec.GetImage(), "unmaterialized_image", extra)
	}
	out := make([]sandbox.VMContainer, 0, len(ordered))
	for i, e := range ordered {
		// The pod's single rootfs share is materialized once, from the first
		// container in start order.
		dst := ""
		if i == 0 {
			dst = rootfs
		}
		vc, reason, err := r.resolveVMContainer(ctx, box, e, rootfsTag, backend, dst)
		if err != nil {
			return nil, reason, err
		}
		out = append(out, vc)
	}
	return out, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// vmExtraRootfsImage reports the first image in start order that differs from
// the one the pod's single rootfs share will carry, if any — the observable the
// multi-image warning above is made from. An empty image is skipped:
// resolveVMContainer refuses it with its own per-container message.
func vmExtraRootfsImage(ordered []vmContainer) (string, bool) {
	first := ""
	for _, e := range ordered {
		ref := e.spec.GetImage()
		if ref == "" {
			continue
		}
		if first == "" {
			first = ref
			continue
		}
		if ref != first {
			return ref, true
		}
	}
	return "", false
}

// resolveVMContainer resolves one container: pull, read the image config, merge
// it with the pod spec, and map the result onto the guest carrier.
//
// rootfsDest, when non-empty, is the host directory the pod's k3sm.rootfs share
// exports: this container's image is materialized into it (the guest composes
// its root as an overlay over that share). It is set for exactly one container
// per pod — see resolveVMContainers.
func (r *Runtime) resolveVMContainer(ctx context.Context, box *runtimev1.PodBox, e vmContainer, rootfsTag string, backend runtimev1.SandboxBackend, rootfsDest string) (sandbox.VMContainer, runtimev1.FailureReason, error) {
	c := e.spec
	name := c.GetName()
	invalid := func(err error) (sandbox.VMContainer, runtimev1.FailureReason, error) {
		return sandbox.VMContainer{}, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: container %s: %w", errInvalidPodBox, name, err)
	}
	pullFailed := func(err error) (sandbox.VMContainer, runtimev1.FailureReason, error) {
		return sandbox.VMContainer{}, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			fmt.Errorf("container %s: %w", name, err)
	}
	rootfsFailed := func(err error) (sandbox.VMContainer, runtimev1.FailureReason, error) {
		return sandbox.VMContainer{}, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("container %s: %w", name, err)
	}

	ref := c.GetImage()
	switch {
	case ref == "":
		return invalid(errors.New("image is required"))
	case ref == NativeImage || image.IsHostPathReference(ref):
		return invalid(fmt.Errorf("%w: image %q names a host binary, and this pod runs in a Linux guest", errVMHostBinaryImage, ref))
	}
	if e.init && c.GetRestartPolicy() == runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS {
		return invalid(errVMSidecarUnexpressible)
	}

	// The identity the merge reasons about is the same one the container will
	// run as (the container > pod > box precedence chain), so the runAsNonRoot
	// verdict is made about the identity that actually runs — the host-process
	// spine's rule, applied here for the same reason.
	cred := resolveCredential(box, c)

	pullCred, err := r.pullCredential(ctx, box, ref)
	if err != nil {
		return pullFailed(err)
	}
	res, err := r.puller.Pull(ctx, ref, pullCred, pullPolicy(backend), c.GetImagePullPolicy())
	if err != nil {
		return pullFailed(fmt.Errorf("pull image %q: %w", ref, err))
	}
	// RECORD the ROOT, then release the LEASE — the ordering resolveBinary
	// documents: the blobs are on disk and named by nothing until the record
	// exists, so releasing first reopens the window a concurrent reclaim
	// deletes into.
	if err := r.recordPodImage(box.GetPodId(), res.Manifest); err != nil {
		res.Lease.Release()
		return pullFailed(err)
	}
	res.Lease.Release()

	// Materialize the image's layers into the pod's rootfs share (M11.2-d7's
	// unpacker, on the vm spine). Until this call the vm path pulled and then
	// left <podDir>/rootfs EMPTY: the guest mounted an empty lower layer, its
	// first container exec found no /bin/sh, the container exited instantly and
	// guest init powered the VM off with containers=0. The blobs being in the
	// store is not the same fact as the pod's rootfs holding runnable files —
	// MaterializeTree is the one call that turns one into the other.
	//
	// It runs after the lease release for the reason the host-process spine
	// gives (resolveBinary): the reachability root recorded just above is what
	// protects these blobs for the whole of the unpack, and it is durable where
	// the lease expires. The dialect comes from the pod's own backend, so a
	// Linux image is never applied under the native rules.
	//
	// A failure is ROOTFS_SETUP, not IMAGE_PULL: the registry did its part.
	if rootfsDest != "" {
		policy, perr := unpackPolicy(backend)
		if perr != nil {
			return rootfsFailed(perr)
		}
		mat, merr := r.unpacker.MaterializeTree(ctx, res.Manifest, policy, rootfsDest)
		if merr != nil {
			return rootfsFailed(fmt.Errorf("materialize image %q into %s: %w", ref, rootfsDest, merr))
		}
		r.log.Debug("materialized vm pod rootfs",
			"pod", box.GetPodId(), "container", name, "image", ref, "rootfs", rootfsDest,
			"tree", mat.Tree.Key, "tree_cache_hit", mat.Tree.CacheHit, "cloned", mat.Cloned)
	}

	runCfg, err := r.unpacker.ImageRunConfig(res.Manifest)
	if err != nil {
		return pullFailed(fmt.Errorf("read image config for %q: %w", ref, err))
	}
	run, err := image.MergeRunSpec(runCfg, image.RunSpecRequest{
		Container:    c,
		RunAsUID:     int64(cred.UID),
		RunAsNonRoot: effectiveRunAsNonRoot(c),
	})
	if err != nil {
		// A merge refusal is a POD-SPEC verdict (image.ErrRunSpecInvalid: no
		// command anywhere, or an identity that contradicts runAsNonRoot), not a
		// registry failure — the operator's remedy is to change the container.
		return sandbox.VMContainer{}, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	// The uid is undetermined exactly when the pod set no runAsUser and the
	// image's USER did not parse as a number — the RunSpec contract, read rather
	// than re-derived by parsing the directive a second time here.
	if !run.HasUID && run.User != "" {
		return invalid(fmt.Errorf("%w: image user %q, and no runAsUser was set", errVMUnresolvableUser, run.User))
	}

	// The supplemental set is the resolved credential's, which already carries
	// the pod's fsGroup alongside the primary gid (resolveCredential). The gid
	// comes from the securityContext chain alone: the group half of an image
	// USER directive ("1000:1000") is not carried across guest/v1 either, the
	// same B193 gap the uid half fails closed on — but a lost group half cannot
	// promote a container to root, so it is recorded here rather than refused.
	gids := make([]int64, 0, len(cred.Groups))
	for _, g := range cred.Groups {
		gids = append(gids, int64(g))
	}
	return sandbox.VMContainer{
		Name:      name,
		Init:      e.init,
		RootfsTag: rootfsTag,
		// The merged vector, unsplit: guest/v1 defines argv as command + args
		// and states the merge already happened host-side, so the composer
		// carries it whole (sandbox.guestContainers).
		Argv:             run.Argv,
		Env:              run.Env,
		WorkingDir:       run.WorkingDir,
		TTY:              c.GetTty(),
		Stdin:            c.GetStdin(),
		UID:              run.UID,
		GID:              int64(cred.GID),
		SupplementalGIDs: gids,
	}, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}
