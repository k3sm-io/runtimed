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
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
	"k3sm.io/runtimed/pkg/volume"
)

// hasExposeVolume reports whether box declares any exposure volume.
func hasExposeVolume(box *runtimev1.PodBox) bool {
	for _, v := range box.GetVolumes() {
		if v.GetExpose() != nil {
			return true
		}
	}
	return false
}

// exposeDataRoot is the data root whose expose/ tree holds this node's
// exposures: Config.DataRoot when set, else the runtime root. The profile
// denies the exposures root under both (sandbox exposeRoots).
func (r *Runtime) exposeDataRoot() string {
	if r.cfg.DataRoot != "" {
		return filepath.Clean(r.cfg.DataRoot)
	}
	return filepath.Clean(r.cfg.Root)
}

// lookupAccountName is the node's current name for uid (os/user).
func lookupAccountName(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// exposeGrantsFromFile reads the node's exposure grants from the host-share
// file (Config.HostSharesFile), as hostShares reads its shares: an unset file
// grants nothing.
func (r *Runtime) exposeGrantsFromFile() ([]hostshare.ExposeGrant, error) {
	if r.cfg.HostSharesFile == "" {
		return nil, nil
	}
	eff, err := hostshare.LoadEffective(r.cfg.HostSharesFile)
	if err != nil {
		return nil, err
	}
	return eff.Exposes, nil
}

// authorizeExposures decides box's exposure volumes against the node's
// grants, read now from the root-owned file and never from the request. A
// box with no exposure volume gets nil without the file being read. A
// refusal is errInvalidPodBox wrapping hostshare.ErrNotExposed.
func (r *Runtime) authorizeExposures(box *runtimev1.PodBox) ([]hostshare.Exposure, error) {
	if !hasExposeVolume(box) {
		return nil, nil
	}
	load, name := r.exposeGrants, r.accountName
	if load == nil {
		load = r.exposeGrantsFromFile
	}
	if name == nil {
		name = lookupAccountName
	}
	grants, err := load()
	if err != nil {
		return nil, fmt.Errorf("%w: pod %s: read exposure grants: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	exps, err := hostshare.AuthorizeExposures(grants, box, r.exposeDataRoot(), name)
	if err != nil {
		return nil, fmt.Errorf("%w: pod %s: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	return exps, nil
}

// prepareExposures is createPod's fail-fast half, run before anything about
// the pod exists on disk: a node with no ExposeACL, an exposure the grants do
// not admit or a mount path that would nest refuses the pod here
// (errInvalidPodBox).
func (r *Runtime) prepareExposures(box *runtimev1.PodBox) ([]hostshare.Exposure, error) {
	if !hasExposeVolume(box) {
		return nil, nil
	}
	if r.exposeACL == nil {
		return nil, fmt.Errorf("%w: pod %s: %w: %w", errInvalidPodBox, box.GetPodId(), hostshare.ErrNotExposed, volume.ErrNoExposeACL)
	}
	if _, err := volume.PlanExposures(box, r.exposeDataRoot()); err != nil {
		return nil, fmt.Errorf("%w: pod %s: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	return r.authorizeExposures(box)
}

// bindExposures materializes the authorized exposures and returns their
// leaves, the profile's exposure scope. Each grant is logged at Info: the
// node-side record of which account was let into which pod's data.
func (r *Runtime) bindExposures(ctx context.Context, box *runtimev1.PodBox, rootfs string, exps []hostshare.Exposure) ([]string, error) {
	if len(exps) == 0 {
		return nil, nil
	}
	bindings, err := volume.BindExposures(ctx, r.exposeACL, box, rootfs, r.exposeDataRoot(), exps)
	if err != nil {
		return nil, err
	}
	leaves := make([]string, 0, len(bindings))
	for i, b := range bindings {
		access := "read"
		if b.ReadWrite {
			access = "read-write"
		}
		r.log.Info("exposure granted", "pod", box.GetPodId(), "namespace", box.GetNamespace(), "name", box.GetName(),
			"volume", b.Volume, "path", b.Dir, "uid", b.UID, "user", exps[i].User, "access", access)
		leaves = append(leaves, b.Dir)
	}
	return leaves, nil
}

// exposePaths is the pure derivation of box's exposure leaves for the
// profile (volume.PlanExposures): what createPod bound, re-derived from the
// spec alone so a re-attach compiles the same profile without any I/O.
func (r *Runtime) exposePaths(box *runtimev1.PodBox) ([]string, error) {
	if !hasExposeVolume(box) {
		return nil, nil
	}
	return volume.PlanExposures(box, r.exposeDataRoot())
}

// recheckAttachedExposures re-decides a re-attached pod's exposures against
// the grants as they are now. A grant root revoked while the daemon was down
// takes the account's ACL entry off each leaf, logged at Warn; the pod itself
// keeps running (it is the account's access being withdrawn, not the pod's).
func (r *Runtime) recheckAttachedExposures(box *runtimev1.PodBox) {
	if !hasExposeVolume(box) {
		return
	}
	_, authErr := r.authorizeExposures(box)
	if authErr == nil {
		return
	}
	leaves, err := r.exposePaths(box)
	if err != nil {
		r.log.Warn("attach: exposure no longer admitted and its leaves cannot be derived", "pod", box.GetPodId(), "reason", authErr, "err", err)
		return
	}
	uids := map[string]uint32{}
	for _, v := range box.GetVolumes() {
		if x := v.GetExpose(); x != nil {
			if dir, derr := hostshare.ExposeDir(r.exposeDataRoot(), box.GetNamespace(), box.GetName(), v.GetName()); derr == nil {
				uids[dir] = x.GetUid()
			}
		}
	}
	for _, leaf := range leaves {
		uid := uids[leaf]
		if r.exposeACL == nil {
			r.log.Warn("attach: exposure no longer admitted; no ExposeACL to revoke it with", "pod", box.GetPodId(), "path", leaf, "uid", uid, "reason", authErr)
			continue
		}
		if err := r.exposeACL.Revoke(leaf, uid); err != nil {
			r.log.Warn("attach: revoke an exposure no longer admitted", "pod", box.GetPodId(), "path", leaf, "uid", uid, "reason", authErr, "err", err)
			continue
		}
		r.log.Warn("attach: exposure no longer admitted; access revoked", "pod", box.GetPodId(), "path", leaf, "uid", uid, "reason", authErr)
	}
}

// removeExposures deletes box's exposure dirs (pod lifetime), best effort.
func (r *Runtime) removeExposures(box *runtimev1.PodBox) {
	if !hasExposeVolume(box) {
		return
	}
	if err := volume.RemoveExposures(r.exposeDataRoot(), box.GetNamespace(), box.GetName()); err != nil {
		r.log.Warn("remove pod exposures", "pod", box.GetPodId(), "err", err)
	}
}

// sweepExposures removes the exposure dirs of pods this runtime does not
// know: pods deleted while it was down. It runs once at startup, after every
// surviving pod was re-attached, and is skipped while a create is in flight
// (that create may be binding a dir the snapshot does not yet name).
func (r *Runtime) sweepExposures() {
	r.mu.Lock()
	if len(r.creating) > 0 {
		r.mu.Unlock()
		r.log.Info("startup exposure sweep skipped: a pod create is in flight")
		return
	}
	known := map[[2]string]bool{}
	for _, p := range r.pods {
		known[[2]string{p.box.GetNamespace(), p.box.GetName()}] = true
	}
	r.mu.Unlock()
	removed, err := volume.SweepExposures(r.exposeDataRoot(), func(ns, pod string) bool { return known[[2]string{ns, pod}] })
	for _, name := range removed {
		r.log.Info("removed the exposures of a pod that no longer exists", "pod", name)
	}
	if err != nil {
		r.log.Warn("startup exposure sweep", "err", err)
	}
}
