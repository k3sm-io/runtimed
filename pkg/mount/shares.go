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
	"os"
	"path/filepath"
	"sort"
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Host directory modes for the pod-dir share roots. The proj root pools every
// credential-bearing volume of the pod, so it is 0700 and chmod'd exactly
// (MkdirAll would leave an umask-widened or pre-existing mode in place); the
// rootfs and vols roots carry no credential and take the pod dir's own 0750.
// None of these gate the GUEST: virtiofs serves the share under the vmhost
// helper's identity, and a share's writability is the VZ device flag the plan
// carries. They gate the HOST — a share root a host-side reader should not be
// able to list.
const (
	projShareRootMode os.FileMode = 0o700
	shareRootMode     os.FileMode = 0o750
	// volShareDirMode is the per-volume directory mode inside a pooled share,
	// matching the mount-dir mode materializeVolume uses on the native spine.
	volShareDirMode os.FileMode = 0o755
)

// MaterializeShares renders a computed SharePlan's pooled-share content onto
// disk: it creates each pod-dir share root (rootfs / proj / vols), materializes
// every proj-share bind's volume into <projRoot>/<volume name>, and creates
// every vols-share bind's writable <volsRoot>/<volume name> directory. box is
// the pod being created, plan its ComputeSharePlan output, podIP the pod's
// cluster address for status.podIP downward-API projections ("" when the vm
// path has none), and r supplies ConfigMap/Secret data and SA tokens.
//
// This is the filesystem half ComputeSharePlan deliberately does not do (that
// function is pure data — see its doc). Without it a vm pod's proj share root
// never exists and the guest's first bind of an automounted ServiceAccount
// token fails with ENOENT, which is the whole reason this function exists.
//
// Two things it deliberately does NOT do:
//
//   - PVC shares are skipped entirely. Their roots are durable and
//     lifecycle-decoupled; pkg/volume owns creating and seeding them, exactly
//     as Materialize documents for the native spine.
//   - A bind's SubPath is NOT applied here. The guest composes the bind source
//     as <shareRoot>/<SourceRel>/<SubPath> (sandbox.guestMounts), so the host
//     renders the WHOLE volume at <shareRoot>/<SourceRel> and the guest selects
//     within it. Applying the selection here too would narrow it twice.
//
// A volume bound by several containers is materialized once; an identical
// repeat is not an error, and two different volumes claiming one share
// directory is (mirroring Materialize's conflict guard, keyed on the
// per-volume share directory rather than a rebased mount path).
func MaterializeShares(ctx context.Context, box *runtimev1.PodBox, plan SharePlan, podIP string, r Resolver) error {
	if box == nil {
		return errors.New("nil pod box")
	}
	volumes := make(map[string]*runtimev1.Volume, len(box.GetVolumes()))
	for _, v := range box.GetVolumes() {
		volumes[v.GetName()] = v
	}

	// Create the pod-dir share roots up front, whether or not a bind lands in
	// them: a VZ shared-directory device over a missing host dir is a boot
	// failure, and a share the planner emitted but nothing mounted is legal.
	roots := make(map[string]string, len(plan.Shares))
	for _, s := range plan.Shares {
		if strings.HasPrefix(s.Tag, ShareTagPVCPrefix) {
			continue // pkg/volume owns a PVC's data dir
		}
		if s.Root == "" {
			return fmt.Errorf("share %s has an empty root", s.Tag)
		}
		mode := shareRootMode
		if s.Tag == ShareTagProj {
			mode = projShareRootMode
		}
		if err := os.MkdirAll(s.Root, mode); err != nil {
			return fmt.Errorf("create share dir %s (%s): %w", s.Root, s.Tag, err)
		}
		if s.Tag == ShareTagProj {
			if err := os.Chmod(s.Root, mode); err != nil {
				return fmt.Errorf("chmod share dir %s (%s): %w", s.Root, s.Tag, err)
			}
		}
		roots[s.Tag] = s.Root
	}

	// Deterministic container order so a conflict is reported the same way on
	// every run (the plan's Binds is a map).
	cnames := make([]string, 0, len(plan.Binds))
	for name := range plan.Binds {
		cnames = append(cnames, name)
	}
	sort.Strings(cnames)

	// conflict guard: per-volume share dir -> the volume name that claimed it.
	seen := make(map[string]string)
	for _, cname := range cnames {
		for _, b := range plan.Binds[cname] {
			root, ok := roots[b.ShareTag]
			if !ok {
				continue // a PVC share (skipped above); pkg/volume owns it
			}
			// SourceRel is the volume name and becomes a path component here,
			// so it is validated where it turns into one. The planner does not
			// constrain volume names (Kubernetes' own DNS-1123 label rules
			// already make them single-component), so this is the fail-closed
			// guard against a name that would address a sibling or an ancestor
			// of the share root.
			if err := validateVMPathComponent("volume name", b.SourceRel); err != nil {
				return fmt.Errorf("container %s: volume %s: %w", cname, b.VolumeName, err)
			}
			dir := filepath.Join(root, b.SourceRel)
			if prev, dup := seen[dir]; dup {
				if prev == b.VolumeName {
					continue // the same volume mounted by several containers
				}
				return fmt.Errorf("volumes %q and %q both claim share dir %q", prev, b.VolumeName, dir)
			}
			seen[dir] = b.VolumeName

			switch b.ShareTag {
			case ShareTagVols:
				// A default-medium emptyDir is a writable directory and nothing
				// more; the guest binds it out of the writable vols share.
				if err := os.MkdirAll(dir, volShareDirMode); err != nil {
					return fmt.Errorf("create emptyDir share dir %s: %w", dir, err)
				}
			case ShareTagProj:
				vol, ok := volumes[b.VolumeName]
				if !ok {
					return fmt.Errorf("container %s: bind references undefined volume %q", cname, b.VolumeName)
				}
				if _, err := materializeVolume(ctx, box.GetNamespace(), podIP, vol, dir, box, r); err != nil {
					return fmt.Errorf("materialize volume %s: %w", b.VolumeName, err)
				}
			default:
				// Only the two pooled shares are materialized here; a bind out
				// of the rootfs share (or a tag this build does not know) is
				// refused rather than rendered somewhere unintended.
				return fmt.Errorf("container %s: volume %s binds unexpected share tag %q", cname, b.VolumeName, b.ShareTag)
			}
		}
	}
	return nil
}
