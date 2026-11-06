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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"k3sm.io/runtimed/pkg/pathsafe"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// An image volume (runtimev1.ImageVolumeSource) is an OCI artifact the runtime
// has fetched into the node cache and built a read-only view of (pkg/artifact:
// a directory of 0444 clones under <viewsRoot>/<manifest-hex>/<path-set-key>).
// It is never materialized into the pod data volume. On the native spine the
// rebased mount path is a symlink to the view (LinkImageVolumes) and the
// sandbox profile is granted read on that one view directory; on the vm spine
// the view is one read-only share (ComputeSharePlanWithViews).

// ErrImageVolumePaths refuses an image volume that names a subset of the
// artifact's files. This build always mounts the whole artifact, and mounting
// the whole artifact for a caller that asked for a subset is never acceptable.
var ErrImageVolumePaths = errors.New("image volume paths are not supported by this runtime")

// ErrImageView refuses a view directory that is not exactly
// <viewsRoot>/<manifest-hex>/<path-set-key>.
var ErrImageView = errors.New("image volume view is not a view directory")

// viewComponent is the shape of both view path components below the views
// root: the manifest hex and the path-set key are each a hex sha256.
var viewComponent = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ImageViews names the view built for each image volume of a pod.
type ImageViews struct {
	// Root is the views root every view sits two levels under.
	Root string
	// ByVolume maps an image volume's name to its view directory.
	ByVolume map[string]string
}

// ImageVolumes returns the image volumes of box that a container mounts, in
// sorted name order. A volume no container mounts is not returned: it is never
// fetched. A volume with a non-empty paths is ErrImageVolumePaths.
func ImageVolumes(box *runtimev1.PodBox) ([]*runtimev1.Volume, error) {
	mounted := map[string]bool{}
	for _, c := range append(append([]*runtimev1.Container{}, box.GetInitContainers()...), box.GetContainers()...) {
		for _, vm := range c.GetVolumeMounts() {
			mounted[vm.GetName()] = true
		}
	}
	var out []*runtimev1.Volume
	for _, v := range box.GetVolumes() {
		if v.GetImage() == nil || !mounted[v.GetName()] {
			continue
		}
		if len(v.GetImage().GetPaths()) > 0 {
			return nil, fmt.Errorf("volume %s: %w (it names %d paths)", v.GetName(), ErrImageVolumePaths, len(v.GetImage().GetPaths()))
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return out, nil
}

// CheckView refuses dir unless it is exactly <root>/<hex64>/<hex64>: a single
// view, never the views root, a manifest directory, or anything outside them.
// Both operands are compared lexically and must already be absolute and clean.
func CheckView(root, dir string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("%w: %q under %q is not absolute and clean", ErrImageView, dir, root)
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrImageView, dir, err)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || !viewComponent.MatchString(parts[0]) || !viewComponent.MatchString(parts[1]) {
		return fmt.Errorf("%w: %q is not <%s>/<manifest>/<paths>", ErrImageView, dir, root)
	}
	return nil
}

// view returns the checked view for volume name.
func (iv ImageViews) view(name string) (string, error) {
	dir, ok := iv.ByVolume[name]
	if !ok {
		return "", fmt.Errorf("image volume %s has no view", name)
	}
	if err := CheckView(iv.Root, dir); err != nil {
		return "", fmt.Errorf("image volume %s: %w", name, err)
	}
	return dir, nil
}

// LinkImageVolumes places every image volume mount of box into the pod data
// volume dataVol (a pod with no mounted image volume is a no-op): the rebased mount path becomes a symlink to the volume's view
// (to the selected element under it, for a subPath mount, so a subPath into a
// view is a link and never a copy). It returns the view directories the pod's
// sandbox profile must grant read on, sorted and de-duplicated: each is one
// view, never the views root, so a pod can open the files of the artifacts it
// mounts and nothing else in the cache.
//
// The mount walk is planMounts, so an image mount takes part in the same
// undefined-volume, escape and destination-conflict checks as every other
// mount. A pre-existing symlink at the destination is replaced (an idempotent
// re-create); anything else there is refused, as is a destination whose
// parents traverse a symlink.
func LinkImageVolumes(box *runtimev1.PodBox, dataVol string, views ImageViews) ([]string, error) {
	dataVol = filepath.Clean(dataVol)
	if vols, err := ImageVolumes(box); err != nil || len(vols) == 0 {
		return nil, err
	}
	plans, err := planMounts(box, dataVol)
	if err != nil {
		return nil, err
	}
	grants := map[string]bool{}
	for _, pm := range plans {
		if pm.class != classImage {
			continue
		}
		view, err := views.view(pm.vol.GetName())
		if err != nil {
			return nil, err
		}
		target, err := viewTarget(view, pm.mount.GetSubPath())
		if err != nil {
			return nil, fmt.Errorf("volume %s: %w", pm.mount.GetName(), err)
		}
		if err := placeLink(dataVol, pm.dest, target); err != nil {
			return nil, fmt.Errorf("volume %s: %w", pm.mount.GetName(), err)
		}
		grants[view] = true
	}
	return sortedKeys(grants), nil
}

// LinkedImageViews re-derives, from what LinkImageVolumes left on disk, the
// view directories a pod's profile grants: the pure half a re-attaching daemon
// uses, which reads each image mount's link and keeps the view it names. A
// link that no longer names a view under root is an error. A link the pod
// re-pointed at another view yields that view, so the recompiled profile
// differs from the one recorded at create and the attach is refused.
func LinkedImageViews(box *runtimev1.PodBox, dataVol, root string) ([]string, error) {
	dataVol = filepath.Clean(dataVol)
	if vols, err := ImageVolumes(box); err != nil || len(vols) == 0 {
		return nil, err
	}
	plans, err := planMounts(box, dataVol)
	if err != nil {
		return nil, err
	}
	grants := map[string]bool{}
	for _, pm := range plans {
		if pm.class != classImage {
			continue
		}
		target, err := os.Readlink(pm.dest)
		if err != nil {
			return nil, fmt.Errorf("volume %s: read view link: %w", pm.mount.GetName(), err)
		}
		view, err := viewOf(root, filepath.Clean(target))
		if err != nil {
			return nil, fmt.Errorf("volume %s: %w", pm.mount.GetName(), err)
		}
		grants[view] = true
	}
	return sortedKeys(grants), nil
}

// viewOf returns the view directory target lies in (target itself or a
// descendant of <root>/<hex64>/<hex64>).
func viewOf(root, target string) (string, error) {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: link target %q is outside %q", ErrImageView, target, root)
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("%w: link target %q is not in a view", ErrImageView, target)
	}
	view := filepath.Join(root, parts[0], parts[1])
	if err := CheckView(root, view); err != nil {
		return "", err
	}
	return view, nil
}

// viewTarget returns what an image mount links to: the view itself, or the
// element subPath selects in it. subPath must be relative, clean and free of
// "..", and must name an existing element; the view is built by the daemon of
// regular files and directories only, so the lexical check is containment.
func viewTarget(view, subPath string) (string, error) {
	if subPath == "" {
		return view, nil
	}
	if err := validateVMSubPath(subPath); err != nil {
		return "", err
	}
	target := filepath.Join(view, subPath)
	if !IsStrictlyUnder(target, view) {
		return "", fmt.Errorf("sub_path %q escapes the view", subPath)
	}
	fi, err := os.Lstat(target)
	if err != nil {
		return "", fmt.Errorf("sub_path %q: %w", subPath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("sub_path %q names a symlink in the view", subPath)
	}
	return target, nil
}

// placeLink makes dest a symlink to target. The parents of dest are refused if
// any is a symlink (they are created otherwise), a stale symlink at dest is
// replaced, and any other existing entry is refused.
func placeLink(dataVol, dest, target string) error {
	parent := filepath.Dir(dest)
	if err := pathsafe.RefuseSymlinkedPath(dataVol, parent); err != nil {
		return fmt.Errorf("refusing mount parent %s: %w", parent, err)
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create mount parent %s: %w", parent, err)
	}
	if fi, err := os.Lstat(dest); err == nil {
		if fi.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s already exists and is not a symlink", dest)
		}
		if err := os.Remove(dest); err != nil {
			return fmt.Errorf("replace stale view link %s: %w", dest, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat view link %s: %w", dest, err)
	}
	if err := os.Symlink(target, dest); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", dest, target, err)
	}
	return nil
}

// sortedKeys returns the keys of set, sorted; nil when empty.
func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
