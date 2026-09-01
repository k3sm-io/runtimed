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
	"errors"
	"fmt"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// errInvalidPodBox is the sentinel for PodBox validation failures (mapped to
// codes.InvalidArgument + FailureReason_INVALID_POD_BOX).
var errInvalidPodBox = errors.New("invalid pod box")

// validatePodBox checks the minimum a PodBox needs to be instantiable. It returns
// a typed FailureReason and an errInvalidPodBox-wrapped error on failure.
//
// It is a method because the rootfs_path check below is decided against the
// runtime's own cache-derived pod layout — the seam cannot restate that layout
// without the guard and the deriver drifting apart.
func (r *Runtime) validatePodBox(box *runtimev1.PodBox) (runtimev1.FailureReason, error) {
	if box == nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: pod is nil", errInvalidPodBox)
	}
	// pod_id becomes a directory name the ROOT daemon creates, writes into and
	// removes, so it is validated at the seam as well as at the derivation. The
	// seam check is what makes the rule total: it covers every derivation of the
	// id, including ones that do not go through the image cache.
	if _, err := image.ParsePodID(box.GetPodId()); err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	// rootfs_path is the same shape of hazard one level up: the directory the
	// ROOT daemon MkdirAll's, materializes secrets into and recursively chowns
	// for fsGroup. Reject it here, at the seam, for the same reason pod_id is
	// rejected here — the seam check makes the rule total across every ingress,
	// not just the ones that happen to call rootfsPath.
	//
	// It is asked of rootfsPath rather than restated, so there is one predicate
	// (byte-equality with the cache derivation; see rootfsPath for why not
	// containment). Note that UpdatePod does not run validatePodBox — it runs
	// updatableOnly, whose rootfs_path comparison below is an IMMUTABILITY check,
	// not a validation. The structural guard inside rootfsPath is what covers
	// that ingress, which is precisely why the load-bearing check lives there and
	// this one is defence in depth.
	if _, err := r.rootfsPath(box); err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	if box.GetSandboxProfile() == nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: sandbox_profile is required", errInvalidPodBox)
	}
	// sandbox_profile.data_volume_path is the same shape of hazard again, one tier
	// over: it is not a directory the daemon writes but the tree the emitted SBPL
	// re-allows read+write after the protected denies (last-match-wins), and the
	// carve-out base every other caller-supplied path is validated against. It is
	// asked of dataVolumePath rather than restated, for the same single-predicate
	// reason rootfs_path is asked of rootfsPath — see that method for why equality
	// with the derivation, why both derived spellings, and how it divides labour
	// with the sink-side bound in sandbox.Generate. It sits after the nil-profile
	// check above so a missing profile keeps its own clear reason.
	//
	// UpdatePod does not run validatePodBox (it runs updatableOnly, which does not
	// compare this field at all), so an update cannot smuggle a new value in: the
	// stored box's profile is the one that was validated at create, and the
	// structural check inside createPod covers the spine directly.
	if _, err := r.dataVolumePath(box); err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	if len(box.GetContainers()) == 0 && len(box.GetInitContainers()) == 0 {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: pod %s has no containers", errInvalidPodBox, box.GetPodId())
	}
	// Fail-closed signature policy is enforced per-binary at exec time, but reject
	// an explicitly-unspecified policy early with a clear reason.
	if box.GetSignaturePolicy() == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		return runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED,
			fmt.Errorf("%w: signature_policy is UNSPECIFIED (fail-closed)", errInvalidPodBox)
	}
	return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// updatableOnly verifies that newBox changes only in-place-updatable fields
// (labels, annotations) relative to oldBox. Any other difference is NOT_UPDATABLE.
func updatableOnly(oldBox, newBox *runtimev1.PodBox) (runtimev1.FailureReason, error) {
	if newBox.GetName() != oldBox.GetName() || newBox.GetNamespace() != oldBox.GetNamespace() {
		return runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			errors.New("name/namespace are not updatable in place")
	}
	if newBox.GetRootfsPath() != oldBox.GetRootfsPath() {
		return runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			errors.New("rootfs_path is not updatable in place")
	}
	if newBox.GetUid() != oldBox.GetUid() || newBox.GetGid() != oldBox.GetGid() {
		return runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			errors.New("uid/gid are not updatable in place")
	}
	if len(newBox.GetContainers()) != len(oldBox.GetContainers()) {
		return runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE,
			errors.New("container set is not updatable in place")
	}
	return runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}
