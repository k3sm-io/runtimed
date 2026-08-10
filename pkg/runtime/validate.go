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
func validatePodBox(box *runtimev1.PodBox) (runtimev1.FailureReason, error) {
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
	if box.GetSandboxProfile() == nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: sandbox_profile is required", errInvalidPodBox)
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
