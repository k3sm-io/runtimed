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
	"strings"

	runtimev1 "k3sm.io/apis/runtime/v1"
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
	if err := validPodID(box.GetPodId()); err != nil {
		return runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %v", errInvalidPodBox, err)
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

// validPodID requires the pod id to be a single, clean path component. The id
// is spliced into on-disk paths (<root>/pods/<podID> — image.Cache.PodRootfs,
// removePodDir, the SBPL profile paths), so this is the narrowest ingress at
// which every consumer inherits traversal safety: no separators, no "..", no
// ".", never empty, no NUL. CreatePod rejects a violation as INVALID_POD_BOX
// before any path is derived; removePodDir independently re-checks containment
// (defense in depth for ids arriving on other RPCs).
func validPodID(id string) error {
	switch {
	case id == "":
		return errors.New("pod_id is required")
	case id == "." || id == "..":
		return fmt.Errorf("pod_id %q is not a valid path component", id)
	case strings.ContainsAny(id, `/\`) || strings.ContainsRune(id, 0):
		return fmt.Errorf("pod_id %q must be a single path component (no separators or NUL)", id)
	}
	return nil
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
