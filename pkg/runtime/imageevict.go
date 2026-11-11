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

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// errEvictImageInUse is the EvictImage refusal for a target a pod runs: some
// per-pod record or pod hold names the target manifest or its config. The
// handler decides it before Cache.Evict runs and wraps it with the pod it
// found; evictStatusError turns it into FAILED_PRECONDITION with the
// IMAGE_IN_USE detail.
var errEvictImageInUse = errors.New("evict: image is in use by a pod")

// evictSkipReason maps pkg/image's kept reason onto the wire enum.
//
//	EvictKeptRooted       -> EVICT_SKIP_REASON_ROOTED
//	EvictKeptInUse        -> EVICT_SKIP_REASON_IN_USE
//	EvictKeptLeased       -> EVICT_SKIP_REASON_LEASED
//	EvictKeptShared       -> EVICT_SKIP_REASON_SHARED
//	EvictKeptYoung        -> EVICT_SKIP_REASON_YOUNG
//	EvictKeptUnlinkFailed -> not sent (ok false)
//
// ok is false for EvictKeptUnlinkFailed, which is a failure carried by the
// INTERNAL status (evictStatusError), never a kept reason on the wire, and for
// any value outside the set, so an unnamed reason is never sent as some other
// one.
func evictSkipReason(r image.EvictKeepReason) (runtimev1.EvictSkipReason, bool) {
	switch r {
	case image.EvictKeptRooted:
		return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_ROOTED, true
	case image.EvictKeptInUse:
		return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_IN_USE, true
	case image.EvictKeptLeased:
		return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_LEASED, true
	case image.EvictKeptShared:
		return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_SHARED, true
	case image.EvictKeptYoung:
		return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_YOUNG, true
	}
	return runtimev1.EvictSkipReason_EVICT_SKIP_REASON_UNSPECIFIED, false
}

// evictUnlinkFailed counts the result's blobs kept EvictKeptUnlinkFailed.
func evictUnlinkFailed(res *image.EvictResult) int {
	if res == nil {
		return 0
	}
	n := 0
	for _, k := range res.Kept {
		if k.Reason == image.EvictKeptUnlinkFailed {
			n++
		}
	}
	return n
}

// evictStatusError maps the outcome of one eviction onto its gRPC status, or
// nil when the call is OK.
//
// The three refusals the method contract names are FAILED_PRECONDITION, each
// with a google.rpc.ErrorInfo detail in domain runtime.k3sm.io naming the
// case, so a caller never matches on message text:
//
//	errEvictImageInUse           -> IMAGE_IN_USE
//	image.ErrIndexEntryAmbiguous -> REFERENCE_AMBIGUOUS
//	image.ErrRootsIncomplete     -> ROOTS_INCOMPLETE
//
// The contract says those cases unlinked nothing, so a refusal that comes back
// with a result that removed blobs (a later executor's guard failing after an
// earlier one unlinked) is INTERNAL instead: some blobs are gone, and a
// FAILED_PRECONDITION would say they were not. Any other error goes through
// indexStatusError, which carries no detail. With no error, a result with any
// blob kept EvictKeptUnlinkFailed is INTERNAL: an unlink that failed or whose
// re-verification refused it is a failure, not a partial success.
func evictStatusError(res *image.EvictResult, err error) error {
	if err != nil {
		reason, refusal := evictRefusalReason(err)
		if !refusal {
			return indexStatusError(err)
		}
		if res != nil && len(res.Removed) > 0 {
			return status.Error(codes.Internal, fmt.Sprintf("evict: refused after %d blob(s) were unlinked: %v", len(res.Removed), err))
		}
		return evictRefusalStatus(reason, err)
	}
	if n := evictUnlinkFailed(res); n > 0 {
		return status.Error(codes.Internal, fmt.Sprintf("evict: %d target blob(s) could not be unlinked", n))
	}
	return nil
}

// evictRefusalReason names the ErrorInfo reason of a FAILED_PRECONDITION
// refusal, or reports false when err is none of the three.
func evictRefusalReason(err error) (string, bool) {
	switch {
	case errors.Is(err, errEvictImageInUse):
		return runtimev1.EvictReasonImageInUse, true
	case errors.Is(err, image.ErrIndexEntryAmbiguous):
		return runtimev1.EvictReasonReferenceAmbiguous, true
	case errors.Is(err, image.ErrRootsIncomplete):
		return runtimev1.EvictReasonRootsIncomplete, true
	}
	return "", false
}

// evictRefusalStatus builds the FAILED_PRECONDITION status for one refusal with
// its ErrorInfo detail. Attaching the detail fails only when the message cannot
// be marshalled, which a fixed two-string ErrorInfo cannot hit; that is still
// INTERNAL rather than a detail-less FAILED_PRECONDITION, because the contract
// promises the detail.
func evictRefusalStatus(reason string, err error) error {
	st, derr := status.New(codes.FailedPrecondition, err.Error()).WithDetails(&errdetails.ErrorInfo{
		Reason: reason,
		Domain: runtimev1.EvictErrorInfoDomain,
	})
	if derr != nil {
		return status.Error(codes.Internal, fmt.Sprintf("evict: attach %s detail: %v", reason, derr))
	}
	return st.Err()
}
