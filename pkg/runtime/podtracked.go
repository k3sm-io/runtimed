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
	"k3sm.io/runtimed/pkg/image"
)

// endCreatingLocked ends one in-flight CreatePod for podID. r.mu must be held.
func (r *Runtime) endCreatingLocked(podID string) {
	if r.creating[podID] <= 1 {
		delete(r.creating, podID)
		return
	}
	r.creating[podID]--
}

// podUntracked reports whether this daemon PROVABLY holds nothing for podID,
// which is the only condition under which the image GC may skip a pod dir that
// has no reachability record (image.UntrackedPodFunc). Every doubt answers
// false, which keeps that dir fatal to the prune:
//
//   - before the startup reap has run, AttachPod may still adopt any pod, so
//     absence from the registry proves nothing yet;
//   - a registered pod (CreatePod or AttachPod) is live;
//   - a CreatePod in flight is building the dir and has not written the
//     record yet;
//   - a durable process record under the pod-reap store names a process group
//     a previous run left, and a reap-store read error is a doubt (a reap
//     directory with no record file in it is not a record);
//   - a vm host helper that still runs for the pod, unadopted, holds a guest.
func (r *Runtime) podUntracked(id image.PodID) bool {
	podID := id.String()
	r.mu.Lock()
	_, live := r.pods[podID]
	inFlight := r.creating[podID] > 0
	reaped := r.podReapStarted
	r.mu.Unlock()
	if !reaped || live || inFlight {
		return false
	}
	if has, ok := r.podHasReapRecord(podID); !ok || has {
		return false
	}
	if pr, ok := r.vmBackend.(unadoptedHelperProber); ok {
		if _, running := pr.UnadoptedHelper(podID); running {
			return false
		}
	}
	return true
}
