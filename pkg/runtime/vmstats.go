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
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// guestStatsTimeout bounds ONE on-demand guest-agent Stats call.
const guestStatsTimeout = 2 * time.Second

// GuestStatsConditionType is the pod-condition type reporting whether a vm pod's
// guest agent answered the last on-demand Stats call.
const GuestStatsConditionType = "k3sm.io/guest-stats-available"

// The reasons GuestStatsConditionType carries.
const (
	guestStatsReasonReachable   = "GuestAgentReachable"
	guestStatsReasonNoSamples   = "GuestStatsUnreadable"
	guestStatsReasonUnreachable = "GuestAgentUnreachable"
)

// guestStatsRecord is the outcome of a vm pod's LAST on-demand guest-agent Stats
// call. Guarded by pod.mu.
type guestStatsRecord struct {
	// observed is false until the first Stats attempt, so a pod nothing has asked
	// about yet carries no condition at all rather than a fabricated one.
	observed       bool
	available      bool
	reason         string
	message        string
	lastProbe      time.Time
	lastTransition time.Time
}

// vmPodStats builds a vm pod's PodStats from the guest agent's cgroup2 sample.
//
// SKELETON (B107 commit 1): it still delegates to the host rusage path, which is
// exactly the un-forked behaviour the gate reds against. The real guest-agent
// source lands in commit 2.
func (r *Runtime) vmPodStats(ctx context.Context, p *pod) *runtimev1.PodStats {
	return r.hostPodStats(ctx, p)
}
