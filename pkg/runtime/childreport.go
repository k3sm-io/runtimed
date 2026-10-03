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
	"strings"
	"time"

	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/runtimed/pkg/supervisor"
)

// Restricted-child reports (supervisor.ChildReport): the path shim appends the
// platform binaries a container's processes exec'd without it to a
// per-container file in the pod data volume, and runtimed surfaces them on
// the existing k3sm.io/shim-inactive condition with
// ShimInactiveRestrictedChildReason. The file is polled on the pod's memory
// sampler tick and once more when the container's process exits, so the
// report of a container that lives for less than one tick is not lost.

// shimChildLoss is a container instance's restricted-child verdict: the
// platform binaries it reported, and when the first was seen. Written and read
// under pod.mu. The zero value means "none reported".
type shimChildLoss struct {
	names []string
	at    time.Time
}

// childShimMessage is the condition message for a container whose processes
// ran platform binaries the pod shim cannot load into.
func childShimMessage(container string, names []string) string {
	return fmt.Sprintf("container %s: a platform binary it ran (%s) cannot load the pod shim: "+
		"absolute paths under the pod's volume mounts resolve to host paths in it, and "+
		"per-namespace DNS precedence and bind/connect source discipline are unavailable to it "+
		"(advisory: reported from inside the pod)", container, strings.Join(names, ", "))
}

// armChildReport gives cp a reader for its restricted-child report file in
// the pod data volume rootfs, deriving the file from the container name
// itself (never from the environment the pod sees). fresh is a new instance:
// a report its predecessor left is removed first, so the new instance is not
// charged with it. An adopted instance (fresh false) re-reads the file from
// the start, which republishes nothing new to the node (one Event per reason).
// Called before cp is visible to any other goroutine.
func (r *Runtime) armChildReport(podID, rootfs string, cp *containerProc, fresh bool) {
	name, err := supervisor.ChildReportName(cp.name)
	if err != nil {
		r.log.Warn("no restricted-child report for this container", "pod", podID, "container", cp.name, "err", err)
		return
	}
	if fresh {
		if err := supervisor.RemoveChildReport(rootfs, name); err != nil {
			r.log.Warn("remove a stale restricted-child report", "pod", podID, "container", cp.name, "err", err)
		}
	}
	cp.childReport = supervisor.NewChildReport(rootfs, name, r.childRestricted)
}

// readChildReport polls cp's report and records any new names on cp under
// p.mu, reporting whether the recorded verdict changed. It does not publish.
func (r *Runtime) readChildReport(p *pod, cp *containerProc) bool {
	if cp.childReport == nil {
		return false
	}
	names, err := cp.childReport.Poll()
	if err != nil {
		r.log.Debug("read restricted-child report", "pod", p.box.GetPodId(), "container", cp.name, "err", err)
	}
	if len(names) == 0 {
		return false
	}
	r.log.Warn("a container ran platform binaries without the pod shim",
		"pod", p.box.GetPodId(), "container", cp.name, "binaries", names)
	p.mu.Lock()
	if cp.childShim.at.IsZero() {
		cp.childShim.at = time.Now()
	}
	cp.childShim.names = append(cp.childShim.names, names...)
	p.mu.Unlock()
	return true
}

// childReportPoller runs pollChildReports once per kick until ctx is
// cancelled. It is the memory sampler's tick consumer (armMemorySampler),
// kept off the sampling goroutine so report IO never delays the OOM check.
func (r *Runtime) childReportPoller(ctx context.Context, p *pod, kick <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			r.pollChildReports(p)
		}
	}
}

// pollChildReports reads every container's report (the sampler-tick caller)
// and, if any verdict changed and the pod is still registered, publishes a
// MODIFIED status so the condition reaches the node.
func (r *Runtime) pollChildReports(p *pod) {
	p.mu.Lock()
	cps := make([]*containerProc, 0, len(p.containers))
	for _, cp := range p.containers {
		if cp.childReport != nil {
			cps = append(cps, cp)
		}
	}
	p.mu.Unlock()
	changed := false
	for _, cp := range cps {
		if r.readChildReport(p, cp) {
			changed = true
		}
	}
	if !changed {
		return
	}
	if cur, ok := r.lookupPod(p.box.GetPodId()); ok && cur == p {
		r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
	}
}
