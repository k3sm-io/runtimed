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

	"k3sm.io/runtimed/pkg/supervisor"
)

// sidecarsLocked returns the pod's native sidecars in START order. p.containers
// preserves it: sidecars are appended during the init sequence (before any main)
// and a RestartContainer swap replaces in place. Caller holds p.mu.
func sidecarsLocked(p *pod) []*containerProc {
	var out []*containerProc
	for _, cp := range p.containers {
		if cp.sidecar() {
			out = append(out, cp)
		}
	}
	return out
}

// stopSidecars stops sidecars sequentially in REVERSE start order against ONE
// pod-level grace budget expiring at deadline: each stop gets the budget's
// REMAINDER (elapsed time subtracted), and a remainder <= 0 takes the
// immediate-SIGKILL path (supervisor.GracefulStop with grace 0 sends no
// SIGTERM) — sidecars never extend the pod's grace. It is shared by DeletePod
// (the mains are stopped first against the full budget, so the sidecars get
// what is left — see resolveGrace) and by the voluntary-completion teardown in
// watchContainerExit (the mains exited on their own, so the sidecars start with
// the whole budget). A never-spawned or already-reaped sidecar is skipped.
func (r *Runtime) stopSidecars(ctx context.Context, podID string, sidecars []*containerProc, deadline time.Time) {
	for i := len(sidecars) - 1; i >= 0; i-- {
		cp := sidecars[i]
		pid := cp.proc.PID()
		if pid <= 0 {
			continue
		}
		select {
		case <-cp.proc.Done():
			continue // already exited and reaped; nothing to stop
		default:
		}
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		if _, err := supervisor.GracefulStop(ctx, pid, remaining, cp.proc.Done(), termSignal, killSignal, r.signalGroup); err != nil {
			r.log.Warn("graceful stop sidecar", "pod", podID, "container", cp.name, "pid", pid, "err", err)
		}
	}
}
