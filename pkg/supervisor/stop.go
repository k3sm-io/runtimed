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

package supervisor

import (
	"context"
	"os"
	"time"
)

// DefaultExitObservationGrace bounds the post-kill wait for the reaper's exit
// OBSERVATION (see GracefulStop). SIGKILL is uncatchable, so a live process dies
// at its next scheduling opportunity and the only latency left is the reaper's:
// KqueueReaper.WaitExit polls its kqueue on a 250ms timeout, so the bound must
// cover several poll periods, not one. 2s ≈ eight of them, and matches the
// sibling bound the runtime already spends on a dying container (pkg/runtime's
// defaultDrainGrace log-drain wait) — the two run in sequence on the same
// teardown, so keeping them the same order of magnitude keeps a DeletePod's
// worst case predictable. It is a CEILING, not a delay: the wait ends the
// instant the reaper reports the exit, which is the overwhelming case.
const DefaultExitObservationGrace = 2 * time.Second

// GracefulStop tears down a pod process group with the SIGTERM → grace → SIGKILL
// escalation Kubernetes terminationGracePeriodSeconds mandates, racing the
// grace timer against the supervisor's kqueue reaper:
//
//   - grace <= 0: send killSig IMMEDIATELY (no termSig, no timer) — the
//     DeletePodRequest.grace_period_seconds == 0 "immediate kill" contract.
//   - grace  > 0: send termSig, then wait up to grace for the process to exit,
//     observed via exited (the channel Process.Done returns, which the SOLE
//     kqueue reaper closes). An exit BEFORE the deadline stops the timer and
//     returns WITHOUT sending killSig — the reaper already collected the status,
//     so there is no double-kill and no leaked timer. On the deadline (or ctx
//     cancellation) it escalates to killSig.
//
// EVERY path that sends killSig then WAITS for the reaper's exit observation,
// bounded by exitWait (<= 0 selects DefaultExitObservationGrace), and reports
// through observed whether it arrived. "killSig was sent" and "the reaper saw
// the exit" are different events: the caller's teardown continues the moment
// this returns, and in the runtime that continuation CANCELS the pod-lifetime
// supervision context the reaper runs under. Returning between those two events
// therefore let the cancel preempt the reaper at its ctx check, recording
// "context canceled" as the container's terminated reason for a process the
// daemon had in fact just SIGKILLed — a status the operator cannot tell from a
// genuinely cancelled wait. Waiting here makes the reason honest at the source.
//
// The wait deliberately does NOT select on ctx.Done(): the ctx-cancellation arm
// below has already escalated BECAUSE ctx is gone, so honoring it again would
// skip the observation exactly where the race is most likely. observed == false
// means the bound expired — the caller may proceed (teardown must never hang on
// a process that refuses to die), but a terminated status recorded after it is
// no longer trustworthy and is worth logging.
//
// GracefulStop only OBSERVES exited; it never wait4s, so the kqueue reaper stays
// the single reaper. signal sends a signal to the process GROUP led by pgid
// (SignalGroup is the production implementation; tests inject a recorder). It
// reports whether killSig was sent (escalation or immediate kill).
//
// The signal values are parameters (not hard-coded) so this stays pure Go and
// cross-platform-testable; the runtime passes the platform SIGTERM/SIGKILL.
func GracefulStop(ctx context.Context, pgid int, grace time.Duration, exited <-chan struct{}, termSig, killSig os.Signal, signal func(pgid int, sig os.Signal) error, exitWait time.Duration) (escalated, observed bool, err error) {
	if grace <= 0 {
		if err := signal(pgid, killSig); err != nil {
			return true, false, err
		}
		return true, awaitExit(exited, exitWait), nil
	}
	if err := signal(pgid, termSig); err != nil {
		return false, false, err
	}
	t := time.NewTimer(grace)
	defer t.Stop() // stop the timer on every path (incl. early exit) — no leak
	select {
	case <-exited:
		// Voluntary exit within grace: the reaper collected it. Do NOT escalate.
		return false, true, nil
	case <-t.C:
		// Deadline: the process ignored SIGTERM — escalate.
	case <-ctx.Done():
		// The caller (DeletePod RPC) is gone; escalate so we never leave a
		// half-terminated pod behind.
	}
	if err := signal(pgid, killSig); err != nil {
		return true, false, err
	}
	return true, awaitExit(exited, exitWait), nil
}

// awaitExit blocks until exited closes (the reaper recorded the final status) or
// wait elapses, reporting whether the observation arrived. wait <= 0 selects
// DefaultExitObservationGrace. It takes no context on purpose — see GracefulStop.
func awaitExit(exited <-chan struct{}, wait time.Duration) bool {
	if wait <= 0 {
		wait = DefaultExitObservationGrace
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-exited:
		return true
	case <-t.C:
		return false
	}
}
