package supervisor

import (
	"context"
	"os"
	"time"
)

// GracefulStop tears down a pod process group with the SIGTERM → grace → SIGKILL
// escalation Kubernetes terminationGracePeriodSeconds mandates (M2.4), racing the
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
// GracefulStop only OBSERVES exited; it never wait4s, so the kqueue reaper stays
// the single reaper. signal sends a signal to the process GROUP led by pgid
// (SignalGroup is the production implementation; tests inject a recorder). It
// reports whether killSig was sent (escalation or immediate kill).
//
// The signal values are parameters (not hard-coded) so this stays pure Go and
// cross-platform-testable; the runtime passes the platform SIGTERM/SIGKILL.
func GracefulStop(ctx context.Context, pgid int, grace time.Duration, exited <-chan struct{}, termSig, killSig os.Signal, signal func(pgid int, sig os.Signal) error) (escalated bool, err error) {
	if grace <= 0 {
		return true, signal(pgid, killSig)
	}
	if err := signal(pgid, termSig); err != nil {
		return false, err
	}
	t := time.NewTimer(grace)
	defer t.Stop() // stop the timer on every path (incl. early exit) — no leak
	select {
	case <-exited:
		// Voluntary exit within grace: the reaper collected it. Do NOT escalate.
		return false, nil
	case <-t.C:
		// Deadline: the process ignored SIGTERM — escalate.
		return true, signal(pgid, killSig)
	case <-ctx.Done():
		// The caller (DeletePod RPC) is gone; escalate so we never leave a
		// half-terminated pod behind.
		return true, signal(pgid, killSig)
	}
}
