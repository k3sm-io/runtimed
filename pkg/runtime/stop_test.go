package runtime

import (
	"context"
	"os"
	"sync"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// sentSignal is one recorded process-group signal.
type sentSignal struct {
	pid int
	sig os.Signal
}

// recordingSignalGroup records the signals DeletePod / oomKill send to process
// groups, and optionally (onKill) runs a hook when a SIGKILL is recorded — the OOM
// test wires it to release a fake waiter so the "killed" container actually exits.
type recordingSignalGroup struct {
	mu     sync.Mutex
	sent   []sentSignal
	onKill func(pid int)
}

func (r *recordingSignalGroup) signal(pid int, sig os.Signal) error {
	r.mu.Lock()
	r.sent = append(r.sent, sentSignal{pid, sig})
	onKill := r.onKill
	r.mu.Unlock()
	if onKill != nil && sig == killSignal {
		onKill(pid)
	}
	return nil
}

func (r *recordingSignalGroup) signals() []os.Signal {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]os.Signal, len(r.sent))
	for i, s := range r.sent {
		out[i] = s.sig
	}
	return out
}

func (r *recordingSignalGroup) sawKill() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sent {
		if s.sig == killSignal {
			return true
		}
	}
	return false
}

// mustCreatePod creates box and fails the test on any error.
func mustCreatePod(t *testing.T, rt *Runtime, box *runtimev1.PodBox) {
	t.Helper()
	resp, err := rt.CreatePod(context.Background(), &runtimev1.CreatePodRequest{Pod: box})
	if err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if resp.GetError() != nil {
		t.Fatalf("CreatePod failed: %v (reason %v)", resp.GetError(), resp.GetFailureReason())
	}
}

// TestDeletePodGracefulStop is the runtime-level M2.4 proof: the SIGTERM→SIGKILL
// resolution + the reaper race wired through DeletePod. The deterministic deadline
// escalation itself is proven in supervisor.TestGracefulStop.
func TestDeletePodGracefulStop(t *testing.T) {
	t.Run("grace-zero-immediate-sigkill", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal

		mustCreatePod(t, rt, hostBinBox("pod-g0")) // no grace anywhere → 0 → immediate
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-g0"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := rec.signals(); len(got) != 1 || got[0] != killSignal {
			t.Errorf("grace-0 DeletePod signals = %v, want [SIGKILL] (immediate)", got)
		}
		w.release(1001) // let the reaper finish
	})

	t.Run("positive-grace-voluntary-exit-skips-sigkill", func(t *testing.T) {
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal

		box := hostBinBox("pod-gp")
		box.TerminationGracePeriodSeconds = 30 // long grace from the PodBox
		mustCreatePod(t, rt, box)

		// The container exits "voluntarily": release it so the reaper closes
		// proc.Done(). DeletePod must observe the exit and NOT escalate to SIGKILL.
		w.release(1001)
		if _, err := rt.DeletePod(context.Background(), &runtimev1.DeletePodRequest{PodId: "pod-gp"}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if rec.sawKill() {
			t.Error("a voluntary exit within grace must NOT escalate to SIGKILL")
		}
		if got := rec.signals(); len(got) != 1 || got[0] != termSignal {
			t.Errorf("signals = %v, want [SIGTERM] only (reaper collected the exit)", got)
		}
	})

	t.Run("request-grace-overrides-podbox", func(t *testing.T) {
		// req.grace_period_seconds=0 falls back to the PodBox value (30s here), so
		// a delete with no request grace still SIGTERMs first.
		w := newBlockingWaiter()
		rt := newTestRuntime(t, Deps{Waiter: w})
		rec := &recordingSignalGroup{}
		rt.signalGroup = rec.signal
		box := hostBinBox("pod-gr")
		box.TerminationGracePeriodSeconds = 30
		mustCreatePod(t, rt, box)
		w.release(1001)
		if _, err := rt.DeletePod(context.Background(),
			&runtimev1.DeletePodRequest{PodId: "pod-gr", GracePeriodSeconds: 0}); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		if got := rec.signals(); len(got) == 0 || got[0] != termSignal {
			t.Errorf("signals = %v, want SIGTERM first (PodBox grace honored)", got)
		}
	})
}
