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
	"errors"
	"fmt"
	"time"
)

// defaultCloseGrace bounds Close's wait for the supervision goroutines of ALL
// live pods to observe the shutdown cancel. It is a ceiling on a shutdown, not a
// delay: the cancels are fired for every pod first, so a healthy node's waits are
// already satisfied when the wait begins. The size matches the reaper's own
// latency ceiling (supervisor.DefaultExitObservationGrace — the kqueue poll is
// 250ms), since the slowest observer here IS a reaper.
const defaultCloseGrace = 2 * time.Second

// ErrSupervisionNotStopped reports that a pod's supervision goroutine had not
// stopped when Close's bound expired. It is informational: the daemon is exiting
// regardless, and the goroutine dies with the process.
var ErrSupervisionNotStopped = errors.New("supervision did not stop before the close deadline")

// closeGraceDuration is Close's bounded wait for supervision to stop
// (Runtime.closeGrace, default defaultCloseGrace).
func (r *Runtime) closeGraceDuration() time.Duration {
	if r.closeGrace > 0 {
		return r.closeGrace
	}
	return defaultCloseGrace
}

// Close stops the per-pod SUPERVISION this daemon owns: for every live pod it
// cancels the memory sampler and then the pod-lifetime supervision context,
// which is what the per-container kqueue reapers, their watchContainerExit
// completions, and the ~1 Hz memory samplers are all rooted at. It then waits,
// bounded by closeGraceDuration, for each of those goroutines to actually
// observe the cancel, and reports the ones that did not. It is the shutdown
// counterpart of DeletePod's teardown, which fires the same two cancels for one
// pod (server.go) — the daemon had no equivalent for the node's remaining pods,
// so a shutdown left every live pod's supervision running until the process
// happened to exit.
//
// Close does NOT signal the pod PROCESSES, and that is the point: they are
// native Darwin processes in their own session, they survive the daemon by
// design, and the startup pod reap reconciles them on the next boot (podreap.go).
// Killing a node's workloads because the runtime restarted is precisely what a
// `launchctl kickstart -k` must not do.
//
// The registry is left intact — the pods are still running, so forgetting them
// would be a lie — which also makes Close idempotent: every cancel is, and a
// second call simply re-observes stopped goroutines.
//
// It returns a joined error naming each supervision that outlived the bound
// (ErrSupervisionNotStopped); one wedged pod never short-circuits the sweep,
// because a shutdown that stops at the first stuck pod leaves exactly the
// goroutines Close exists to stop.
func (r *Runtime) Close() error {
	r.mu.Lock()
	pods := make([]*pod, 0, len(r.pods))
	for _, p := range r.pods {
		pods = append(pods, p)
	}
	r.mu.Unlock()

	if len(pods) > 0 {
		r.log.Info("stopping pod supervision for daemon shutdown", "pods", len(pods))
	}

	// Phase 1: fire every cancel BEFORE waiting on any of them. Cancelling is
	// non-blocking, so this stops the whole node's supervision at once and leaves
	// the bound below to be shared rather than spent pod by pod (a wedged pod
	// would otherwise consume a healthy successor's budget).
	//
	// It also runs BEFORE the vm stop below, which is load-bearing rather than
	// incidental: watchVMHelperExit would otherwise observe the shutdown's own
	// stop as a crash and publish a Failed status for every vm pod on the way
	// out. Contexts are monotonic, so cancelling first settles that
	// deterministically instead of by winning a race (see DeletePod's vm branch,
	// where the live smoke found the same ordering bug).
	waits := make([]supervisionWait, 0, len(pods))
	for _, p := range pods {
		waits = append(waits, r.cancelPodSupervision(p))
	}

	// THE VM CARVE-OUT, and it is the exact OPPOSITE of the rule above. A host
	// pod's processes survive the daemon by design; a vm pod's helper must not —
	// "no VM outlives the binary that booted it" (cmd/k3sm-vmhost) — because an
	// orphaned helper holds a whole machine that nothing on the node can talk to,
	// adopt, or stop. So every live helper is stopped here, CONCURRENTLY inside
	// the backend.
	//
	// The concurrency is a requirement, not a tidiness: each helper's graceful
	// stop can spend up to the vm host's 30-second ceiling, and launchd gives the
	// daemon 45 seconds total, so a serial sweep blows the ExitTimeOut with two vm
	// pods — and launchd's answer to a blown timeout is SIGKILL of the daemon,
	// stranding exactly the helpers this sweep exists to stop.
	//
	// It runs even with no registered pods: the pod registry and the backend's
	// handle map are different records, and a helper whose CreatePod failed to
	// register is precisely the one worth catching.
	stopCtx, cancelStop := context.WithTimeout(context.Background(), vmShutdownBound)
	defer cancelStop()
	vmErr := r.vmBackend.StopAllVMs(stopCtx)
	if vmErr != nil {
		r.log.Warn("some vm host helpers did not stop cleanly during shutdown", "err", vmErr)
	}
	if len(pods) == 0 {
		return vmErr
	}

	// Phase 2: confirm the cancels were observed.
	deadline := time.Now().Add(r.closeGraceDuration())
	errs := []error{vmErr}
	for _, w := range waits {
		errs = append(errs, w.await(deadline)...)
	}
	return errors.Join(errs...)
}

// vmShutdownBound caps the whole concurrent vm-helper stop at shutdown.
//
// It is sized against launchd's 45-second ExitTimeOut, NOT against one helper:
// the helpers stop in parallel, so the node's cost is one budget rather than one
// per pod, and this leaves room for the supervision waits that follow plus the
// daemon's own teardown. A helper still running when it expires is left to the
// next start's orphan sweep, which is the backstop that makes this a bound rather
// than a promise.
const vmShutdownBound = 35 * time.Second

// supervisionWait is one pod's set of "the cancel was observed" edges: the
// per-container reaper completions (Process.Done, closed when the reaper returns
// — on the real exit or on the cancel) and the memory sampler's loop exit. It is
// assembled under p.mu and awaited outside it.
type supervisionWait struct {
	podID   string
	procs   []namedDone
	sampler <-chan struct{}
}

// namedDone is a container's supervision-stopped edge, named for the error.
type namedDone struct {
	container string
	done      <-chan struct{}
}

// cancelPodSupervision fires p's memory-sampler cancel and then its pod-lifetime
// cancel, returning the edges that report those goroutines having stopped.
//
// The read of p.memCancel/p.memSampler takes p.mu for the same reason DeletePod's
// does: armMemorySampler REPLACES both at arbitrary runtime (a RestartContainer
// re-exec re-arms the sampler), so an unsynchronized read can cancel a stale
// sampler and leave the live one running (B26). p.cancel is immutable after
// createPod and needs no lock.
func (r *Runtime) cancelPodSupervision(p *pod) supervisionWait {
	p.mu.Lock()
	memCancel := p.memCancel
	sampler := p.memSampler
	procs := make([]namedDone, 0, len(p.containers))
	for _, cp := range p.containers {
		if cp.proc == nil {
			continue
		}
		procs = append(procs, namedDone{container: cp.name, done: cp.proc.Done()})
	}
	p.mu.Unlock()

	if memCancel != nil {
		memCancel()
	}
	if p.cancel != nil {
		p.cancel()
	}

	w := supervisionWait{podID: p.box.GetPodId(), procs: procs}
	if sampler != nil {
		w.sampler = sampler.Done()
	}
	return w
}

// await blocks until every one of the pod's supervision edges is closed or
// deadline passes, returning one error per edge that was still open. It never
// returns early on the first miss: the remaining edges are usually closed
// already, and reporting "container A is stuck" while silently skipping B would
// misdescribe the shutdown.
func (w supervisionWait) await(deadline time.Time) []error {
	var errs []error
	for _, nd := range w.procs {
		if !waitClosed(nd.done, deadline) {
			errs = append(errs, fmt.Errorf("pod %s container %s reaper: %w", w.podID, nd.container, ErrSupervisionNotStopped))
		}
	}
	if w.sampler != nil && !waitClosed(w.sampler, deadline) {
		errs = append(errs, fmt.Errorf("pod %s memory sampler: %w", w.podID, ErrSupervisionNotStopped))
	}
	return errs
}

// waitClosed reports whether ch is closed, waiting until deadline at the latest.
// The already-closed case is checked FIRST and separately: a select over a
// closed channel and an expired timer picks between the two at random, which
// would report a stopped goroutine as stuck whenever an earlier pod had already
// consumed the shared bound.
func waitClosed(ch <-chan struct{}, deadline time.Time) bool {
	select {
	case <-ch:
		return true
	default:
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	}
}
