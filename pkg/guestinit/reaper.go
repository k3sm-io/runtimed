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

package guestinit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Signal is the portable signal selector the Proc seam takes. Only the two
// signals the stop sequence sends are defined; the values are the numbers both
// Linux and Darwin use, so the seam's darwin fake and its linux implementation
// agree without a translation table.
type Signal int

// The signals the stop sequence sends.
const (
	SignalTerm Signal = 15
	SignalKill Signal = 9
)

// WaitStatus is a child's terminal outcome, in the portable shape guest/v1's
// ContainerExited carries. Exactly one of the two is meaningful: a process
// that was killed by a signal has Signal set and ExitCode 0.
type WaitStatus struct {
	ExitCode int
	Signal   int
}

// ExitEvent is one TRACKED container's exit, delivered to the reaper's
// callback exactly once.
type ExitEvent struct {
	Container string
	PID       int
	Status    WaitStatus
}

// Errors the Proc seam reports back to the reap loop.
var (
	// ErrNoChildren is wait4(2)'s ECHILD: the process has no children at all,
	// which is the loop's cue to sleep until the next SIGCHLD.
	ErrNoChildren = errors.New("no child processes")

	// ErrInterrupted is wait4(2)'s EINTR. It is retried, never reported: a
	// signal arriving during the wait is normal for PID 1.
	ErrInterrupted = errors.New("interrupted")

	// ErrStopped is returned by Wait when the reaper stopped before the
	// container's exit was observed.
	ErrStopped = errors.New("reaper stopped")
)

// Proc is the three-method process seam PID 1 needs from the kernel.
//
// It is defined at the consumer (this package) and implemented once, in the
// linux executor. Keeping it to three methods is what lets the whole reaper
// and stop state machine — the vm path's only genuinely concurrent code — run
// under `go test -race` on darwin against a fake.
type Proc interface {
	// Wait4 reaps one exited child without BLOCKING (wait4 with WNOHANG).
	// It returns:
	//   - (pid > 0, status, nil) when a child was reaped;
	//   - (0, _, nil) when children exist but none has exited;
	//   - (0, _, ErrNoChildren) when there are no children at all;
	//   - (0, _, ErrInterrupted) when the wait was interrupted.
	// Blocking is deliberately not part of the seam: the loop blocks on the
	// SIGCHLD channel instead, which is the only way it can also be woken by
	// a context cancellation.
	Wait4() (pid int, status WaitStatus, err error)

	// Kill sends sig to pid. A pid that is already gone must be reported as a
	// nil error or an error the caller can ignore; the stop sequence treats a
	// kill failure as non-fatal because the process it could not signal is
	// either already dead or about to be powered off.
	Kill(pid int, sig Signal) error

	// Poweroff syncs the filesystems and powers the machine off. An
	// implementation must sync before powering off — the guest's writable
	// layers and any writable virtiofs share are the pod's data. On success it
	// does not return.
	Poweroff() error
}

// ReaperOptions are the reaper's injectable seams and its callback.
type ReaperOptions struct {
	// OnExit is called once per TRACKED child exit, outside every lock. It may
	// be called concurrently from Run and from Track (a child that exits
	// before its Track lands is delivered by Track), so it must be safe for
	// concurrent use.
	OnExit func(ExitEvent)

	// Logger receives the reaper's own narration; nil means slog.Default.
	Logger *slog.Logger

	// NewTimer is the grace timer, injectable so the stop sequence's ordering
	// is asserted deterministically rather than by sleeping. nil means
	// time.NewTimer.
	NewTimer func(d time.Duration) (<-chan time.Time, func() bool)
}

// Reaper is PID 1's child-reaping loop and its shutdown state machine.
//
// PID 1 in a pid namespace inherits every orphan, so it reaps every child, not
// only the containers it started; an unreaped child stays a zombie forever
// because there is no other process to inherit it. Only tracked children are
// forwarded as ExitEvents — an orphan's exit belongs to nobody's container
// status.
//
// Locking discipline: mu guards live, pending and done. The OnExit callback
// and every Proc call are made with mu released, so a callback that starts a
// container (which Tracks) cannot deadlock against the loop that delivered it.
type Reaper struct {
	proc     Proc
	sigchld  <-chan struct{}
	onExit   func(ExitEvent)
	log      *slog.Logger
	newTimer func(d time.Duration) (<-chan time.Time, func() bool)

	// exited is a coalescing notification that a tracked child was reaped; the
	// stop sequence waits on it instead of polling.
	exited chan struct{}

	mu sync.Mutex
	// live maps a tracked, not-yet-reaped pid to its container name.
	live map[int]string
	// pending holds a status reaped before its Track call arrived. Starting a
	// container and recording its pid cannot be atomic against the kernel, so
	// a short-lived process can be reaped first; without this map its exit
	// would be discarded as an orphan's.
	//
	// It also catches every genuine orphan the guest inherits, which is never
	// claimed, so it is bounded: pendingOrder is the insertion order and the
	// oldest entry is evicted past maxPendingReaps. The window an entry has to
	// be claimed in is the microseconds between a container's exit and its
	// Track, so an eviction would need that many orphans to exit inside it.
	pending      map[int]WaitStatus
	pendingOrder []int
	// done holds each container's observed final status, for Wait.
	done map[string]WaitStatus
	// waiters are the per-container Wait channels, closed on that container's
	// exit.
	waiters map[string]chan struct{}

	stopOnce sync.Once
	stopErr  error
	stopped  chan struct{}
}

// NewReaper builds a reaper over proc. sigchld is a coalescing notification
// that at least one child may have exited (SIGCHLD); it may be nil, in which
// case the loop only reaps what is already exited and then waits for the
// context.
func NewReaper(proc Proc, sigchld <-chan struct{}, opts ReaperOptions) *Reaper {
	r := &Reaper{
		proc:     proc,
		sigchld:  sigchld,
		onExit:   opts.OnExit,
		log:      opts.Logger,
		newTimer: opts.NewTimer,
		exited:   make(chan struct{}, 1),
		live:     map[int]string{},
		pending:  map[int]WaitStatus{},
		done:     map[string]WaitStatus{},
		waiters:  map[string]chan struct{}{},
		stopped:  make(chan struct{}),
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.newTimer == nil {
		r.newTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		}
	}
	return r
}

// Track registers a started container's pid.
//
// It is safe to call concurrently with Run, and it closes the start/exit race
// in both directions: if the child has already been reaped, its stashed status
// is delivered here instead of being lost.
func (r *Reaper) Track(container string, pid int) {
	r.mu.Lock()
	status, alreadyExited := r.unstashLocked(pid)
	if !alreadyExited {
		r.live[pid] = container
	}
	r.mu.Unlock()

	if alreadyExited {
		r.finish(container, pid, status)
	}
}

// Run reaps children until ctx is cancelled or the seam fails. It returns
// ctx.Err() on cancellation, which is the normal end of PID 1's loop.
func (r *Reaper) Run(ctx context.Context) error {
	for {
		if err := r.drain(); err != nil {
			return err
		}
		select {
		case <-r.sigchld:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// drain reaps every child that has already exited.
func (r *Reaper) drain() error {
	for {
		pid, status, err := r.proc.Wait4()
		switch {
		case errors.Is(err, ErrNoChildren):
			return nil
		case errors.Is(err, ErrInterrupted):
			continue
		case err != nil:
			return fmt.Errorf("reap: %w", err)
		case pid <= 0:
			return nil
		}
		r.reaped(pid, status)
	}
}

// reaped records one reaped pid and forwards it if it is tracked.
func (r *Reaper) reaped(pid int, status WaitStatus) {
	r.mu.Lock()
	container, tracked := r.live[pid]
	if tracked {
		delete(r.live, pid)
	} else {
		// An untracked pid is either an orphan the guest inherited — which is
		// reaped and forgotten — or a container whose Track has not landed
		// yet, which Track will pick up.
		r.stashLocked(pid, status)
	}
	r.mu.Unlock()

	if !tracked {
		r.log.Debug("reaped an untracked child", "pid", pid, "exit_code", status.ExitCode, "signal", status.Signal)
		return
	}
	r.finish(container, pid, status)
}

// finish records a container's terminal status, wakes its waiters and the stop
// sequence, and delivers the exit event. Every one of those happens exactly
// once per container exit, and the callback runs with no lock held.
func (r *Reaper) finish(container string, pid int, status WaitStatus) {
	r.mu.Lock()
	r.done[container] = status
	if ch, ok := r.waiters[container]; ok {
		close(ch)
		delete(r.waiters, container)
	}
	r.mu.Unlock()

	select {
	case r.exited <- struct{}{}:
	default:
	}

	r.log.Info("container exited", "container", container, "pid", pid,
		"exit_code", status.ExitCode, "signal", status.Signal)
	if r.onExit != nil {
		r.onExit(ExitEvent{Container: container, PID: pid, Status: status})
	}
}

// maxPendingReaps bounds the reaped-before-Track map (see Reaper.pending).
const maxPendingReaps = 4096

// stashLocked records an untracked reap, evicting the oldest entry once the
// map is full. Caller holds r.mu.
func (r *Reaper) stashLocked(pid int, status WaitStatus) {
	if _, dup := r.pending[pid]; !dup {
		r.pendingOrder = append(r.pendingOrder, pid)
	}
	r.pending[pid] = status
	for len(r.pendingOrder) > maxPendingReaps {
		oldest := r.pendingOrder[0]
		r.pendingOrder = r.pendingOrder[1:]
		delete(r.pending, oldest)
	}
}

// unstashLocked claims a reaped-before-Track status. Caller holds r.mu.
func (r *Reaper) unstashLocked(pid int) (WaitStatus, bool) {
	status, ok := r.pending[pid]
	if !ok {
		return WaitStatus{}, false
	}
	delete(r.pending, pid)
	for i, p := range r.pendingOrder {
		if p == pid {
			r.pendingOrder = append(r.pendingOrder[:i], r.pendingOrder[i+1:]...)
			break
		}
	}
	return status, true
}

// Wait blocks until container's exit has been observed and returns its status.
// It is how an init container's run-to-completion step is sequenced without a
// second reaper: PID 1 reaps every child, so nothing else may wait(2).
func (r *Reaper) Wait(ctx context.Context, container string) (WaitStatus, error) {
	r.mu.Lock()
	if status, ok := r.done[container]; ok {
		r.mu.Unlock()
		return status, nil
	}
	ch, ok := r.waiters[container]
	if !ok {
		ch = make(chan struct{})
		r.waiters[container] = ch
	}
	r.mu.Unlock()

	select {
	case <-ch:
		r.mu.Lock()
		status := r.done[container]
		r.mu.Unlock()
		return status, nil
	case <-r.stopped:
		return WaitStatus{}, fmt.Errorf("%w: waiting for container %q", ErrStopped, container)
	case <-ctx.Done():
		return WaitStatus{}, ctx.Err()
	}
}

// Stop runs the guest's shutdown state machine exactly once:
//
//	SIGTERM every live container -> wait up to grace for them to exit ->
//	SIGKILL whatever is left -> sync + poweroff.
//
// Three properties are load-bearing and each is pinned by a test:
//
//   - SIGKILL is never sent before the grace budget has elapsed (or every
//     container has exited, which ends the wait early). Killing early turns a
//     graceful shutdown into data loss for anything mid-write.
//   - The machine is always powered off, on every path, including one where
//     signalling fails and one where a container never exits. A stop that
//     returns without powering off leaves a VM running with no pod, which the
//     host can only reap by timeout.
//   - It runs once. A second call is a no-op returning the first call's error,
//     because the second poweroff would race the first.
//
// grace is clamped at zero; a negative or zero grace goes straight to SIGKILL
// (the caller has already spent the budget). The host clamps grace to fit
// inside the daemon's launchd exit timeout before it ever reaches here.
func (r *Reaper) Stop(ctx context.Context, grace time.Duration) error {
	r.stopOnce.Do(func() { r.stopErr = r.stop(ctx, grace) })
	return r.stopErr
}

// stop is Stop's body, run exactly once. The result is assigned in the defer
// so the poweroff's own error is part of it: a plain `return errors.Join(...)`
// would be evaluated before the deferred poweroff ever ran.
func (r *Reaper) stop(ctx context.Context, grace time.Duration) (err error) {
	close(r.stopped)
	var errs []error

	// The poweroff is deferred so that no return path, and no panic in the
	// signalling above it, can skip it.
	defer func() {
		r.log.Info("powering off the guest")
		if perr := r.proc.Poweroff(); perr != nil {
			errs = append(errs, fmt.Errorf("poweroff: %w", perr))
		}
		err = errors.Join(errs...)
	}()

	pids := r.livePIDs()
	r.log.Info("stopping the guest", "containers", len(pids), "grace", grace)
	for _, pid := range pids {
		if err := r.proc.Kill(pid, SignalTerm); err != nil {
			errs = append(errs, fmt.Errorf("term pid %d: %w", pid, err))
		}
	}

	if grace > 0 && len(pids) > 0 {
		r.awaitDrain(ctx, grace)
	}

	for _, pid := range r.livePIDs() {
		r.log.Warn("container did not exit within the grace budget; killing", "pid", pid)
		if err := r.proc.Kill(pid, SignalKill); err != nil {
			errs = append(errs, fmt.Errorf("kill pid %d: %w", pid, err))
		}
	}

	return nil
}

// awaitDrain blocks until every tracked container has been reaped, the grace
// budget expires, or ctx is cancelled.
func (r *Reaper) awaitDrain(ctx context.Context, grace time.Duration) {
	timer, stopTimer := r.newTimer(grace)
	defer stopTimer()
	for {
		if len(r.livePIDs()) == 0 {
			return
		}
		select {
		case <-r.exited:
		case <-timer:
			return
		case <-ctx.Done():
			return
		}
	}
}

// livePIDs is the sorted set of tracked, not-yet-reaped pids. Sorted so the
// signalling order is deterministic and a test can assert it.
func (r *Reaper) livePIDs() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	pids := make([]int, 0, len(r.live))
	for pid := range r.live {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}
