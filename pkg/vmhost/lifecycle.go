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

package vmhost

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// State is the VM host's lifecycle state. The transitions are total and
// one-directional: New -> Starting -> Running -> Stopping -> Stopped, with Failed
// reachable from Starting and Stopping. Nothing ever goes backwards, so an
// observed state is also a statement about what has already happened.
type State int

// The lifecycle states.
const (
	// StateNew is the state before Run is called.
	StateNew State = iota
	// StateStarting means the machine is being created and booted.
	StateStarting
	// StateRunning means the machine booted and has not been asked to stop.
	StateRunning
	// StateStopping means shutdown has begun: the guest agent has been asked to
	// stop, or the grace budget is being spent.
	StateStopping
	// StateStopped is the terminal success state: the machine is off.
	StateStopped
	// StateFailed is the terminal failure state: the machine could not be started,
	// or could not be stopped cleanly.
	StateFailed
)

// String renders a state for logs. The tokens are machine-greppable and stable.
func (s State) String() string {
	switch s {
	case StateNew:
		return "New"
	case StateStarting:
		return "Starting"
	case StateRunning:
		return "Running"
	case StateStopping:
		return "Stopping"
	case StateStopped:
		return "Stopped"
	case StateFailed:
		return "Failed"
	default:
		return fmt.Sprintf("Unknown(%d)", int(s))
	}
}

// machineRunner is the consumer-side seam for the virtual machine itself: the
// three verbs the lifecycle needs and nothing more.
//
// Keeping it to three methods is what lets the whole state machine — the only
// genuinely concurrent code in this package — run under `go test -race` on any
// machine, against a fake, with no Virtualization framework and no entitlement.
// The darwin implementation is vzRunner (vz_darwin.go).
type machineRunner interface {
	// Start creates and boots the machine. It returns once the machine is
	// running, or an error if it could not be started.
	Start(ctx context.Context) error
	// Wait blocks until the machine has left the running state — the guest
	// powered itself off, or the hypervisor stopped it — and returns the reason,
	// or nil for a clean stop. It returns ctx.Err() if ctx ends first.
	Wait(ctx context.Context) error
	// Stop halts the machine without giving the guest a chance to stop cleanly.
	// It is the last resort after the graceful path has spent its budget, and it
	// must be safe to call on a machine that has already stopped.
	Stop(ctx context.Context) error
}

// agentStopper is the consumer-side seam for the graceful half of shutdown: one
// call into the guest agent asking the guest to terminate its containers, sync,
// and power off.
//
// It is separate from machineRunner because it is a different FAILURE DOMAIN. The
// agent lives in the guest and is reached over vsock, so it can be wedged,
// compromised, or simply not listening yet, while the hypervisor-level stop cannot.
// A lifecycle that could not tell the two apart would have to treat an unreachable
// agent as a machine failure.
type agentStopper interface {
	// Stop asks the guest to shut down within grace. An error means the request
	// did not get through; the caller falls back to the hard stop.
	Stop(ctx context.Context, grace time.Duration) error
}

// DefaultStopGrace is the graceful-termination budget used when none is supplied.
const DefaultStopGrace = 20 * time.Second

// MaxStopGrace is the ceiling this helper will ever wait for a guest. It is the
// guest agent's own ceiling (pkg/guestagent maxStopGraceSeconds, 300 s): the
// agent clamps whatever it is sent to that value, so a longer host-side budget
// would be one the guest never spends, and a shorter one would cut a pod's
// terminationGracePeriodSeconds the guest is prepared to honour.
//
// The helper serves TWO callers, and each owns its own budget; neither lives here.
//
//   - A pod deletion (DeletePod -> StopVM) gives the helper the pod's grace, up
//     to this ceiling, and the daemon waits that grace plus a fixed margin
//     (pkg/sandbox VMHelperStopMargin) before it SIGKILLs the helper, so the
//     helper's own hard stop and clean exit always come first.
//   - A bounded stop of every helper (StopAllVMs, for a caller that means to
//     end every guest on the node) is capped by pkg/sandbox VMStopAllBound. The
//     daemon divides that bound itself and SIGKILLs a helper whose pod grace
//     does not fit, logging the cut; the helper cannot be told a shorter budget
//     after it was spawned, so it never reasons about that path. A daemon exit
//     is NOT a caller: the helper outlives the daemon and the next one adopts
//     it (pkg/sandbox AdoptVM) or kills it.
//
// A caller asking for more than this is clamped and told.
const MaxStopGrace = 300 * time.Second

// AgentUnreachableWait bounds the wait for the machine to leave Running on its
// own once the graceful leg has failed: the guest agent refused or never
// answered the Stop RPC, or there is no agent transport at all.
//
// Without a request delivered, nothing in the guest is shutting the workload
// down, so spending the rest of the pod's grace idle would only delay the hard
// stop that is coming anyway. The short wait remains for a guest that was
// already on its way down (a poweroff in flight is exactly what makes the agent
// stop answering). A host-side power-button request (VZ RequestStop) would be a
// second graceful path; it is not wired here, so this bound is the whole
// fallback.
const AgentUnreachableWait = 5 * time.Second

// GuestStopReserve is the time past the guest's own grace the helper leaves the
// guest before the hard stop: the guest init SIGKILLs whatever ignored SIGTERM
// when the grace runs out, and only then syncs its filesystems and powers off.
// A helper whose hard stop landed exactly at the grace would cut that sync on
// every pod that used its whole grace, which is the data loss the graceful path
// exists to prevent.
const GuestStopReserve = 2 * time.Second

// HardStopBound bounds the hard stop itself (the hypervisor halting the
// machine). Together with GuestStopReserve it must fit inside the margin the
// daemon allows past the grace (pkg/sandbox VMHelperStopMargin), so a helper
// whose guest spent the whole budget still halts its machine and exits before the
// daemon would kill it; TestStopGraceBoundsAreSingleValued pins the ordering.
const HardStopBound = 3 * time.Second

// LifecycleOptions are the lifecycle's tunables and test seams.
type LifecycleOptions struct {
	// Grace is the graceful-termination budget, measured from the moment shutdown
	// begins (the SIGTERM). Zero means DefaultStopGrace; anything above
	// MaxStopGrace is clamped (with a Warn) — see MaxStopGrace.
	Grace time.Duration
	// Logger receives the lifecycle's narration; nil means slog.Default.
	Logger *slog.Logger
	// NewTimer is the grace timer, injectable so shutdown ordering is asserted
	// deterministically rather than by sleeping. nil means time.NewTimer. It
	// mirrors guestinit.ReaperOptions.NewTimer, which solves the same problem at
	// the other end of the same shutdown.
	NewTimer func(d time.Duration) (<-chan time.Time, func() bool)
	// Now is the clock the shutdown measures the elapsed time it logs at each
	// step on. nil means time.Now.
	Now func() time.Time
}

// Lifecycle drives one virtual machine from creation to poweroff.
//
// The shutdown sequence is the whole reason it exists, and its order is
// load-bearing:
//
//		SIGTERM (as ctx cancellation) -> start ONE clock of grace +
//		GuestStopReserve -> agent.Stop(grace) -> wait, until the clock runs out, for
//		the machine to leave Running -> hard machine.Stop()
//
//	  - The AGENT goes first because only the guest can terminate the workload
//	    gracefully and sync its filesystems. A hard stop is a power cut: for a pod
//	    mid-write it is data loss, and for a PVC it is data loss that outlives the
//	    pod.
//	  - The guest is sent the grace in whole seconds, rounded to the nearest and
//	    never below one (see guestGrace), and it gets GuestStopReserve past it
//	    for the sync and poweroff that follow its own SIGKILL.
//	  - There is ONE clock, started when the signal arrives. The daemon times its
//	    own SIGKILL from the moment it sent SIGTERM, so a helper whose budget
//	    started later (when the Stop RPC returned, say) would always be the second
//	    to expire, and a guest that used its whole grace would always end with the
//	    daemon killing the helper instead of the helper halting the machine.
//	  - The hard stop always happens if the graceful path did not finish. A helper
//	    that returned while its VM was still running would leave a machine with no
//	    pod, which the daemon can only reap by timeout.
//	  - An agent that cannot be reached shortens the wait to AgentUnreachableWait:
//	    no request got through, so nothing in the guest is spending the budget.
//	  - Grace is CLAMPED, not trusted (see MaxStopGrace).
//
// Locking discipline: mu guards state only. Every runner and agent call is made
// with mu released, so a seam that blocks — which the agent one certainly can —
// never blocks a State() read from the logging path.
//
// The zero value is not usable; construct one with NewLifecycle.
type Lifecycle struct {
	runner   machineRunner
	agent    agentStopper
	grace    time.Duration
	log      *slog.Logger
	newTimer func(d time.Duration) (<-chan time.Time, func() bool)
	now      func() time.Time

	mu    sync.Mutex
	state State
}

// NewLifecycle builds a lifecycle over runner and agent. agent may be nil, in
// which case shutdown skips the graceful leg and goes straight to the hard stop —
// which is the honest behaviour when no agent transport could be established, not
// a reason to refuse to stop.
func NewLifecycle(runner machineRunner, agent agentStopper, opts LifecycleOptions) *Lifecycle {
	l := &Lifecycle{
		runner:   runner,
		agent:    agent,
		grace:    opts.Grace,
		log:      opts.Logger,
		newTimer: opts.NewTimer,
		now:      opts.Now,
		state:    StateNew,
	}
	if l.log == nil {
		l.log = slog.Default()
	}
	if l.newTimer == nil {
		l.newTimer = func(d time.Duration) (<-chan time.Time, func() bool) {
			t := time.NewTimer(d)
			return t.C, t.Stop
		}
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.grace <= 0 {
		l.grace = DefaultStopGrace
	}
	if l.grace > MaxStopGrace {
		l.log.Warn("clamping the guest stop grace to the guest agent's ceiling",
			"requested", l.grace, "clamped_to", MaxStopGrace)
		l.grace = MaxStopGrace
	}
	return l
}

// State returns the current lifecycle state.
func (l *Lifecycle) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// set records a transition and narrates it.
func (l *Lifecycle) set(s State) {
	l.mu.Lock()
	prev := l.state
	l.state = s
	l.mu.Unlock()
	l.log.Info("vm lifecycle transition", "from", prev.String(), "to", s.String())
}

// Run boots the machine and blocks until it stops.
//
// It returns when EITHER the guest ended on its own (the machine left Running:
// StateStopped, or StateFailed with the machine's reason) OR ctx was cancelled, in
// which case it runs the shutdown sequence first and returns its outcome. It never
// returns with the machine still running.
//
// ctx cancellation is how SIGTERM arrives: cmd/k3sm-vmhost builds a
// signal.NotifyContext, so the signal handler is a context cancellation and this
// function needs no signal handling of its own.
func (l *Lifecycle) Run(ctx context.Context) error {
	if l.State() != StateNew {
		return errors.New("vmhost: lifecycle already run; a Lifecycle drives exactly one machine")
	}
	l.set(StateStarting)
	if err := l.runner.Start(ctx); err != nil {
		// A failed Start must still BE TORN down. The darwin runner races the
		// framework's boot against ctx (vz_darwin.go Start's select), so a
		// cancelled Start returns while the machine it already created goes on
		// to finish booting — a VM with no supervisor, outliving the process
		// that made it, which is exactly the invariant this package exists to
		// keep ("no VM outlives the binary"). Forcing the hard stop here is the
		// only place that window can be closed: Run is about to return, and
		// nothing downstream holds the runner.
		//
		// The stop runs on a context DETACHED from ctx — ctx is the thing that
		// just ended, so passing it would cancel the teardown it is the reason
		// for — bounded by the same grace budget the shutdown path uses. Stop is
		// documented safe on a machine that never started, so the ordinary
		// failure (a bad configuration, no entitlement) pays one no-op call.
		stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(ctx), l.grace)
		defer cancelStop()
		if serr := l.runner.Stop(stopCtx); serr != nil {
			l.log.Warn("could not halt the machine after a failed start; it may still be running",
				"start_err", err, "stop_err", serr)
		}
		l.set(StateFailed)
		return fmt.Errorf("start the virtual machine: %w", err)
	}
	l.set(StateRunning)

	// waitCtx is deliberately not ctx: the wait must survive ctx's cancellation so
	// the shutdown sequence below can use the same wait to observe the guest
	// leaving Running. Cancelling it is this function's own job, on the way out.
	waitCtx, cancelWait := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWait()

	waited := make(chan error, 1)
	go func() { waited <- l.runner.Wait(waitCtx) }()

	select {
	case err := <-waited:
		// The guest ended on its own terms. Nothing to stop.
		if err != nil {
			l.set(StateFailed)
			return fmt.Errorf("the virtual machine stopped abnormally: %w", err)
		}
		l.set(StateStopped)
		return nil
	case <-ctx.Done():
		l.log.Info("shutting the guest down", "cause", ctx.Err(), "grace", l.grace)
		return l.shutdown(waited)
	}
}

// shutdown runs the graceful-then-hard stop sequence, using waited — the same wait
// goroutine Run already started — as its observation of the machine leaving
// Running. Reusing it is what makes the "wait <= grace" leg honest: a second wait
// would be a second observer of a one-shot event, and the two could disagree.
//
// The grace clock starts here, before the agent is asked anything, and the agent
// call runs beside it rather than in front of it: a wedged RPC spends the same
// budget the guest would have, never extra.
func (l *Lifecycle) shutdown(waited <-chan error) error {
	start := l.now()
	elapsed := func() time.Duration { return l.now().Sub(start) }
	l.set(StateStopping)

	// The deadline covers the grace the guest is sent AND the reserve for its
	// sync and poweroff, measured from the signal: the guest's own SIGKILL comes
	// at sent, and the helper's hard stop never before sent + GuestStopReserve.
	sent := guestGrace(l.grace)
	deadline, stopDeadline := l.newTimer(sent + GuestStopReserve)
	defer stopDeadline()
	l.log.Info("asking the guest to stop", "grace", sent, "reserve", GuestStopReserve)

	// The graceful leg runs on a context that is not the cancelled one: ctx is
	// already done by the time we are here, so passing it would cancel the very
	// RPC whose whole purpose is to run after the signal. It is cancelled when
	// this function returns, which bounds it by the grace clock above.
	rpcCtx, cancelRPC := context.WithCancel(context.Background())
	defer cancelRPC()

	agentDone := make(chan error, 1)
	if l.agent == nil {
		agentDone <- errors.New("no guest agent transport")
	} else {
		go func() { agentDone <- l.agent.Stop(rpcCtx, sent) }()
	}

	var fallback <-chan time.Time
	stopFallback := func() bool { return false }
	defer func() { stopFallback() }()
	for {
		select {
		case err := <-waited:
			if err != nil {
				l.set(StateFailed)
				return fmt.Errorf("the virtual machine stopped abnormally during shutdown: %w", err)
			}
			l.log.Info("the guest powered itself off within the grace budget",
				"grace", sent, "elapsed", elapsed())
			l.set(StateStopped)
			return nil
		case err := <-agentDone:
			agentDone = nil
			if err == nil {
				l.log.Info("the guest agent accepted the stop request", "elapsed", elapsed())
				continue
			}
			// not fatal, and not a machine failure: the agent lives in the guest
			// and is a different failure domain (see agentStopper). Nothing reached
			// the guest, so the rest of the budget would be spent idle; wait only
			// a short bound for a guest already on its way down.
			l.log.Warn("no graceful path reached the guest; halting the machine unless it powers off first",
				"err", err, "elapsed", elapsed(), "wait", AgentUnreachableWait)
			fallback, stopFallback = l.newTimer(AgentUnreachableWait)
			continue
		case <-fallback:
			l.log.Warn("the guest did not power off after the failed stop request; halting the machine",
				"elapsed", elapsed())
		case <-deadline:
			l.log.Warn("the guest did not power off within the grace budget; halting the machine",
				"grace", sent, "reserve", GuestStopReserve, "elapsed", elapsed())
		}
		break
	}

	// The hard stop. It is reached only after the budget was spent or no
	// graceful path exists, which is the property that keeps a graceful shutdown
	// from becoming a power cut. Its own bound fits inside the margin the daemon
	// allows past the grace (see HardStopBound).
	hardCtx, cancelHard := context.WithTimeout(context.Background(), HardStopBound)
	defer cancelHard()
	if err := l.runner.Stop(hardCtx); err != nil {
		l.set(StateFailed)
		return fmt.Errorf("halt the virtual machine: %w", err)
	}
	l.log.Info("the machine was halted", "elapsed", elapsed())
	l.set(StateStopped)
	return nil
}

// guestGrace is the grace the guest is sent: the configured grace rounded to
// the nearest whole second (the proto carries seconds), never below one.
//
// It is computed from the configured grace, not from what is left of it when the
// RPC goes out: that remainder is always a little under the integer, so flooring
// it sent a 1 s pod grace as 0 (an immediate SIGKILL in the guest) and a 30 s
// grace as 29 s. The floor of one second keeps a SIGTERM in front of every
// SIGKILL, as the k8s contract does for any non-zero grace.
func guestGrace(d time.Duration) time.Duration {
	return max(d.Round(time.Second), time.Second)
}
