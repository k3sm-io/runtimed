//go:build darwin

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

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"k3sm.io/runtimed/pkg/supervisor"
)

// CreateVM boots the pod's Linux guest and returns once its guest agent has
// answered a Health RPC.
//
// the DAEMON never TOUCHES Virtualization.framework. What happens here is: write
// the machine description into the pod dir, spawn one k3sm-vmhost helper — the
// only k3sm binary carrying com.apple.security.virtualization — and wait for the
// guest it builds to answer. Every framework call is on the other side of that
// process boundary.
//
// The helper is spawned UNCONFINED, and that is a measured choice, not an
// oversight. See spawnVMHost for the two denials that decided it.
//
// It is ATOMIC IN EFFECT: every failure path after the spawn kills the helper
// before returning, so a CreateVM that reports an error leaves no machine
// running and no handle registered. The caller may retry, and the pod's next
// create is not competing with the last one's guest.
func (b *VMBackend) CreateVM(ctx context.Context, spec VMSpec) error {
	if err := validateVMSpec(spec); err != nil {
		return err
	}
	consolePath := filepath.Join(spec.PodDir, VMConsoleLogName)
	fail := func(cause VMBootCause, detail string, err error) error {
		e := &VMBootError{PodID: spec.PodID, Cause: cause, ConsolePath: consolePath, Detail: detail, Err: err}
		// one log line, at the boundary that handles the failure. The error is
		// returned as well, and the standards forbid log-and-return of the same
		// error — but this is the boundary: the caller turns it into a pod
		// FailureReason and a status message, and neither carries the helper's
		// stderr tail, which is the only evidence there is for a helper death.
		b.logger().Error("vm pod boot failed",
			"pod", spec.PodID, "cause", string(cause), "console", consolePath, "err", err, "helper_output", detail)
		return e
	}

	if b.artifacts == nil {
		return fail(VMBootArtifactsMissing, "",
			fmt.Errorf("%w: no guest-artifact locator is wired on this node, so no vm pod can boot", ErrGuestArtifactsUnavailable))
	}
	art, err := b.artifacts()
	if err != nil {
		return fail(VMBootArtifactsMissing, "", fmt.Errorf("%w: %w", ErrGuestArtifactsUnavailable, err))
	}
	if art.KernelPath == "" || art.InitramfsPath == "" {
		return fail(VMBootArtifactsMissing, "",
			fmt.Errorf("%w: the locator returned kernel=%q initramfs=%q; both are required",
				ErrGuestArtifactsUnavailable, art.KernelPath, art.InitramfsPath))
	}

	if err := ensurePodShareRoots(spec); err != nil {
		return fail(VMBootSpecWriteFailed, "", err)
	}
	specPath, err := writeVMHostSpec(spec.PodDir, buildVMHostSpec(spec, art))
	if err != nil {
		return fail(VMBootSpecWriteFailed, "", err)
	}
	// The BOOT contract, written into the k3sm.spec share root the line above
	// created, and written before the spawn below: no guest exists while it is
	// being composed, and the guest that does exist holds that share read-only
	// at the VZ device. See writeGuestSpec for why those two facts — not the
	// file mode — are what make it tamper-evident.
	gs, err := buildGuestSpec(spec)
	if err != nil {
		return fail(VMBootSpecWriteFailed, "", err)
	}
	if _, err := writeGuestSpec(spec.PodDir, gs); err != nil {
		return fail(VMBootSpecWriteFailed, "", err)
	}

	helper, err := b.vmHostFn()
	if err != nil {
		return fail(VMBootHelperNotFound, "", err)
	}

	vp, err := b.spawnVMHost(ctx, spec, helper, specPath, consolePath)
	if err != nil {
		return fail(VMBootSpawnFailed, "", err)
	}

	if err := b.awaitGuestReady(ctx, vp); err != nil {
		// Every non-ready outcome kills the helper before reporting: a helper
		// left running would hold a VM for a pod the caller is about to be told
		// does not exist.
		b.hardStop(vp)
		var bootErr *VMBootError
		if errors.As(err, &bootErr) {
			bootErr.ConsolePath = consolePath
			b.logger().Error("vm pod boot failed",
				"pod", spec.PodID, "cause", string(bootErr.Cause), "console", consolePath,
				"err", bootErr.Err, "helper_output", bootErr.Detail)
			return bootErr
		}
		return fail(VMBootAgentNeverReady, vp.tail.String(), err)
	}

	b.mu.Lock()
	if b.live == nil {
		b.live = make(map[string]*vmProc)
	}
	b.live[spec.PodID] = vp
	b.mu.Unlock()

	b.logger().Info("vm pod guest is ready",
		"pod", spec.PodID, "helper_pid", vp.pgid, "agent_socket", vp.agentSocket, "console", consolePath)
	return nil
}

// spawnVMHost starts one helper child and records it durably before returning.
//
// CONFINEMENT: the HELPER RUNS UNCONFINED, decided by measurement on an entitled
// rig (a named, deliberate choice). Spawning it under the pod's own
// Generate() profile was built and run; two independent denials killed it, both
// captured verbatim:
//
//	ls: /<work-dir>/run/vm/<pod>: Operation not permitted
//	mkdir: /tmp: Operation not permitted
//
// — the profile DENIES <work-dir>/run, which is where the agent socket must be
// bound, and that deny is not incidental: pkg/runtime's guestAgentSocket sites
// the socket there precisely so "no pod SBPL allows any agent.sock" is a property
// of the LAYOUT. Widening the profile to admit it would undo that. And, with the
// socket moved into the re-allowed pod dir to isolate the second leg:
//
//	Error Domain=VZErrorDomain Code=1 Description="Internal Virtualization error.
//	Failed to issue Fuse sandbox extension."
//
// — a confined process cannot issue the virtiofs sandbox extension VZ needs for
// a shared directory, which is exactly the device surface the S1(5) spike
// disclaimed when it showed SBPL and VZ coexisting for a share-less guest.
//
// residual, recorded rather than papered over: the helper is the one k3sm binary
// carrying com.apple.security.virtualization and it runs with no Seatbelt profile.
// Its exposure is bounded by what it is: it reads one host-written spec file,
// binds one owner-only socket, and relays bytes without parsing them
// (vmhost.Proxy). Narrowing it needs a profile written for the hypervisor's
// device surface rather than the pod's, which is its own deliverable.
//
// PUBLISHER IDENTITY, also residual: the helper is located by
// FindVMHost (beside the daemon, then PATH) and gated by Available()'s
// SecStaticCodeCheckValidity + entitlement read — a "was this mangled after
// signing" check under the code's own designated requirement, not a publisher or
// CDHash pin. On a notarized install the anchor could be pinned; k3sm helpers are
// ad-hoc signed in a dev tree, so pinning one here today would make the vm
// backend permanently unavailable outside an installed build. Tracked separately.
func (b *VMBackend) spawnVMHost(ctx context.Context, spec VMSpec, helper, specPath, consolePath string) (*vmProc, error) {
	grace := clampStopGrace(spec.StopGrace)
	tail := newLogTail(vmHelperLogTailLines)
	argv := []string{
		helper,
		"-spec", specPath,
		"-agent-socket", spec.AgentSocketPath,
		"-console-log", consolePath,
		"-stop-grace", grace.String(),
	}
	// pkg/supervisor's primitives, not a hand-rolled spawn: posix_spawn with
	// SETSID (so the helper leads its own group and a signal reaches whatever it
	// forked), SETSIGMASK/SETSIGDEF (so the helper does not inherit the Go
	// runtime's blocked SIGTERM and silently ignore graceful stop), the combined
	// stdout+stderr pipe, and the sole kqueue reaper. Re-deriving any of that
	// here would be a second, worse answer to problems this package already
	// solved once.
	proc := supervisor.NewProcess(b.spawner, b.waiter, supervisor.SpawnSpec{
		Path: helper,
		Argv: argv,
		// The helper's environment is the daemon's, deliberately: it carries no
		// pod-supplied value, and the helper reads none.
		Env: os.Environ(),
	}, tail.add)
	// The supervision context is DETACHED from ctx: the reaper and the log pump
	// must outlive the CreatePod RPC that started them — the helper runs for the
	// pod's whole life, not the request's.
	if err := proc.Start(context.WithoutCancel(ctx)); err != nil {
		return nil, err
	}

	pgid := proc.PID()
	start, ok := b.procStart(pgid)
	if !ok {
		// The helper died between spawn and probe. Record zero identity: the
		// orphan sweep can then never match it to a live leader, so it can never
		// authorize a kill (see vmReapDecision). The readiness wait below
		// observes the death and reports it properly.
		start = 0
	}
	vp := &vmProc{
		podID:         spec.PodID,
		proc:          proc,
		pgid:          pgid,
		startUnixNano: start,
		helperGrace:   grace,
		agentSocket:   spec.AgentSocketPath,
		runDir:        filepath.Dir(spec.AgentSocketPath),
		consolePath:   consolePath,
		tail:          tail,
	}
	// Record before readiness. A daemon SIGKILLed during a boot leaves a helper
	// holding a live VM, and the startup sweep can only kill what a record names
	// — so the window between spawn and record must be as close to zero as the
	// spawn's own return allows.
	if err := b.recordVMProc(vp); err != nil {
		b.hardStop(vp)
		return nil, err
	}
	b.logger().Info("spawned the vm host helper",
		"pod", spec.PodID, "helper", helper, "pid", pgid, "stop_grace", grace.String())
	return vp, nil
}

// awaitGuestReady polls the guest agent's Health RPC until it answers, the helper
// dies, the caller cancels, or the deadline expires.
//
// the exit race is the point. A helper that fails after spawn — an unentitled
// binary, a spec the contract rejects, a kernel VZ will not boot — exits in
// milliseconds. Polling alone would spend the whole 30-second deadline before
// reporting it, and would then report the wrong cause: "the agent never became
// ready" instead of the helper's own one-line explanation. Racing Process.Done()
// (closed by the sole kqueue reaper) turns that into an immediate failure
// carrying the stderr the helper actually printed.
func (b *VMBackend) awaitGuestReady(ctx context.Context, vp *vmProc) error {
	deadline := time.NewTimer(vmBootDeadline)
	defer deadline.Stop()
	poll := time.NewTicker(vmHealthPollInterval)
	defer poll.Stop()

	died := func() error {
		return &VMBootError{PodID: vp.podID, Cause: VMBootHelperDied, Detail: vp.tail.String(),
			Err: errors.New("the vm host helper exited before its guest agent answered")}
	}
	for {
		// The exit and cancellation arms are checked before each attempt as well
		// as during the wait: a helper that died while the previous attempt was
		// in flight must not buy another attempt's timeout.
		select {
		case <-vp.proc.Done():
			return died()
		case <-ctx.Done():
			return &VMBootError{PodID: vp.podID, Cause: VMBootCanceled, Err: ctx.Err()}
		default:
		}

		attemptCtx, cancel := context.WithTimeout(ctx, vmHealthAttemptTimeout)
		err := b.health(attemptCtx, vp.agentSocket)
		cancel()
		if err == nil {
			return nil
		}

		select {
		case <-vp.proc.Done():
			return died()
		case <-ctx.Done():
			return &VMBootError{PodID: vp.podID, Cause: VMBootCanceled, Err: ctx.Err()}
		case <-deadline.C:
			return &VMBootError{PodID: vp.podID, Cause: VMBootAgentNeverReady, Detail: vp.tail.String(),
				Err: fmt.Errorf("no Health response within %s; last attempt: %w", vmBootDeadline, err)}
		case <-poll.C:
		}
	}
}
