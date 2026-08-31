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
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"k3sm.io/runtimed/pkg/supervisor"

	guestv1 "k3sm.io/apis/guest/v1"
)

// vmBootDeadline bounds spec-write -> spawn -> VM attach -> guest boot -> agent
// handshake for ONE pod.
//
// DERIVATION, not a round number. The M11 S1 spike measured create->guest-token
// at 165 ms median / 172 ms max on one uncontended VM; a live d9 smoke on the
// same rig measured the WHOLE chain — helper spawn through a Health round trip
// over agent.sock — at 668-707 ms across five runs. So 30 s is roughly forty
// times the observed worst case, which is the margin a node under real pod
// churn needs: several guests booting at once contend for CPU, page cache and
// the APFS clone the rootfs share was just built from, and none of that shows
// up in a single-VM measurement.
//
// It is a CEILING, never a delay — readiness ends the wait the instant the agent
// answers, and a helper that dies first ends it sooner still (CreateVM races the
// poll against Process.Done). The bound exists so a guest that will never boot
// fails one pod in bounded time instead of holding a CreatePod RPC open forever.
const vmBootDeadline = 30 * time.Second

// vmHealthPollInterval is how often the readiness poll retries the Health RPC
// while the guest boots. It is short relative to the sub-second boot the smoke
// measured, so readiness is observed promptly, and the cost is bounded: the poll
// is per-pod, runs only during boot, and stops at the first success.
const vmHealthPollInterval = 50 * time.Millisecond

// vmHealthAttemptTimeout bounds ONE readiness attempt. Without it a dial into a
// socket the helper has bound but whose guest is still booting could block past
// the whole deadline inside a single attempt, and the exit-watch arm below would
// never be re-evaluated — a helper that died mid-boot would then be reported as
// "agent never ready" instead of by its own stderr.
const vmHealthAttemptTimeout = 2 * time.Second

// vmHelperLogTailLines is how many of the helper's most recent combined-output
// lines are retained for a boot failure's message. The helper is terse — a
// handful of lifecycle transitions and one error — so this holds its whole
// narrative, while bounding what a screaming helper can accumulate in daemon
// memory per pod.
const vmHelperLogTailLines = 32

// VMBootCause names WHY a vm pod's guest never reached readiness.
//
// Every one of them surfaces to the caller as FAILURE_REASON_SANDBOX_SETUP,
// because at the enum level they are all "the sandbox could not be set up" and
// the runtime/v1 taxonomy has no finer bucket. The distinction that matters is
// OPERATIONAL, not schematic: "no artifacts on this node" is a provisioning
// fault that will fail every pod, "the helper died" points at the helper's own
// stderr, and "the agent never answered" points at the guest console. So the
// cause is carried in the MESSAGE, where an operator reads it, rather than
// invented as a new wire enum nothing consumes.
type VMBootCause string

// The boot-failure causes, in the order the spine can hit them.
const (
	// VMBootArtifactsMissing: the pinned kernel/initramfs could not be resolved.
	// A node fault, identical for every pod.
	VMBootArtifactsMissing VMBootCause = "artifacts-missing"
	// VMBootSpecWriteFailed: the machine description could not be written into
	// the pod dir.
	VMBootSpecWriteFailed VMBootCause = "spec-write-failed"
	// VMBootHelperNotFound: the k3sm-vmhost helper does not resolve. Distinct
	// from artifacts-missing because the remedy is an install, not a fetch.
	VMBootHelperNotFound VMBootCause = "helper-not-found"
	// VMBootSpawnFailed: posix_spawn of the helper failed. The helper never ran,
	// so there is no stderr and no console.
	VMBootSpawnFailed VMBootCause = "spawn-failed"
	// VMBootHelperDied: the helper exited BEFORE the agent answered. Its own
	// stderr tail is the diagnosis and is carried in the error.
	VMBootHelperDied VMBootCause = "helper-died-pre-ready"
	// VMBootAgentNeverReady: the helper stayed alive but no Health round trip
	// completed within vmBootDeadline. The guest console is the diagnosis.
	VMBootAgentNeverReady VMBootCause = "agent-never-ready"
	// VMBootCanceled: the caller's context ended during the boot.
	VMBootCanceled VMBootCause = "canceled"
)

// VMBootError is a vm pod's boot failure with its sub-cause named.
//
// It always carries the CONSOLE PATH, including for causes where the console is
// certainly empty (spawn-failed). That is deliberate: the operator reading the
// message should not have to know which failures produce a console to know where
// to look, and an empty file is itself the answer that the guest never started.
type VMBootError struct {
	// PodID is the pod whose guest failed to boot.
	PodID string
	// Cause is the sub-cause; see VMBootCause.
	Cause VMBootCause
	// ConsolePath is the pod's guest console log.
	ConsolePath string
	// Detail is cause-specific evidence — for VMBootHelperDied, the helper's
	// captured stderr tail. Empty when the cause carries none.
	Detail string
	// Err is the underlying error, if any.
	Err error
}

// Error renders the failure with the sub-cause and the console path first, since
// those are the two things a reader acts on.
func (e *VMBootError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "vm pod %s failed to boot (%s; guest console %s)", e.PodID, e.Cause, e.ConsolePath)
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, "; helper output: %s", e.Detail)
	}
	return b.String()
}

// Unwrap exposes the underlying error so errors.Is reaches the sentinels
// (ErrGuestArtifactsUnavailable, ErrInvalidVMSpec, ErrVMHostNotFound).
func (e *VMBootError) Unwrap() error { return e.Err }

// GuestHealthFunc round-trips a guest/v1 Health RPC over a helper's agent socket
// and reports whether the guest answered.
//
// READINESS IS AN RPC, NEVER A SOCKET DIAL. The helper binds and accepts on
// agent.sock BEFORE the machine is created (cmd/k3sm-vmhost listens, then runs
// the lifecycle), so a successful connect proves only that the helper is alive —
// it says nothing about the guest, and treating it as readiness would report
// every pod Running the instant its helper started. Only a Health response
// crosses the whole chain: unix socket -> helper proxy -> vsock -> the guest
// agent, which guest-init starts as its LAST boot step precisely so answering it
// means the pod is up.
//
// It is a seam so the whole readiness state machine — the deadline, the
// exit race, the kill — is unit-testable against a fake agent with no VM.
type GuestHealthFunc func(ctx context.Context, agentSocket string) error

// dialGuestHealth is the production GuestHealthFunc: one gRPC Health call over a
// fresh connection to the helper's agent socket, closed on return.
//
// A fresh connection per attempt is right for a probe that runs a handful of
// times during one boot: there is no reconnect state machine to get wrong, and a
// connection made before the guest was listening cannot be reused into a
// misleading success.
func dialGuestHealth(ctx context.Context, agentSocket string) error {
	conn, err := grpc.NewClient("passthrough:///"+agentSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(dctx context.Context, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(dctx, "unix", agentSocket)
		}),
	)
	if err != nil {
		return fmt.Errorf("dial the guest agent at %s: %w", agentSocket, err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := guestv1.NewGuestAgentClient(conn).Health(ctx, &guestv1.HealthRequest{}); err != nil {
		return fmt.Errorf("guest agent Health at %s: %w", agentSocket, err)
	}
	return nil
}

// vmProc is one live k3sm-vmhost child: the handle the daemon stops it, watches
// it, and reaps its record through.
//
// Immutable after CreateVM registers it. The one mutable thing it references is
// the log tail, which has its own lock.
type vmProc struct {
	podID string
	proc  *supervisor.Process
	// pgid is the helper's process GROUP, which equals its pid: the supervisor
	// spawns with POSIX_SPAWN_SETSID, so the child is a session leader. Signals
	// go to the GROUP so a helper that forked is torn down whole.
	pgid int
	// startUnixNano is the helper's kernel start time — the other half of the
	// exact-instance identity the orphan sweep matches on. See vmProcRecord.
	startUnixNano int64
	// helperGrace is the budget the helper will actually honour, already clamped
	// by the same rule the helper applies. The daemon's escalation never waits
	// less than this.
	helperGrace time.Duration
	// agentSocket / runDir / consolePath are recorded verbatim rather than
	// re-derived at teardown: the derivations live in pkg/runtime, and a second
	// derivation here could disagree with the one that created them.
	agentSocket string
	runDir      string
	consolePath string
	tail        *logTail
}

// logTail is a bounded ring of a child's most recent output lines.
//
// It exists so a helper that dies before readiness can explain itself. The
// alternative — reading the console log — answers a different question: the
// console is the GUEST's narrative, and a helper that failed before creating the
// machine has an empty one.
type logTail struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLogTail(max int) *logTail { return &logTail{max: max} }

func (l *logTail) add(line []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, string(line))
	if len(l.lines) > l.max {
		l.lines = l.lines[len(l.lines)-l.max:]
	}
}

// String renders the retained lines newline-joined, or a stated absence. The
// absence is spelled out rather than left empty because "the helper printed
// nothing" and "we captured nothing" look identical in a log line otherwise.
func (l *logTail) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return "(the helper produced no output)"
	}
	return strings.Join(l.lines, " | ")
}

// StopVM terminates the pod's vm host helper and releases everything the spine
// recorded for it. It is idempotent: a pod with no live helper succeeds.
//
// ONE GRACE BUDGET, TWO PROCESSES. The wait is max(the caller's grace, the budget
// the helper was actually given) — never less than the helper's. The helper
// answers SIGTERM by asking the guest to stop, waiting out its own budget, and
// only then halting the machine; a daemon that escalated to SIGKILL first would
// cut that short, and a hard stop with a guest mid-write is the power cut the
// grace period exists to prevent. A caller-requested grace of 0 is honoured as
// the apis immediate-kill contract, because that request is explicit.
func (b *VMBackend) StopVM(ctx context.Context, podID string, grace time.Duration) error {
	b.mu.Lock()
	vp, ok := b.live[podID]
	delete(b.live, podID)
	b.mu.Unlock()
	if !ok {
		return nil
	}
	return b.stopProc(ctx, vp, grace)
}

// stopProc runs the SIGTERM -> wait -> SIGKILL escalation for one helper and
// cleans up after it.
func (b *VMBackend) stopProc(ctx context.Context, vp *vmProc, grace time.Duration) error {
	wait := grace
	if wait > 0 && wait < vp.helperGrace {
		wait = vp.helperGrace
	}
	escalated, observed, err := supervisor.GracefulStop(ctx, vp.pgid, wait, vp.proc.Done(),
		vmTermSignal, vmKillSignal, b.signal, 0)
	b.logger().Info("vm host helper stop outcome",
		"pod", vp.podID, "pid", vp.pgid, "wait", wait.String(), "escalated", escalated, "exit_observed", observed)
	if !observed {
		// The helper did not die within the observation bound. Teardown must not
		// hang on it, so we continue — but the record is KEPT (below) so the next
		// daemon start's sweep re-evaluates it, which is the only thing that can
		// still catch a helper holding a live VM.
		b.logger().Warn("vm host helper exit not observed; its record is kept for the next startup sweep",
			"pod", vp.podID, "pid", vp.pgid)
		return err
	}
	b.removeVMProcRecord(vp.pgid)
	b.cleanupVMRunDir(vp)
	return err
}

// hardStop is the failure-path teardown: SIGKILL the helper's group with no
// grace, then release its record and run dir.
//
// No grace, deliberately. It is reached only when the boot FAILED, so there is no
// workload to terminate gracefully and no guest state worth syncing — and the
// alternative, spending a grace budget on a guest that never came up, delays the
// pod's failure by exactly that budget for nothing.
func (b *VMBackend) hardStop(vp *vmProc) {
	ctx, cancel := context.WithTimeout(context.Background(), supervisor.DefaultExitObservationGrace)
	defer cancel()
	if _, _, err := supervisor.GracefulStop(ctx, vp.pgid, 0, vp.proc.Done(),
		vmTermSignal, vmKillSignal, b.signal, 0); err != nil {
		b.logger().Warn("could not kill the vm host helper after a failed boot",
			"pod", vp.podID, "pid", vp.pgid, "err", err)
	}
	b.removeVMProcRecord(vp.pgid)
	b.cleanupVMRunDir(vp)
}

// StopAllVMs stops every live helper CONCURRENTLY and returns the joined errors.
//
// CONCURRENCY IS REQUIRED, NOT AN OPTIMIZATION. This runs on daemon shutdown,
// inside launchd's 45-second ExitTimeOut. Each helper's graceful stop can spend
// up to VMHostMaxStopGrace (30 s), so stopping serially blows the timeout with
// two vm pods — and launchd's answer to a blown timeout is SIGKILL of the daemon,
// which strands exactly the helpers this sweep exists to stop. Fanning out makes
// the whole node's cost one budget rather than one per pod.
//
// Each helper is stopped with ITS OWN recorded grace, not a shared one: the
// budget is the pod's promise to its workload and does not become shorter because
// the pod happens to be shutting down alongside others.
func (b *VMBackend) StopAllVMs(ctx context.Context) error {
	b.mu.Lock()
	procs := make([]*vmProc, 0, len(b.live))
	for _, vp := range b.live {
		procs = append(procs, vp)
	}
	b.live = make(map[string]*vmProc)
	b.mu.Unlock()
	if len(procs) == 0 {
		return nil
	}
	b.logger().Info("stopping every vm host helper for daemon shutdown", "helpers", len(procs))

	errs := make([]error, len(procs))
	var wg sync.WaitGroup
	for i, vp := range procs {
		wg.Add(1)
		go func(i int, vp *vmProc) {
			defer wg.Done()
			errs[i] = b.stopProc(ctx, vp, vp.helperGrace)
		}(i, vp)
	}
	wg.Wait()
	return errors.Join(errs...)
}

// VMDone returns the edge closed when the pod's helper has exited, and whether
// the pod has a live helper at all.
//
// It is what lets the runtime WATCH a booted guest: a hypervisor crash or a guest
// kernel panic ends the helper, and without this edge the pod would sit at
// Running forever with nothing on the host able to notice. The channel is the
// supervisor's, closed by the sole kqueue reaper, so it is broadcast-safe for
// several observers and never a second wait4.
func (b *VMBackend) VMDone(podID string) (<-chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	vp, ok := b.live[podID]
	if !ok {
		return nil, false
	}
	return vp.proc.Done(), true
}

// VMHelperOutput returns the retained tail of a live helper's combined output, or
// a stated absence. It is the diagnosis for a helper that died AFTER readiness,
// where the pod is already Running and the boot-time error path is long gone.
func (b *VMBackend) VMHelperOutput(podID string) string {
	b.mu.Lock()
	vp, ok := b.live[podID]
	b.mu.Unlock()
	if !ok {
		return "(no live vm host helper for this pod)"
	}
	return vp.tail.String()
}

// cleanupVMRunDir removes the helper's runtimed-private run directory.
//
// The helper unlinks its own socket on a clean exit but cannot remove the
// directory (it may have been SIGKILLed, and it does not own the layout). A
// leftover dir is not merely untidy: the next pod with the same id binds inside
// it, and a stale socket there would make a fresh helper's bind fail for a reason
// that has nothing to do with it.
func (b *VMBackend) cleanupVMRunDir(vp *vmProc) {
	if vp.runDir == "" {
		return
	}
	if err := os.RemoveAll(vp.runDir); err != nil {
		b.logger().Warn("could not remove the vm pod's private run dir",
			"pod", vp.podID, "dir", vp.runDir, "err", err)
	}
}
