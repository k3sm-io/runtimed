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
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Pod re-adoption after a daemon restart.
//
// Pod processes are session leaders that outlive the daemon (see podreap.go).
// Before this, a restarted daemon had one answer for all of them: SIGKILL the
// group, and let the node re-create the pod. AttachPod is the second answer, the
// kubelet's: on start the node lists the pods bound to it from the apiserver (the
// spec source of truth — runtimed persists none) and, for each, asks the runtime
// to ATTACH to the live processes rather than create new ones. containerd does
// the same for its shims across a restart; k3sm has no shim to reconnect to, so
// the runtime re-attaches to the process group directly.
//
// What is rebuilt, and from what:
//   - the pod and container records, from the spec the caller passes plus the
//     live pids from the podreap records;
//   - each container's published identity (container_id), from the same record
//     derivation the spawn used, so it is unchanged across the restart;
//   - the memory sampler, from the spec's limits only;
//   - the exit watch, through EVFILT_PROC/NOTE_EXIT on a process that is no
//     longer this daemon's child (supervisor.AdoptedExitWaiter);
//   - the log capture: a container's stdout/stderr are files the daemon tails
//     (supervisor.CaptureToFiles), so the tail resumes from the persisted
//     offset and nothing written during the gap is lost. Those lines carry the
//     time they were READ; one info line in the CRI log says where the gap was.
//
// What cannot be rebuilt, and is said rather than invented:
//   - the exit STATUS: a non-child's wait status belongs to launchd, so a
//     re-attached container that exits is reported terminated with reason
//     ExitStatusUnknownReason and exit code exitCodeUnknown — never 0;
//   - the log stream of a pod spawned before file capture: its pipes belonged
//     to the dead daemon. A marker line goes into the container's CRI log and
//     the pod carries the LogStreamLostConditionType condition. A pod whose raw
//     files and offsets exist never gets either;
//   - CPU accounting: the carry of earlier instances' CPU is gone, so it starts
//     over, and the pod message says so;
//   - the shim-inactive verdict: the exec observation happened in the previous
//     daemon, so the condition is absent rather than guessed;
//   - the confinement profile and the resolved launch environment: they were
//     derived from volume materialization the previous daemon performed, so an
//     adopted pod refuses Exec and RestartContainer (recreate the pod instead)
//     rather than run a process under a profile it cannot reproduce.

// ErrNothingToAttach reports that AttachPod found no live process group it may
// adopt for the pod. The caller falls back to CreatePod. Every refusal wraps it,
// including a store that cannot be read and an attach that arrived after the
// startup reap began, so the fallback is one errors.Is check.
var ErrNothingToAttach = errors.New("runtime: no live process group to attach")

// LogStreamLostConditionType is the pod condition an attached pod carries when a
// container's output could not be resumed: it was spawned with pipes (before
// file capture), so its output after the daemon's death was not captured.
const LogStreamLostConditionType = "k3sm.io/log-stream-lost"

// logStreamLostReason is the reason on LogStreamLostConditionType.
const logStreamLostReason = "RuntimeRestarted"

// logStreamLostMarker is the line AttachPod appends to each attached container's
// CRI log, so a reader of `kubectl logs` sees the gap where it happened.
const logStreamLostMarker = "k3sm: log stream re-attached after a daemon restart; earlier output from this container may be missing"

// ExitStatusUnknownReason is the terminated reason of a container whose exit was
// observed but whose status could not be collected (supervisor.ErrExitUnknown).
const ExitStatusUnknownReason = "ExitStatusUnknown"

// exitCodeUnknown is the exit code reported with ExitStatusUnknownReason. A real
// wait status is 0-255 (or 128+signal), so -1 cannot be mistaken for one, and it
// is non-zero so the phase accounting never reads the container as Succeeded.
const exitCodeUnknown = -1

// attachedPodMessage is the pod status message of an attached pod;
// attachedLostSuffix is appended when a container's log stream was lost.
const (
	attachedPodMessage = "re-attached after a runtime daemon restart: CPU accounting restarted from zero"
	attachedLostSuffix = "; container output written while the daemon was down was not captured"
)

// errAdoptedPod is the refusal for a verb that must re-derive the pod's
// confinement, which an adopted pod does not carry (see the header).
var errAdoptedPod = errors.New("the pod was re-attached after a runtime daemon restart and its sandbox profile was not rebuilt; recreate the pod")

// runtimeFingerprint names the build of this daemon for the podreap records: the
// hex code-directory hash of the running binary (csops CS_OPS_CDHASH), prefixed
// with its scheme. It is chosen over the module version or VCS revision because
// it is exact: two builds of one dirty tree share a revision but not a cdhash,
// and a pod's confinement is a property of the exact binary that spawned it.
// When the hash cannot be read the fingerprint is empty and AttachPod adopts
// nothing — the reap then handles every group exactly as before.
func runtimeFingerprint(log *slog.Logger) string {
	h, err := supervisor.CodeDirectoryHash(os.Getpid())
	if err != nil || h == "" {
		log.Warn("cannot read this binary's code-directory hash; pods will not be re-attached across a daemon restart", "err", err)
		return ""
	}
	return "cdhash:" + h
}

// AttachPod re-attaches the runtime to a pod whose processes survived a daemon
// restart, instead of creating it. box is the pod's spec, supplied by the caller
// (the node reads it from the apiserver); the processes are found through the
// durable podreap records, and only records attachDecision admits are used: the
// leader alive under the recorded pgid with exactly the recorded start, spawned
// by this very build. See the file header for what is and is not rebuilt.
//
// It returns ErrNothingToAttach (wrapped) when there is nothing it may adopt —
// no adoptable record, a vm pod (the vm sweep never keeps one), a pod that was
// still running a plain init container, or a call after the startup reap began —
// and the caller then creates the pod. A pod already known to the runtime is
// returned as it is, as CreatePod does.
//
// ORDERING INVARIANT: the caller attaches every pod bound to the node BEFORE it
// calls ReapOrphanedPods. The reap skips the pgids of registered pods, so an
// attached group survives it; a group nothing attached is reaped as before. An
// attach that loses the race to the reap is refused, never half-installed.
//
// It is a method on the concrete Runtime and not a Runtime service RPC: only the
// in-process node calls it, through a consumer-defined interface.
func (r *Runtime) AttachPod(ctx context.Context, box *runtimev1.PodBox) (*runtimev1.PodStatus, error) {
	if _, err := r.validatePodBox(box); err != nil {
		return nil, err
	}
	podID := box.GetPodId()

	r.mu.Lock()
	existing, known := r.pods[podID]
	started := r.podReapStarted
	r.mu.Unlock()
	if known {
		return r.podStatus(existing), nil
	}
	if started {
		return nil, fmt.Errorf("attach pod %s: the startup reap has already run: %w", podID, ErrNothingToAttach)
	}

	selected, err := sandbox.SelectBackend(box.GetSandboxProfile().GetBackend(), os.Geteuid() == 0, r.backend.Available(), r.vmBackend.Available())
	if err != nil || selected == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return nil, fmt.Errorf("attach pod %s: not a host-process pod: %w", podID, ErrNothingToAttach)
	}

	records, _, err := r.listPodProcRecords()
	if err != nil {
		return nil, fmt.Errorf("attach pod %s: %w: %w", podID, ErrNothingToAttach, err)
	}
	var mine []podProcRecord
	for _, rec := range records {
		if rec.PodID == podID {
			mine = append(mine, rec)
		}
	}
	adopt, _ := attachDecision(mine, r.procGroup, r.procStart, r.fingerprint)

	// One instance per container: the newest adoptable record wins. Any other
	// record — an older instance, a container the spec no longer names — stays
	// unowned, and the reap that follows kills it exactly as it would have.
	byName := make(map[string]podProcRecord, len(adopt))
	for _, rec := range adopt {
		if cur, ok := byName[rec.Container]; !ok || rec.StartUnixNano > cur.StartUnixNano {
			byName[rec.Container] = rec
		}
	}
	for _, c := range box.GetInitContainers() {
		if _, ok := byName[c.GetName()]; ok && !isSidecarSpec(c) {
			// The pod was mid-initialization. Resuming an init sequence from a
			// process this daemon did not start is not a thing it can do
			// faithfully; the reap kills it and the pod is created afresh.
			return nil, fmt.Errorf("attach pod %s: init container %s was still running: %w", podID, c.GetName(), ErrNothingToAttach)
		}
	}

	type slot struct {
		cp      *containerProc
		rec     podProcRecord
		ok      bool
		capture *supervisor.FileCapture
	}
	attachedAt := time.Now()
	var slots []slot
	lost := false
	add := func(c *runtimev1.Container, isInit bool) {
		rec, ok := byName[c.GetName()]
		cp, capture, cLost := r.attachedContainer(box, c, isInit, rec, ok, attachedAt)
		lost = lost || cLost
		slots = append(slots, slot{cp: cp, rec: rec, ok: ok, capture: capture})
	}
	for _, c := range box.GetInitContainers() {
		if isSidecarSpec(c) {
			add(c, true)
		}
	}
	for _, c := range box.GetContainers() {
		add(c, false)
	}
	adopted := 0
	for _, s := range slots {
		if s.ok {
			adopted++
		}
	}
	closeLogs := func() {
		for _, s := range slots {
			if s.cp.logw != nil {
				_ = s.cp.logw.Close()
			}
		}
	}
	if adopted == 0 {
		closeLogs()
		return nil, fmt.Errorf("attach pod %s: %w", podID, ErrNothingToAttach)
	}

	msg := attachedPodMessage
	if lost {
		msg += attachedLostSuffix
	}
	podCtx, podCancel := context.WithCancel(context.Background())
	p := &pod{
		box:           box,
		backend:       selected,
		phase:         runtimev1.PodPhase_POD_PHASE_RUNNING,
		message:       msg,
		podIP:         box.GetPodIp(),
		supCtx:        podCtx,
		cancel:        podCancel,
		adopted:       true,
		attachedAt:    attachedAt,
		logStreamLost: lost,
	}
	for _, s := range slots {
		p.containers = append(p.containers, s.cp)
	}

	// Register and start the exit watches under r.mu, in one step with the
	// podReapStarted check: the reap sets that flag under the same lock at the
	// moment it snapshots the owned pgids, so either this pod is in that
	// snapshot or it is never installed. AdoptProcess only launches a goroutine,
	// and the identity re-probe is one process-table read, so nothing blocks
	// under the lock.
	r.mu.Lock()
	if r.podReapStarted {
		r.mu.Unlock()
		podCancel()
		closeLogs()
		return nil, fmt.Errorf("attach pod %s: the startup reap began during the attach: %w", podID, ErrNothingToAttach)
	}
	if cur, ok := r.pods[podID]; ok {
		r.mu.Unlock()
		podCancel()
		closeLogs()
		return r.podStatus(cur), nil
	}
	for _, s := range slots {
		if !s.ok {
			continue
		}
		var sink supervisor.LogSink
		if s.capture != nil {
			sink = containerLogSink(s.cp.logw, s.cp.fanout)
		}
		// attachDecision ran before the per-container file I/O above; the
		// leader may have exited (and its pgid been recycled) since. Re-probe
		// the exact recorded identity — the check the reap's kill path runs
		// before signalGroup — so a group that is no longer the recorded
		// instance is refused, never adopted.
		if !r.groupIsRecordedInstance(s.rec) {
			r.mu.Unlock()
			podCancel()
			closeLogs()
			return nil, fmt.Errorf("attach pod %s container %s: the leader no longer matches its record: %w", podID, s.cp.name, ErrNothingToAttach)
		}
		proc, err := supervisor.AdoptProcess(podCtx, r.adoptWaiter, s.rec.Pgid, sink, s.capture)
		if err != nil {
			// Unreachable for a record listPodProcRecords returned (it
			// quarantines pgid <= 1), but a half-adopted pod must not be
			// installed: cancelling podCtx ends the watches already started.
			r.mu.Unlock()
			podCancel()
			closeLogs()
			return nil, fmt.Errorf("attach pod %s container %s: %w: %w", podID, s.cp.name, ErrNothingToAttach, err)
		}
		s.cp.proc = proc
	}
	r.pods[podID] = p
	r.mu.Unlock()

	p.mu.Lock()
	r.recomputePhaseLocked(p)
	p.mu.Unlock()
	for _, s := range slots {
		if s.cp.proc != nil {
			go r.watchContainerExit(podCtx, p, s.cp, nil)
		}
	}
	r.armMemorySampler(p)
	r.log.Info("re-attached a pod that survived a daemon restart", "pod", podID, "containers", adopted)

	st := r.podStatus(p)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED, st)
	return st, nil
}

// isSidecarSpec reports whether an init-list container is a native sidecar
// (restart_policy always), the predicate containerProc.sidecar applies.
func isSidecarSpec(c *runtimev1.Container) bool {
	return c.GetRestartPolicy() == runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
}

// attachedContainer builds the containerProc for one spec container of a pod
// being attached. With a record (ok) it is the running instance: the CRI log of
// its instance is re-opened, and its identity and start come from the record.
// Without one the container died while no daemon was watching, so it is
// reported terminated with an unknown status. The process is installed by the
// caller.
//
// It returns the capture to resume when the container's output was
// file-captured (captureResumable) — the CRI log then gets one info line naming
// the gap — and lost when it was not: a pipe-era container, whose log gets the
// gap marker and whose pod gets LogStreamLostConditionType.
func (r *Runtime) attachedContainer(box *runtimev1.PodBox, c *runtimev1.Container, isInit bool, rec podProcRecord, ok bool, attachedAt time.Time) (cp *containerProc, capture *supervisor.FileCapture, lost bool) {
	cred := resolveCredential(box, c)
	logDir := containerLogDir(box.GetLogDirectory(), c.GetName())
	// The instance the previous daemon was writing is the highest on disk: one
	// below the number a NEW instance would take.
	instance := int32(0)
	if next, err := restartCountFromLogDir(logDir); err == nil && next > 0 {
		instance = next - 1
	}
	cp = &containerProc{
		name:         c.GetName(),
		spec:         c,
		initDeclared: isInit,
		fanout:       &logFanout{},
		state: &runtimev1.ContainerStatus{
			Name:         c.GetName(),
			Image:        c.GetImage(),
			RestartCount: instance,
			VolumeMounts: volumeMountStatuses(c),
			User:         containerUser(cred),
		},
	}
	if !ok {
		cp.state.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
			ExitCode:   exitCodeUnknown,
			Reason:     ExitStatusUnknownReason,
			Message:    "the container exited while the runtime daemon was down; its exit status is unknown",
			FinishedAt: nowProto(),
		}}
		return cp, nil, false
	}
	cp.state.ContainerId = rec.containerID()
	cp.state.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{
		StartedAt: timestamppb.New(time.Unix(0, rec.StartUnixNano)),
	}}

	fc, err := r.containerCapture(box.GetPodId(), c.GetName())
	resumable := err == nil && captureResumable(fc)
	lost = !resumable

	path := filepath.Join(logDir, containerLogFile(instance))
	w, err := crilog.Open(path)
	if err != nil {
		// The container runs either way; its log_path and the tail are lost.
		r.log.Warn("attach: cannot re-open the container log", "pod", box.GetPodId(), "container", c.GetName(), "path", path, "err", err)
		return cp, nil, true
	}
	line := logStreamLostMarker
	if resumable {
		line = resumedLogLine(attachedAt, lastOffsetWrite(fc))
	}
	if err := w.Write(crilog.StreamStderr, []byte(line), false); err != nil {
		r.log.Warn("attach: cannot write the log-gap line", "pod", box.GetPodId(), "container", c.GetName(), "path", path, "err", err)
	}
	cp.logw = w
	cp.state.LogPath = w.Path()
	if resumable {
		capture = &fc
	}
	return cp, capture, lost
}

// lastOffsetWrite is the latest time the previous daemon persisted either of a
// container's tail offsets — the last moment its output is known to have been
// captured. Zero when neither can be stat'ed.
func lastOffsetWrite(fc supervisor.FileCapture) time.Time {
	var last time.Time
	for _, raw := range []string{fc.Stdout, fc.Stderr} {
		if st, err := os.Stat(supervisor.OffsetPath(raw)); err == nil && st.ModTime().After(last) {
			last = st.ModTime()
		}
	}
	return last
}

// resumedLogLine is the one info line an attach writes into a resumed
// container's CRI log: where the daemon restart was, and that what follows was
// captured late and carries read-time timestamps.
func resumedLogLine(attachedAt, lastCaptured time.Time) string {
	gap := "an unknown gap"
	if !lastCaptured.IsZero() && attachedAt.After(lastCaptured) {
		gap = "a gap of up to " + attachedAt.Sub(lastCaptured).Round(time.Millisecond).String()
	}
	return fmt.Sprintf("k3sm: daemon restarted at %s; the following lines were captured after %s and are stamped when read, not when written",
		attachedAt.UTC().Format(time.RFC3339Nano), gap)
}

// logStreamLostConditionLocked renders LogStreamLostConditionType for an attached
// pod, or nil. The caller holds p.mu.
func logStreamLostConditionLocked(p *pod) *runtimev1.PodCondition {
	if !p.logStreamLost {
		return nil
	}
	at := timestamppb.New(p.attachedAt)
	return &runtimev1.PodCondition{
		Type:               LogStreamLostConditionType,
		Status:             runtimev1.ConditionStatus_CONDITION_STATUS_TRUE,
		LastProbeTime:      at,
		LastTransitionTime: at,
		Reason:             logStreamLostReason,
		Message:            logStreamLostMarker,
	}
}
