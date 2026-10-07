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
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
	shimv1 "k3sm.io/apis/shim/v1"
)

// Pod re-adoption after a daemon restart.
//
// Pod processes are session leaders that outlive the daemon (see podreap.go).
// Before this, a restarted daemon had one answer for all of them: SIGKILL the
// group, and let the node re-create the pod. AttachPod is the second answer, the
// kubelet's: on start the node lists the pods bound to it from the apiserver (the
// spec source of truth — runtimed persists none) and, for each, asks the runtime
// to ATTACH to the live processes rather than create new ones. containerd does
// the same for its shims across a restart, and the runtime re-attaches to a
// container's resident shim the same way (residentshim.go).
//
// What is rebuilt, and from what:
//   - the pod and container records, from the spec the caller passes plus the
//     live pids from the podreap records;
//   - each container's published identity (container_id), from the same record
//     derivation the spawn used, so it is unchanged across the restart;
//   - the memory sampler, from the spec's limits only;
//   - the exit watch, through EVFILT_PROC/NOTE_EXIT on the shim, which is no
//     longer this daemon's child (supervisor.AdoptedExitWaiter);
//   - the container's output, exit status and exec surface: they live in the
//     shim, which kept writing the CRI log while no daemon ran, and ConnectShim
//     reaches it again after proving it is the recorded instance. The exit
//     reported later is the shim's persisted record, so it is real; a container
//     that exited while the daemon was down reports its recorded status.
//
// What cannot be rebuilt, and is said rather than invented:
//   - a container whose shim died: it is watched by its own recorded identity,
//     reported terminated with ExitStatusUnknownReason when it exits, its later
//     output is not captured, Exec is refused, and the pod carries
//     LogStreamLostConditionType with reason ShimCrashed. A live shim that does
//     not answer two Status calls gets the same treatment with reason
//     ShimUnresponsive, except that its exit status is still read from its
//     record;
//   - a container spawned without a shim (a backend whose helper cannot stay
//     resident): its pipes belonged to the dead daemon, so a marker line goes
//     into its CRI log, the pod carries LogStreamLostConditionType with reason
//     RuntimeRestarted, its exit is ExitStatusUnknownReason, and it refuses Exec
//     because its resolved launch environment was the previous daemon's;
//   - CPU accounting: the carry of earlier instances' CPU is gone, so it starts
//     over, and the pod message says so;
//   - the shim-inactive verdict: the exec observation happened in the previous
//     daemon, so the condition is absent rather than guessed.
//
// The confinement profile IS rebuilt: it is recompiled from the spec and this
// daemon's posture, through the pure halves of the create-time volume work
// (mount.CredentialPaths, volume.Binder.Plan), and the pod is adopted only when
// that compilation hashes to the digest every adopted container recorded at
// spawn (PodReapRecord.ProfileSHA256). A pod whose profile drifted — a changed
// posture flag, a record from before the digest — is refused and created
// afresh, so a restarted container never runs under a profile its siblings do
// not.

// ErrNothingToAttach reports that AttachPod found no live process group it may
// adopt for the pod. The caller falls back to CreatePod. Every refusal wraps it,
// including a store that cannot be read and an attach that arrived after the
// startup reap began, so the fallback is one errors.Is check.
var ErrNothingToAttach = errors.New("runtime: no live process group to attach")

// LogStreamLostConditionType is the pod condition a pod carries once a
// container's output stopped being followed: it was spawned without a shim and
// the daemon restarted (RuntimeRestarted), or its shim died (ShimCrashed) or
// does not answer (ShimUnresponsive). See residentshim.go.
const LogStreamLostConditionType = "k3sm.io/log-stream-lost"

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

// errAdoptedPod is Exec's refusal on a container re-attached without a shim: a
// session must enter the running instance's resolved launch environment, which
// this daemon did not resolve (see the header).
var errAdoptedPod = errors.New("exec is not supported in a container re-attached after a runtime daemon restart without a resident shim: its launch environment was resolved by the previous daemon")

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
	adopt, degraded, _ := attachDecision(mine, r.procGroup, r.procStart, r.fingerprint)

	// One instance per container: the newest adoptable record wins, then the
	// newest degraded one (a shim that died under a live container). Any other
	// record — an older instance, a container the spec no longer names — stays
	// unowned, and the reap that follows kills it exactly as it would have.
	byName := newestByContainer(adopt, nil)
	degradedByName := newestByContainer(degraded, byName)
	for name, rec := range degradedByName {
		byName[name] = rec
	}
	for _, c := range box.GetInitContainers() {
		if _, ok := byName[c.GetName()]; ok && !isSidecarSpec(c) {
			// The pod was mid-initialization. Resuming an init sequence from a
			// process this daemon did not start is not a thing it can do
			// faithfully; the reap kills it and the pod is created afresh.
			return nil, fmt.Errorf("attach pod %s: init container %s was still running: %w", podID, c.GetName(), ErrNothingToAttach)
		}
	}

	// The profile the pod's containers run under, recompiled from the spec with
	// THIS daemon's posture, and verified against the digest each adopted
	// container recorded at spawn. On a match the pod carries it, so
	// RestartContainer and StartContainer re-spawn a container under exactly the
	// profile its siblings run under — the CRI sandbox config surviving a
	// kubelet restart. On any mismatch (a posture flag changed, the spec's
	// volumes changed, a record predates the digest) the whole pod is refused:
	// one container restarting under a profile its siblings do not run under is
	// a confinement split nothing would ever report.
	profile, err := r.boxProfile(box)
	if err != nil {
		return nil, fmt.Errorf("attach pod %s: compile the sandbox profile: %w: %w", podID, ErrNothingToAttach, err)
	}
	digest := profileDigest(profile)
	for _, c := range attachableContainers(box) {
		rec, ok := byName[c.GetName()]
		if !ok || rec.ProfileSHA256 == digest {
			continue
		}
		r.log.Warn("attach: sandbox profile drift; the pod will be created afresh",
			"pod", podID, "container", c.GetName(), "recorded", rec.ProfileSHA256, "compiled", digest)
		return nil, fmt.Errorf("attach pod %s container %s: sandbox profile drift: %w", podID, c.GetName(), ErrNothingToAttach)
	}

	// Reconnect to every adopted container's shim BEFORE anything is
	// registered, and before r.mu (each is a socket round-trip). The digest loop
	// above ran first: a drifted posture is refused before any shim is asked
	// anything. A shim that is not the recorded instance or speaks another
	// contract version refuses the whole pod (it is created afresh); one that
	// does not answer is watched by its record, without output or exec.
	conns := map[string]shimReconnect{}
	closeConns := func() {
		for _, sr := range conns {
			if sr.conn != nil {
				_ = sr.conn.Close()
			}
		}
	}
	for name, rec := range byName {
		if rec.ShimDir == "" || degradedByName[name] == rec {
			continue
		}
		id := supervisor.ShimIdentity{Container: name, Dir: rec.ShimDir, Pid: rec.Pgid, StartUnixNano: rec.StartUnixNano}
		conn, st, err := supervisor.ConnectShim(ctx, r.shimDialer, id, r.procStart)
		switch {
		case err == nil:
			conns[name] = shimReconnect{conn: conn, st: st}
		case errors.Is(err, supervisor.ErrShimUnresponsive):
			r.log.Warn("attach: a container's resident shim does not answer; its output and exec are lost until it exits",
				"pod", podID, "container", name, "shim", rec.Pgid, "err", err)
			conns[name] = shimReconnect{unresponsive: true}
		default:
			closeConns()
			return nil, fmt.Errorf("attach pod %s container %s: %w: %w", podID, name, ErrNothingToAttach, err)
		}
	}

	type slot struct {
		cp       *containerProc
		rec      podProcRecord
		ok       bool
		degraded bool
		shim     shimReconnect
	}
	attachedAt := time.Now()
	var slots []slot
	lostReason := ""
	noteLost := func(reason string) {
		if lostReason == "" {
			lostReason = reason
		}
	}
	add := func(c *runtimev1.Container, isInit bool) {
		rec, ok := byName[c.GetName()]
		sl := slot{rec: rec, ok: ok, degraded: ok && degradedByName[c.GetName()] == rec, shim: conns[c.GetName()]}
		var exited *recordedExit
		if !ok {
			exited = exitedWhileDown(mine, c.GetName())
		}
		cp, reason := r.attachedContainer(box, c, isInit, attachedSlot{rec: rec, ok: ok, degraded: sl.degraded, shim: sl.shim, exited: exited})
		if reason != "" {
			noteLost(reason)
		}
		sl.cp = cp
		slots = append(slots, sl)
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
		closeConns()
	}
	if adopted == 0 {
		closeLogs()
		return nil, fmt.Errorf("attach pod %s: %w", podID, ErrNothingToAttach)
	}

	msg := attachedPodMessage
	if lostReason != "" {
		msg += attachedLostSuffix
	}
	shimDirs := map[string]string{}
	for _, rec := range mine {
		if rec.ShimDir != "" {
			if _, seen := shimDirs[rec.Container]; !seen || byName[rec.Container] == rec {
				shimDirs[rec.Container] = rec.ShimDir
			}
		}
	}
	podCtx, podCancel := context.WithCancel(context.Background())
	p := &pod{
		box:        box,
		profile:    profile,
		backend:    selected,
		phase:      runtimev1.PodPhase_POD_PHASE_RUNNING,
		message:    msg,
		podIP:      box.GetPodIp(),
		supCtx:     podCtx,
		cancel:     podCancel,
		adopted:    true,
		attachedAt: attachedAt,
		shimDirs:   shimDirs,
	}
	if lostReason != "" {
		noteLogStreamLostLocked(p, lostReason, attachedAt)
	}
	for _, s := range slots {
		p.containers = append(p.containers, s.cp)
	}
	// An ephemeral container is never adopted (it is never restarted, and the
	// reap that follows collects any process group it left): it is recorded as
	// not started, as a re-created pod records it.
	recordEphemeralNotStartedLocked(p)

	// Register and start the exit watches under r.mu, in one step with the
	// podReapStarted check: the reap sets that flag under the same lock at the
	// moment it snapshots the owned pgids, so either this pod is in that
	// snapshot or it is never installed. The Adopt constructors only launch a
	// goroutine, and the identity re-probe is one process-table read, so
	// nothing blocks under the lock.
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
		// attachDecision ran before the per-container I/O above; the leader
		// (or, for a degraded slot, the container) may have exited and its pid
		// been recycled since. Re-probe the exact recorded identity — the check
		// the reap's kill path runs before signalGroup — so a group that is no
		// longer the recorded instance is refused, never adopted.
		if !r.groupIsRecordedInstance(s.rec) {
			r.mu.Unlock()
			podCancel()
			closeLogs()
			return nil, fmt.Errorf("attach pod %s container %s: the leader no longer matches its record: %w", podID, s.cp.name, ErrNothingToAttach)
		}
		proc, err := r.adoptSlot(podCtx, s.rec, s.degraded, s.shim)
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

// shimReconnect is a container's resident shim as AttachPod found it: a verified
// connection and its first Status, or unresponsive.
type shimReconnect struct {
	conn         *supervisor.ShimConn
	st           *shimv1.StatusResponse
	unresponsive bool
}

// adoptSlot builds the running Process of one adopted record: through its shim,
// by its shim's record (unresponsive), by the container's own identity (its
// shim died), or by its group leader (no shim).
func (r *Runtime) adoptSlot(ctx context.Context, rec podProcRecord, degraded bool, sr shimReconnect) (*supervisor.Process, error) {
	switch {
	case degraded:
		return supervisor.AdoptChild(ctx, r.adoptWaiter, rec.Pgid, rec.ChildPid)
	case sr.conn != nil:
		return supervisor.AdoptShim(ctx, r.adoptWaiter, sr.conn, sr.st)
	case sr.unresponsive:
		return supervisor.AdoptShimByRecord(ctx, r.adoptWaiter,
			supervisor.ShimIdentity{Container: rec.Container, Dir: rec.ShimDir, Pid: rec.Pgid, StartUnixNano: rec.StartUnixNano}, rec.ChildPid)
	default:
		return supervisor.AdoptProcess(ctx, r.adoptWaiter, rec.Pgid)
	}
}

// newestByContainer keeps, per container name, the record with the newest
// leader start, skipping names already in skip.
func newestByContainer(recs []podProcRecord, skip map[string]podProcRecord) map[string]podProcRecord {
	out := make(map[string]podProcRecord, len(recs))
	for _, rec := range recs {
		if _, taken := skip[rec.Container]; taken {
			continue
		}
		if cur, ok := out[rec.Container]; !ok || rec.StartUnixNano > cur.StartUnixNano {
			out[rec.Container] = rec
		}
	}
	return out
}

// recordedExit is the persisted exit of a shim-backed instance that ended while
// no daemon ran, with the record that names it.
type recordedExit struct {
	rec  podProcRecord
	exit supervisor.ExitRecord
}

// exitedWhileDown returns the newest instance of container whose shim persisted
// an exit record, or nil: a container that exited while the daemon was down still
// has its real status in its shim dir.
func exitedWhileDown(records []podProcRecord, container string) *recordedExit {
	var best *recordedExit
	for _, rec := range records {
		if rec.Container != container || rec.ShimDir == "" {
			continue
		}
		if best != nil && rec.StartUnixNano <= best.rec.StartUnixNano {
			continue
		}
		if ex, ok, err := supervisor.ReadExitRecord(rec.ShimDir); err == nil && ok {
			best = &recordedExit{rec: rec, exit: ex}
		}
	}
	return best
}

// attachableContainers lists the spec containers AttachPod builds entries for:
// the native sidecars of the init list, then the mains — the order the pod's
// containers take in p.containers.
func attachableContainers(box *runtimev1.PodBox) []*runtimev1.Container {
	var out []*runtimev1.Container
	for _, c := range box.GetInitContainers() {
		if isSidecarSpec(c) {
			out = append(out, c)
		}
	}
	return append(out, box.GetContainers()...)
}

// boxProfile compiles a host-process pod's SBPL profile from its spec alone,
// through the pure halves of the create-time volume work: mount.CredentialPaths
// for the credential read-only sub-scope and volume.Binder.Plan for the PV
// read/write scope, then compileProfile — the derivation createPod feeds from
// Materialize and Bind. Nothing is rendered, bound or created.
func (r *Runtime) boxProfile(box *runtimev1.PodBox) (string, error) {
	rootfs, err := r.rootfsPath(box)
	if err != nil {
		return "", err
	}
	var credPaths []string
	if len(box.GetVolumes()) > 0 {
		if credPaths, err = mount.CredentialPaths(box, rootfs); err != nil {
			return "", err
		}
	}
	var pvWrite, pvRead []string
	bindings, err := r.binder.Plan(box)
	if err != nil {
		return "", err
	}
	for _, bd := range bindings {
		if bd.ReadOnly {
			pvRead = append(pvRead, bd.DataDir)
		} else {
			pvWrite = append(pvWrite, bd.DataDir)
		}
	}
	return r.compileProfile(box, rootfs, box.GetPodIp(), credPaths, pvWrite, pvRead)
}

// isSidecarSpec reports whether an init-list container is a native sidecar
// (restart_policy always), the predicate containerProc.sidecar applies.
func isSidecarSpec(c *runtimev1.Container) bool {
	return c.GetRestartPolicy() == runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
}

// attachedSlot is what AttachPod knows about one spec container.
type attachedSlot struct {
	rec      podProcRecord
	ok       bool // a live, adoptable instance
	degraded bool // its shim died; the container lives
	shim     shimReconnect
	exited   *recordedExit // no live instance, but a persisted exit
}

// attachedContainer builds the containerProc for one spec container of a pod
// being attached, and returns the log-stream-lost reason it contributes ("" for
// none). With a live instance it is Running, with the identity and start its
// record and shim report; a shim-backed instance's log is written by its shim
// and gets nothing from here. Without one, the container ended while no daemon
// watched: reported with its persisted exit when its shim recorded one, else as
// ExitStatusUnknown. The process is installed by the caller.
func (r *Runtime) attachedContainer(box *runtimev1.PodBox, c *runtimev1.Container, isInit bool, sl attachedSlot) (*containerProc, string) {
	cred := resolveCredential(box, c)
	logDir := containerLogDir(box.GetLogDirectory(), c.GetName())
	// The instance the previous daemon was writing is the highest on disk: one
	// below the number a NEW instance would take.
	instance := int32(0)
	if next, err := restartCountFromLogDir(logDir); err == nil && next > 0 {
		instance = next - 1
	}
	path := filepath.Join(logDir, containerLogFile(instance))
	cp := &containerProc{
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
	if !sl.ok {
		if ex := sl.exited; ex != nil {
			cp.state.ContainerId = ex.rec.containerID()
			cp.state.LogPath = path
			term := &runtimev1.ContainerStateTerminated{
				ExitCode:    int32(ex.exit.ExitCode),
				Signal:      int32(ex.exit.Signal),
				FinishedAt:  timestamppb.New(time.Unix(0, ex.exit.FinishedAtUnixNano)),
				ContainerId: ex.rec.containerID(),
				LogPath:     path,
				Reason:      "Error",
			}
			if ex.exit.ExitCode == 0 && ex.exit.Signal == 0 {
				term.Reason = "Completed"
			}
			cp.state.State = &runtimev1.ContainerState{Terminated: term}
			return cp, ""
		}
		cp.state.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
			ExitCode:   exitCodeUnknown,
			Reason:     ExitStatusUnknownReason,
			Message:    "the container exited while the runtime daemon was down; its exit status is unknown",
			FinishedAt: nowProto(),
		}}
		return cp, ""
	}
	rec := sl.rec
	cp.state.ContainerId = rec.containerID()
	// A running adopted instance keeps its report: re-read it from the start.
	if rootfs, err := r.rootfsPath(box); err == nil {
		r.armChildReport(box.GetPodId(), rootfs, cp, false)
	}
	started := rec.StartUnixNano
	if rec.ChildStartUnixNano != 0 {
		started = rec.ChildStartUnixNano
	}
	if st := sl.shim.st; st != nil && st.GetChildStartUnixNano() != 0 {
		started = st.GetChildStartUnixNano()
	}
	cp.state.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{
		StartedAt: timestamppb.New(time.Unix(0, started)),
	}}

	switch {
	case sl.degraded:
		cp.state.LogPath = path
		cp.execRefusal = errShimLost
		return cp, logStreamLostShimCrashed
	case sl.shim.unresponsive:
		cp.state.LogPath = path
		cp.execRefusal = errShimLost
		return cp, logStreamLostShimUnresponsive
	case sl.shim.conn != nil:
		cp.state.LogPath = path
		return cp, ""
	}

	// No shim: the pipes died with the previous daemon.
	cp.execRefusal = errAdoptedPod
	w, err := crilog.Open(path)
	if err != nil {
		// The container runs either way; its log_path is lost.
		r.log.Warn("attach: cannot re-open the container log", "pod", box.GetPodId(), "container", c.GetName(), "path", path, "err", err)
		return cp, logStreamLostRuntimeRestarted
	}
	if err := w.Write(crilog.StreamStderr, []byte(logStreamLostMarker), false); err != nil {
		r.log.Warn("attach: cannot write the log-gap line", "pod", box.GetPodId(), "container", c.GetName(), "path", path, "err", err)
	}
	cp.logw = w
	cp.state.LogPath = w.Path()
	return cp, logStreamLostRuntimeRestarted
}

// logStreamLostConditionLocked renders LogStreamLostConditionType for an attached
// pod, or nil. The caller holds p.mu.
func logStreamLostConditionLocked(p *pod) *runtimev1.PodCondition {
	if p.logStreamLostReason == "" {
		return nil
	}
	at := timestamppb.New(p.logStreamLostAt)
	return &runtimev1.PodCondition{
		Type:               LogStreamLostConditionType,
		Status:             runtimev1.ConditionStatus_CONDITION_STATUS_TRUE,
		LastProbeTime:      at,
		LastTransitionTime: at,
		Reason:             p.logStreamLostReason,
		Message:            logStreamLostMessages[p.logStreamLostReason],
	}
}
