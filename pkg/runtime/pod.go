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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"k3sm.io/runtimed/pkg/image"
	"k3sm.io/runtimed/pkg/mount"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// dyldInsertEnv is the environment variable carrying the DYLD insert library
// (the darwin-net DNS shim). CreatePod copies it from the PodBox annotation into
// every container's env so it survives through the exec-shim into the pod.
const dyldInsertEnv = "DYLD_INSERT_LIBRARIES"

// dyldInsertAnnotation is the PodBox annotation key whose value is the path to
// the DYLD insert dylib for the pod (set by the provider/darwin-net).
const dyldInsertAnnotation = "k3sm.io/dyld-insert-libraries"

// pod is the runtime's per-pod state.
//
// Concurrency: the parent Runtime.mu guards membership in Runtime.pods; pod.mu
// guards this pod's own mutable fields (phase, container procs, logs).
type pod struct {
	box     *runtimev1.PodBox
	profile string

	mu         sync.Mutex
	phase      runtimev1.PodPhase
	reason     string
	message    string
	podIP      string
	containers []*containerProc

	// M2.5 memory metering/OOM state. oomKilled is set by the sampler before it
	// SIGKILLs the pod, so watchContainerExit records the OOMKilled reason.
	// memSampler/memCancel are nil when the pod has no memory limit (no sampler).
	oomKilled  bool
	memSampler *supervisor.MemorySampler
	memCancel  context.CancelFunc

	// cancel ends the pod-lifetime supervision context — the per-container reapers
	// (supervisor.Process.reap) and the watchContainerExit drain-wait. It is derived
	// from context.Background() (NOT the CreatePod request ctx, which is canceled
	// when the unary RPC returns under the daemon split), mirroring memCancel, and
	// is fired on pod teardown (DeletePod). Stored as the CancelFunc only — the
	// context itself is passed down to the goroutines, never held in this struct.
	cancel context.CancelFunc
}

// containerPIDs returns the pod's currently-running container PIDs (the memory
// sampler's PID set; re-evaluated each tick so an exited container drops out).
func (p *pod) containerPIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	pids := make([]int, 0, len(p.containers))
	for _, cp := range p.containers {
		if pid := cp.proc.PID(); pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// containerProc is one running container within a pod.
type containerProc struct {
	name string
	// spec is the container's PodBox definition, retained so Exec (and
	// RestartContainer) can re-resolve its securityContext/env/workingDir to
	// re-enter the same confinement domain and re-spawn from the same spec.
	spec *runtimev1.Container
	proc *supervisor.Process
	logs *logBuffer
	// state is updated as the container runs/terminates.
	state *runtimev1.ContainerStatus
	// restarting marks the container as mid-RestartContainer: its old process is
	// being terminated and replaced, so recomputePhaseLocked must NOT treat its
	// transient termination as a pod-terminal event (which would flip the pod to
	// Succeeded/Failed and cancel the memory sampler). Guarded by pod.mu.
	restarting bool
}

// createPod is the CreatePod spine (called with no lock held). It materializes
// each container rootfs, ad-hoc signs, gates the signature policy BEFORE exec,
// generates+validates the SBPL, and spawns each container through the exec-shim
// backend with DYLD_INSERT_LIBRARIES carried through. It returns the started pod
// or a typed failure.
//
// netcfg is the pod's guest network config (rendered resolv.conf + NAT advisory
// fields). It is INERT on the host-process spine — a host process binds a /32 lo0
// alias via r.network.Setup and never reads it — and flows ONLY to the vm route
// (createVMPod), where it lands in VMSpec.Network. In M5.1 it is zero-valued in
// production (no producer wired yet; the k3sm provider populates it later).
func (r *Runtime) createPod(ctx context.Context, box *runtimev1.PodBox, netcfg sandbox.GuestNetworkConfig) (_ *pod, _ runtimev1.FailureReason, retErr error) {
	sp := box.GetSandboxProfile()
	if sp == nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("pod %s: sandbox_profile is required", box.GetPodId())
	}

	// Fail-closed backend selection (M5.1): honor the backend the provider stamped
	// on the SandboxProfile. UNSPECIFIED — the host-process default — walks the
	// host-OS-gated Seatbelt ladder (not-root drops the uidjail rung; an unavailable
	// Seatbelt degrades ONLY to the stronger vm rung, else refuses — NEVER runs
	// unconfined). A pod that requested the vm backend (Linux image / untrusted
	// tenancy) on a host without Virtualization.framework + the entitlement is
	// REFUSED here, never silently downgraded to the weaker Seatbelt rung.
	selected, err := sandbox.SelectBackend(sp.GetBackend(), os.Geteuid() == 0, r.backend.Available(), r.vmBackend.Available())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("select sandbox backend for pod %s: %w", box.GetPodId(), err)
	}

	// Route the vm rung AWAY from the host-process (Mach-O) spine: a Linux guest has
	// no host binary to resolve, ad-hoc codesign, signature-gate, SBPL-confine, or
	// attach to lo0 — those steps are meaningless for it. The guest network config
	// (netcfg) flows ONLY here, into the vm path; the host-process path below is
	// reached only for the Seatbelt rungs and is byte-unchanged.
	if selected == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return r.createVMPod(ctx, box, sp, netcfg)
	}

	ip, err := r.network.Setup(ctx, box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			fmt.Errorf("network setup pod %s: %w", box.GetPodId(), err)
	}
	// Unwind the successful Setup if any LATER create step fails: without this,
	// a failed create leaks the pod's /32 (real IPAM allocates one per Setup and
	// DeletePod never runs for a pod that was never created). Best-effort
	// log-and-continue, mirroring the delete-path Teardown.
	defer func() {
		if retErr != nil {
			if terr := r.network.Teardown(box.GetPodId()); terr != nil {
				r.log.Warn("network teardown after failed create", "pod", box.GetPodId(), "err", terr)
			}
		}
	}()

	rootfs := r.rootfsPath(box)
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("create rootfs %s: %w", rootfs, err)
	}

	// Materialize volume sources (configMap / secret / emptyDir / downwardAPI /
	// projected) into the pod data volume. Secrets + the projected SA-token come
	// back as credential paths that get the SBPL read-only sub-scope below. (M2.2)
	// PVC sources are skipped here and bound by the volume.Binder below — they are
	// durable, lifecycle-decoupled, and live OUTSIDE the pod data volume.
	var credPaths []string
	if len(box.GetVolumes()) > 0 {
		layout, merr := mount.Materialize(ctx, box, rootfs, ip, r.resolver)
		if merr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("materialize volumes for pod %s: %w", box.GetPodId(), merr)
		}
		credPaths = layout.CredentialPaths()
	}

	// Bind APFS-backed persistent volumes (PVCs): ensure each claim's STABLE dir on
	// the storage root (empty-create / seed-once), symlink it into the pod rootfs,
	// and collect its dir as the SBPL read/write scope. The dir lives outside the
	// pod tree, so DeletePod's removePodDir never touches it (ReclaimPolicy Retain).
	// (M3.1)
	var pvWritePaths, pvReadPaths []string
	if hasPersistentVolume(box) {
		bindings, berr := r.binder.Bind(ctx, box, rootfs)
		if berr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("bind persistent volumes for pod %s: %w", box.GetPodId(), berr)
		}
		for _, bd := range bindings {
			if bd.ReadOnly {
				pvReadPaths = append(pvReadPaths, bd.DataDir)
			} else {
				pvWritePaths = append(pvWritePaths, bd.DataDir)
			}
		}
	}

	// Generate the SBPL AFTER materialization + PV binding so the credential mounts
	// get the read-only sub-scope and the PV mount roots get the read/write scope.
	// The generator validates every extra/PV path against the protected deny-set and
	// emits the protected denies last (last-match-wins).
	profile, err := sandbox.Generate(sp, sandbox.GenerateOptions{
		Posture: sandbox.Posture{
			// Pin the pods-root and protected denies under the runtime work-dir;
			// home (when set) bounds it so a misconfigured work-dir can't point a
			// pod's writable re-allow outside the daemon's data area.
			WorkDir: r.cfg.Root,
			Home:    r.home,
			// The VIPs are plumbing-only (DNS env/status): since M10.1 they render
			// NO SBPL rule — per-IP network filters do not compile on macOS 26
			// (see sandbox.Generate's AllowNetwork stanza).
			ResolverVIP:  r.cfg.ResolverVIP,
			APIServerVIP: r.cfg.APIServerVIP,
		},
		PodIP:         ip,
		ReadOnlyPaths: credPaths,
		WritePaths:    pvWritePaths,
		ReadPaths:     pvReadPaths,
	})
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("generate sbpl for pod %s: %w", box.GetPodId(), err)
	}

	// fsGroup: chown the writable pod data volume to the supplemental group
	// ROOT-SIDE, BEFORE any container's privilege drop (a uid-dropped, sandboxed
	// process can no longer chown). The supervisor runs this synchronously here,
	// strictly before posix_spawn → the exec-shim drop. (M2.3)
	if fsGroup := int(box.GetPodSecurityContext().GetFsGroup()); fsGroup > 0 {
		if err := supervisor.ChownForFSGroup(rootfs, fsGroup); err != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("fsGroup chown for pod %s: %w", box.GetPodId(), err)
		}
	}

	// Pod-lifetime supervision context. The per-container reaper and the
	// watchContainerExit drain-wait must OUTLIVE the CreatePod RPC — under the M2
	// daemon split the request ctx is canceled when the unary handler returns, which
	// would otherwise make the kqueue reaper (it honors ctx) record a bogus
	// context-canceled exit and the drain-wait snapshot an empty tail the instant
	// CreatePod replies. So derive a fresh cancelable ctx from Background — the SAME
	// pattern the M2.5 sampler uses — stored on the pod and fired on teardown. On a
	// FAILED create (a later container won't start) unwind the supervision we already
	// launched instead of leaking it; on success the cancel rides on the pod.
	podCtx, podCancel := context.WithCancel(context.Background())
	defer func() {
		if retErr != nil {
			podCancel()
		}
	}()

	p := &pod{
		box:     box,
		profile: profile,
		phase:   runtimev1.PodPhase_POD_PHASE_PENDING,
		podIP:   ip,
		cancel:  podCancel,
	}

	// init_containers run first, sequentially, each to completion; then the main
	// containers start. M1 starts all main containers and tracks them; the
	// per-container sequencing of init containers is honored by starting+waiting
	// them in order. The supervision runs under podCtx (detached from the request
	// ctx), so an init container's exit is reaped even after CreatePod returns.
	for _, c := range box.GetInitContainers() {
		cp, reason, err := r.startContainer(podCtx, p, rootfs, c, true)
		if err != nil {
			return nil, reason, err
		}
		code, _, werr := cp.proc.Wait(podCtx)
		if werr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_SPAWN,
				fmt.Errorf("init container %s wait: %w", c.GetName(), werr)
		}
		if code != 0 {
			return nil, runtimev1.FailureReason_FAILURE_REASON_SPAWN,
				fmt.Errorf("init container %s exited %d", c.GetName(), code)
		}
	}

	for _, c := range box.GetContainers() {
		cp, reason, err := r.startContainer(podCtx, p, rootfs, c, false)
		if err != nil {
			return nil, reason, err
		}
		p.mu.Lock()
		p.containers = append(p.containers, cp)
		p.mu.Unlock()
	}

	p.mu.Lock()
	p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
	p.mu.Unlock()

	// Memory sampler (M2.5): for a pod with a memory limit, sample
	// ri_phys_footprint at ~1 Hz; on breach SIGKILL the pod and record OOMKilled.
	// The sampler's lifetime is the pod — cancelled on DeletePod and on pod
	// termination (watchContainerExit), so the goroutine never leaks. Pods without
	// a limit run no sampler (the metering/OOM path is limit-driven in M2).
	if limit := podMemoryLimitBytes(box); limit > 0 {
		sampCtx, cancel := context.WithCancel(context.Background())
		sampler := supervisor.NewMemorySampler(r.footprinter, p.containerPIDs, limit, func(footprint uint64) {
			r.oomKill(p, footprint)
		})
		p.mu.Lock()
		p.memSampler = sampler
		p.memCancel = cancel
		p.mu.Unlock()
		sampler.Start(sampCtx, r.sampleInterval())
	}

	return p, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// createVMPod is the M5.1 vm-backend routing target (SKELETON). The vm path is
// deliberately SEPARATE from the host-process spine (createPod above): it does NOT
// resolveBinary, ad-hoc codesign / gateSignature, generate+apply an SBPL profile,
// or set up lo0 networking — a Linux guest runs none of those. It hands the pod's
// sizing (vm_vcpus / vm_memory_bytes) + rootfs to the vm backend's CreateVM.
//
// netcfg is threaded INERT into VMSpec.Network: the rendered resolv.conf content
// plus the NAT advisory fields the vm backend applies to the guest. This path runs
// NO IPAM, NO supervisor.PodNetwork.Setup, and binds NO lo0 alias — a NAT-attached
// guest is reached over the VZNATNetworkDeviceAttachment, never a host lo0 alias.
// The config is plain data because runtimed cannot import darwin-net (see
// sandbox.GuestNetworkConfig); the k3sm provider is the producer/mapper.
//
// The live VM boot is LAB-GATED: it needs a Virtualization.framework-capable Mac
// signed with com.apple.security.virtualization, so CreateVM is a documented stub
// returning sandbox.ErrVMBootNotImplemented. On a non-entitled host SelectBackend
// already fails closed (vmBackend.Available() == false) before this path is
// reached; on a capable host this is where the lab remainder lands — the
// cmd/k3sm-vmhost helper lifecycle, the OCI-Linux-rootfs→bootable-root builder,
// and guest-agent VM metering (see pkg/sandbox vm.go).
func (r *Runtime) createVMPod(ctx context.Context, box *runtimev1.PodBox, sp *runtimev1.SandboxProfile, netcfg sandbox.GuestNetworkConfig) (*pod, runtimev1.FailureReason, error) {
	spec := sandbox.VMSpec{
		PodID:       box.GetPodId(),
		Vcpus:       sp.GetVmVcpus(),
		MemoryBytes: sp.GetVmMemoryBytes(),
		RootfsPath:  r.rootfsPath(box),
		Network:     netcfg,
	}
	if err := r.vmBackend.CreateVM(ctx, spec); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("create vm for pod %s: %w", box.GetPodId(), err)
	}
	// Unreachable in M5.1 (CreateVM is a lab-gated stub): when the live boot lands,
	// CreateVM returns nil and this is replaced by the running-VM pod assembly
	// (phase RUNNING, guest-agent metering wired in place of the M2.5 sampler).
	return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
		fmt.Errorf("pod %s: vm backend lifecycle not implemented", box.GetPodId())
}

// oomKill is the memory sampler's onBreach callback (M2.5): it marks the pod
// OOMKilled and SIGKILLs every container's process group. The kqueue reaper then
// collects the exits and watchContainerExit records the OOMKilled termination
// reason. Called from the sampler goroutine; it takes p.mu only to snapshot state
// and signals OUTSIDE the lock (the re-entrancy rule).
func (r *Runtime) oomKill(p *pod, footprint uint64) {
	p.mu.Lock()
	p.oomKilled = true
	procs := make([]*supervisor.Process, 0, len(p.containers))
	for _, cp := range p.containers {
		procs = append(procs, cp.proc)
	}
	p.mu.Unlock()

	r.log.Warn("pod exceeded memory limit; OOMKilling",
		"pod", p.box.GetPodId(), "footprint_bytes", footprint)
	for _, proc := range procs {
		if pid := proc.PID(); pid > 0 {
			if err := r.signalGroup(pid, killSignal); err != nil {
				r.log.Warn("oom sigkill pod group", "pod", p.box.GetPodId(), "pid", pid, "err", err)
			}
		}
	}
}

// startContainer resolves the container's binary (image path convention),
// ad-hoc signs + gates it, and spawns it under the pod's Seatbelt profile via the
// exec-shim backend. It returns the running containerProc.
//
// ctx is the pod-lifetime SUPERVISION context (createPod's podCtx; restart passes a
// context.WithoutCancel) — NOT the CreatePod request ctx. It scopes the spawn, the
// kqueue reaper, and the watchContainerExit drain-wait to the pod's lifetime so they
// survive the unary RPC's return under the daemon split.
func (r *Runtime) startContainer(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container, isInit bool) (*containerProc, runtimev1.FailureReason, error) {
	binPath, argv, err := r.resolveBinary(ctx, p.box, rootfs, c)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, err
	}

	// Enforce the signature policy in the correct order relative to ad-hoc signing
	// (M2.6), BEFORE exec.
	if err := r.gateSignature(ctx, p.box.GetSignaturePolicy(), binPath); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED, err
	}

	// Resolve the container's securityContext identity, then wrap the command so
	// the spawned exec-shim drops to it, confines itself to the profile, and then
	// execs the pod binary — in that irreversible order (M2.3). env is preserved.
	cred := resolveCredential(p.box, c)
	shimPath, shimArgv, cleanup, err := r.backend.WrapCommand(ctx, p.profile, argv, cred)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("wrap command for %s: %w", c.GetName(), err)
	}

	env := r.containerEnv(p.box, c)
	logs := newLogBuffer()
	spec := supervisor.SpawnSpec{
		Path: shimPath,
		Argv: shimArgv,
		Env:  env,
		Dir:  c.GetWorkingDir(),
	}
	cp := &containerProc{
		name: c.GetName(),
		spec: c,
		logs: logs,
		state: &runtimev1.ContainerStatus{
			Name:  c.GetName(),
			Image: c.GetImage(),
			State: &runtimev1.ContainerState{
				Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()},
			},
			// Lossless status mirrors of the M2.1 spec fields (M2.2 volume_mounts,
			// M2.3 user) so kubectl Pod state does not degrade across the boundary.
			VolumeMounts: volumeMountStatuses(c),
			User:         containerUser(cred),
		},
	}
	proc := supervisor.NewProcess(r.spawner, r.waiter, spec, logs.write)
	cp.proc = proc

	if err := proc.Start(ctx); err != nil {
		_ = cleanup()
		return nil, runtimev1.FailureReason_FAILURE_REASON_SPAWN,
			fmt.Errorf("spawn container %s: %w", c.GetName(), err)
	}

	// Reap-completion goroutine: when the container exits, record terminated
	// state, clean up the staged profile, and publish a status update. It runs under
	// the pod-lifetime supervision ctx (above), so it outlives the CreatePod RPC and
	// is canceled on pod teardown.
	go r.watchContainerExit(ctx, p, cp, cleanup)
	return cp, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// watchContainerExit blocks on the container process exit, records the terminated
// state, runs cleanup, and publishes a pod-status MODIFIED event.
func (r *Runtime) watchContainerExit(ctx context.Context, p *pod, cp *containerProc, cleanup func() error) {
	code, sig, err := cp.proc.Wait(ctx)
	if cleanup != nil {
		_ = cleanup()
	}

	// Wait for the container's log pump to copy the dying child's combined output to
	// EOF BEFORE snapshotting it below for the FallbackToLogsOnError termination
	// message. The supervisor's pump drains the final bytes — the panic / stack
	// trace that is the most diagnostic part of a failure — INDEPENDENTLY of the
	// kqueue reaper that just unblocked Wait; snapshotting straight away races the
	// pump and intermittently loses those last lines. This drain-wait sits OUTSIDE
	// pod.mu so the lock order stays leaf-ward (pod.mu → logBuffer.mu, never inverted).
	//
	// The wait is BOUNDED by drainGrace, independent of ctx: a pod process commonly
	// forks a grandchild (shell → daemon) that inherits and holds the stdout/stderr
	// pipe write-end open after the direct child exits, so the pump never reaches EOF
	// and LogsDrained never closes. Without the timeout this select would block
	// forever — and for a RESTARTED container ctx is a context.WithoutCancel whose
	// Done() never fires, so LogsDrained would be the ONLY reachable arm. The
	// terminated-status path MUST finalize regardless (else the pod shows Running
	// while dead and restartPolicy never fires), so on the deadline we snapshot
	// whatever the pump has buffered so far — a partial tail is still diagnostic.
	drainTimer := time.NewTimer(r.drainGraceDuration())
	defer drainTimer.Stop()
	select {
	case <-cp.proc.LogsDrained():
	case <-drainTimer.C:
	case <-ctx.Done():
	}

	p.mu.Lock()
	term := &runtimev1.ContainerStateTerminated{
		ExitCode:   int32(code),
		Signal:     int32(sig),
		FinishedAt: nowProto(),
	}
	switch {
	case p.oomKilled && (sig != 0 || code != 0):
		// The memory sampler SIGKILLed this pod for a limit breach (M2.5): a
		// container that exited by signal / non-zero is reported OOMKilled.
		term.Reason = "OOMKilled"
	case err != nil:
		term.Reason = "Error"
		term.Message = err.Error()
	case code == 0:
		term.Reason = "Completed"
	default:
		term.Reason = "Error"
	}

	// terminationMessagePolicy=FallbackToLogsOnError: when a container FAILS (non-zero
	// exit OR a signal-kill — including OOMKilled, sig 9 / code 137) and nothing above
	// set a message, fill term.Message from the tail of its combined log. runtimed
	// applies this policy UNCONDITIONALLY — there is no per-container
	// terminationMessagePolicy in apis, and the default `File` policy is unimplementable
	// on darwin (no /dev/termination-log bind mount), so every container is treated as
	// FallbackToLogsOnError. That is a documented divergent-by-design choice, strictly
	// more diagnostic than the unavoidable File-empty message. Only term.Message is
	// touched: term.Reason keeps the tested OOMKilled/Completed/Error strings, an
	// already-set wait-error message (above) is never clobbered, and a successful
	// (exit-0) container keeps an empty message (upstream NodeConformance asserts that).
	if (code != 0 || sig != 0) && term.Message == "" {
		if msg := terminationMessageFromLogs(cp.logs); msg != "" {
			term.Message = msg
		}
	}

	cp.state.State = &runtimev1.ContainerState{Terminated: term}
	r.recomputePhaseLocked(p)
	terminal := p.phase == runtimev1.PodPhase_POD_PHASE_SUCCEEDED || p.phase == runtimev1.PodPhase_POD_PHASE_FAILED
	cancel := p.memCancel
	p.mu.Unlock()

	// Stop the memory sampler once the pod is fully terminated (no goroutine leak).
	if terminal && cancel != nil {
		cancel()
	}

	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
}

// Upstream kubelet caps for a FallbackToLogsOnError termination message sourced from
// the container LOG (kubernetes/pkg/kubelet/container/helpers.go):
// MaxContainerTerminationMessageLogLines (80) and
// MaxContainerTerminationMessageLogLength (2048). These are the LOG-fallback caps;
// the larger 4096 cap is the /dev/termination-log File-read cap, which does NOT apply
// here — the File policy is unimplementable on darwin (see watchContainerExit).
const (
	maxTerminationMessageLogLines = 80
	maxTerminationMessageLogBytes = 2048
)

// terminationMessageFromLogs renders a FallbackToLogsOnError termination message from
// the tail of a container's combined (stdout+stderr) log: the last
// maxTerminationMessageLogLines lines joined with "\n", then truncated tail-biased to
// the last maxTerminationMessageLogBytes bytes (the most recent output is the most
// diagnostic). It returns "" when the log is empty.
func terminationMessageFromLogs(logs *logBuffer) string {
	lines := logs.snapshot(maxTerminationMessageLogLines)
	if len(lines) == 0 {
		return ""
	}
	msg := bytes.Join(lines, []byte("\n"))
	if len(msg) > maxTerminationMessageLogBytes {
		msg = msg[len(msg)-maxTerminationMessageLogBytes:]
		// The byte-count tail cut can land inside a multi-byte UTF-8 rune, leaving
		// orphan continuation bytes at the front. Advance to the next rune boundary
		// so term.Message is valid UTF-8 — this only ever TRIMS, so the <=2048-byte
		// cap still holds (the tail end, the most diagnostic bytes, is untouched).
		for len(msg) > 0 && !utf8.RuneStart(msg[0]) {
			msg = msg[1:]
		}
	}
	return string(msg)
}

// recomputePhaseLocked updates the pod phase from its containers' states. Caller
// holds p.mu.
func (r *Runtime) recomputePhaseLocked(p *pod) {
	if len(p.containers) == 0 {
		return
	}
	allTerminated := true
	anyFailed := false
	for _, cp := range p.containers {
		// A container mid-restart is being re-spawned: do not let its transient
		// termination conclude the pod (the new process is about to replace it).
		if cp.restarting {
			allTerminated = false
			continue
		}
		term := cp.state.GetState().GetTerminated()
		if term == nil {
			allTerminated = false
			continue
		}
		if term.GetExitCode() != 0 {
			anyFailed = true
		}
	}
	switch {
	case allTerminated && anyFailed:
		p.phase = runtimev1.PodPhase_POD_PHASE_FAILED
	case allTerminated:
		p.phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	}
}

// gateSignature enforces the SignaturePolicy in the correct order relative to the
// ad-hoc-sign step (M2.6-d2), fail-closed, BEFORE exec:
//
//   - ADHOC_OK: ad-hoc signing is the point (an unsigned arm64 Mach-O is signed so
//     it execs under AMFI with a later DYLD insert) — so SIGN, then Check confirms
//     the signature took.
//   - REQUIRE_SIGNED / REQUIRE_NOTARIZED: enforce the policy on the AS-PULLED
//     binary and NEVER ad-hoc sign it — `codesign -s - -f` would strip an existing
//     notarization / replace a real authority with an ad-hoc signature, silently
//     downgrading the binary past the policy. A failing image is rejected here.
//   - UNSPECIFIED / unknown: Check fails closed (ErrPolicyUnspecified); no signing.
//
// Both Sign and Check errors are returned wrapped (ErrSignatureRejected /
// ErrPolicyUnspecified), which the caller maps to SIGNATURE_REJECTED.
func (r *Runtime) gateSignature(ctx context.Context, policy runtimev1.SignaturePolicy, path string) error {
	if policy == runtimev1.SignaturePolicy_SIGNATURE_POLICY_ADHOC_OK {
		if err := r.signer.Sign(ctx, path); err != nil {
			return fmt.Errorf("ad-hoc sign %s: %w", path, err)
		}
		return r.signer.Check(ctx, policy, path)
	}
	// require-signed / require-notarized / unspecified: check the as-pulled binary;
	// do NOT ad-hoc sign (no silent downgrade).
	return r.signer.Check(ctx, policy, path)
}

// resolveBinary determines the pod binary path + argv for a container. M1
// convention (mirrors the proto): if command+args are empty the image reference
// is the host binary path; otherwise the image is pulled+materialized and argv =
// command+args. The returned path is the on-disk executable to confine.
func (r *Runtime) resolveBinary(ctx context.Context, box *runtimev1.PodBox, rootfs string, c *runtimev1.Container) (string, []string, error) {
	cmd := c.GetCommand()
	if len(cmd) == 0 && len(c.GetArgs()) == 0 {
		// Host-binary convention: image is an absolute path run in place.
		bin := c.GetImage()
		if !filepath.IsAbs(bin) {
			return "", nil, fmt.Errorf("container %s: image %q is not an absolute host path and no command given", c.GetName(), bin)
		}
		return bin, []string{bin}, nil
	}

	// Resolve the imagePullSecret credential (M2.6) via the consumer-side seam. It
	// is passed ONLY to the pull client below and is NEVER written to the pod dir.
	cred, err := r.pullCredential(ctx, box, c.GetImage())
	if err != nil {
		return "", nil, err
	}

	// Pull + materialize the image into the pod rootfs, then run command/args.
	if _, err := r.puller.Pull(ctx, c.GetImage(), cred); err != nil {
		return "", nil, fmt.Errorf("pull image %q: %w", c.GetImage(), err)
	}
	// M1 materialization placeholder: the cache holds the blobs; a layer-applying
	// materializer lands with the rootfs format. For now argv[0] is command[0]
	// resolved against the rootfs if relative, else as-is.
	bin := cmd[0]
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(rootfs, bin)
	}
	argv := append(append([]string{}, cmd...), c.GetArgs()...)
	argv[0] = bin
	return bin, argv, nil
}

// pullCredential resolves the registry pull credential for ref from the pod's
// imagePullSecrets via the consumer-side CredentialResolver seam (M2.6). It
// returns nil (anonymous pull) when there is no resolver, no imagePullSecrets, or
// no matching credential. The credential never touches disk — it flows straight
// into the pull client.
func (r *Runtime) pullCredential(ctx context.Context, box *runtimev1.PodBox, ref string) (*image.RegistryCredential, error) {
	if r.credentials == nil || len(box.GetImagePullSecrets()) == 0 {
		return nil, nil
	}
	cred, ok, err := r.credentials.PullCredential(ctx, box.GetNamespace(), box.GetImagePullSecrets(), ref)
	if err != nil {
		return nil, fmt.Errorf("resolve imagePullSecret for %q: %w", ref, err)
	}
	if !ok {
		return nil, nil
	}
	return cred, nil
}

// containerEnv builds the child environment: the container's EnvVars plus the
// pod's DYLD insert (from the box annotation) so the DNS shim loads. The order
// puts DYLD_INSERT_LIBRARIES last so an explicit container env can override it if
// needed (rare).
func (r *Runtime) containerEnv(box *runtimev1.PodBox, c *runtimev1.Container) []string {
	env := make([]string, 0, len(c.GetEnv())+1)
	haveDyld := false
	for _, e := range c.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
		if e.GetName() == dyldInsertEnv {
			haveDyld = true
		}
	}
	if !haveDyld {
		if ins := box.GetAnnotations()[dyldInsertAnnotation]; ins != "" {
			env = append(env, dyldInsertEnv+"="+ins)
		}
	}
	return env
}

// rootfsPath returns the on-disk pod data volume for box: its explicit
// rootfs_path when set, else the cache-derived default under the runtime root.
// createPod, Exec, and RestartContainer share it so the pod cwd/SBPL scope is
// resolved one way.
func (r *Runtime) rootfsPath(box *runtimev1.PodBox) string {
	if rootfs := box.GetRootfsPath(); rootfs != "" {
		return rootfs
	}
	return r.cache.PodRootfs(box.GetPodId())
}

// podDir returns the per-pod directory under the cache root.
func (r *Runtime) podDir(podID string) string {
	return filepath.Dir(r.cache.PodRootfs(podID))
}

// removePodDir deletes a pod's on-disk dir (best-effort, on delete).
//
// It removes ONLY <Root>/pods/<podID>. Persistent-volume dirs live under
// <Root>/storage (a sibling of the pods root), so a PVC's data is intentionally
// NOT removed here — that is the M3.1 lifecycle decoupling (ReclaimPolicy Retain):
// the PV survives pod stop/restart/delete and the next pod that mounts the same
// claim reuses it. A PVC's pod-side symlink lives inside the pod dir and IS
// removed, but os.RemoveAll unlinks the symlink without following it, so the
// target dir under <Root>/storage is untouched.
func (r *Runtime) removePodDir(podID string) error {
	dir := r.podDir(podID)
	if dir == "" || dir == "/" || !strings.HasPrefix(dir, r.cfg.Root) {
		return nil
	}
	return os.RemoveAll(dir)
}

// hasPersistentVolume reports whether box carries any PVC-backed volume source
// (the trigger to run the persistent-volume binder). Ephemeral sources
// (configMap/secret/emptyDir/downwardAPI/projected) do not.
func hasPersistentVolume(box *runtimev1.PodBox) bool {
	for _, v := range box.GetVolumes() {
		if v.GetPersistentVolumeClaim() != nil {
			return true
		}
	}
	return false
}

// logBuffer is an in-memory ring of a container's combined output for GetLogs,
// plus a set of live followers (Attach) that receive lines as they are written.
//
// Concurrency: mu guards lines AND subs; write (the supervisor.LogSink, called
// from the supervisor's pump goroutine) appends under mu and fans out to each
// follower under the same lock; a follower's cancel removes it under mu. So a
// follower never receives after cancel and the log pump never blocks (a slow
// follower drops lines rather than stalling the pump).
type logBuffer struct {
	mu      sync.Mutex
	lines   [][]byte
	subs    map[int]chan []byte
	nextSub int
}

func newLogBuffer() *logBuffer { return &logBuffer{} }

// write appends a line (the supervisor.LogSink) and fans it out to live followers.
func (l *logBuffer) write(line []byte) {
	cp := make([]byte, len(line))
	copy(cp, line)
	l.mu.Lock()
	l.lines = append(l.lines, cp)
	for _, ch := range l.subs {
		select {
		case ch <- cp: // cp is never mutated after this, so sharing it is safe
		default: // slow follower: drop rather than block the supervisor's log pump
		}
	}
	l.mu.Unlock()
}

// subscribe registers a follower that receives lines written AFTER the call,
// returning the channel and a cancel that deregisters it. The channel is buffered
// and is NOT closed by cancel (the consumer — Attach — exits on its own ctx /
// the container's Done, never on a channel close), so there is no sender/receiver
// close race.
func (l *logBuffer) subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 256)
	l.mu.Lock()
	if l.subs == nil {
		l.subs = make(map[int]chan []byte)
	}
	id := l.nextSub
	l.nextSub++
	l.subs[id] = ch
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, id)
		l.mu.Unlock()
	}
}

// snapshot returns a copy of the buffered lines, optionally only the last n.
func (l *logBuffer) snapshot(tail int) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	start := 0
	if tail > 0 && tail < len(l.lines) {
		start = len(l.lines) - tail
	}
	out := make([][]byte, 0, len(l.lines)-start)
	for _, ln := range l.lines[start:] {
		c := make([]byte, len(ln))
		copy(c, ln)
		out = append(out, c)
	}
	return out
}
