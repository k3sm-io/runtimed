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

	// backend is the sandbox backend sandbox.SelectBackend RESOLVED for this pod
	// — never the one the PodBox requested. It is recorded once by createPod and
	// read on every (re-)spawn, including RestartContainer, which re-enters
	// startContainer long after CreatePod returned; that is why it lives on the
	// pod rather than riding as a parameter. It is what the image-platform
	// policy of a pull is derived from (image.PlatformPolicy.Backend is defined
	// as the resolved backend), so a pull can never be run under a rung the pod
	// is not actually confined by. Immutable after createPod. A future spine that
	// assembles a pod of its own (createVMPod, once the live boot lands) records
	// its own resolved backend here; leaving it zero fails CLOSED at the next
	// pull (UNSPECIFIED has no image-platform candidates) rather than defaulting.
	backend runtimev1.SandboxBackend

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

	// supCtx / cancel are the pod-lifetime SUPERVISION context and its cancel —
	// the scope of the per-container reapers (supervisor.Process.reap), the
	// watchContainerExit drain-wait, and the M2.5 memory sampler. It is derived
	// from context.Background() (NOT the CreatePod request ctx, which is canceled
	// when the unary RPC returns under the daemon split) and fired on pod teardown
	// (DeletePod).
	//
	// Holding the CONTEXT here is a deliberate, narrow exception to the
	// "never store a Context in a struct" rule (docs/GO-STANDARDS.md §Context),
	// taken for the same reason net/http.Server keeps a BaseContext: the field is
	// NOT a request scope but the object's own LIFETIME, and goroutines started
	// long after CreatePod returned — RestartContainer re-arming the memory
	// sampler — must be rooted at it. Without that, a re-armed sampler was rooted
	// at context.Background() and p.cancel could not stop it, leaving a root
	// daemon goroutine able to SIGKILL a process group forever (B26). Never pass
	// supCtx to a request-scoped call; it outlives every RPC.
	supCtx context.Context
	cancel context.CancelFunc

	// sidecarTeardown marks the terminal sidecar teardown as claimed (guarded by
	// mu): the first main-container exit that concludes the pod stops the native
	// sidecars exactly once, even when several mains terminate concurrently (see
	// claimTerminalTeardownLocked / stopSidecars). It is a one-shot latch, so it
	// cannot cover a sidecar spawned AFTER the claim — RestartContainer re-claims
	// the live sidecars of a still-terminal pod for exactly that reason.
	sidecarTeardown bool
}

// containerPIDs returns the pod's currently-running container PIDs (the memory
// sampler's PID set; re-evaluated each tick so an exited container drops out).
func (p *pod) containerPIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	pids := make([]int, 0, len(p.containers))
	for _, cp := range liveContainersLocked(p) {
		if pid := cp.proc.PID(); pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids
}

// liveContainersLocked returns the pod's containers that have NOT terminated.
//
// The filter is load-bearing, not cosmetic: supervisor.Process.PID() keeps
// returning the LAST pid after the reaper collects the process, so an unfiltered
// walk hands a dead pid to the two consumers that act on it — the memory
// sampler's PID set (containerPIDs) and, worse, oomKill, which SIGKILLs the whole
// PROCESS GROUP as root. Darwin recycles pids/pgids, so a stale entry is a root
// daemon aiming an uncatchable signal at whatever now owns that group. Dropping
// terminated containers is the defense-in-depth half of that (the other half is
// the truly-terminal teardown that stops the sampler at all — see
// trulyTerminalLocked). Caller holds p.mu.
func liveContainersLocked(p *pod) []*containerProc {
	out := make([]*containerProc, 0, len(p.containers))
	for _, cp := range p.containers {
		if cp.state.GetState().GetTerminated() != nil {
			continue
		}
		out = append(out, cp)
	}
	return out
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
	// initDeclared marks a container declared in the pod's INIT list. Combined
	// with the retained spec's restart_policy it derives sidecar(); deriving the
	// class from the spec (rather than copying a second flag) means a
	// RestartContainer re-spawn keeps the same lifecycle class as long as
	// initDeclared is threaded through (see RestartContainer). Immutable after
	// startContainer.
	initDeclared bool
}

// sidecar reports whether cp is a NATIVE SIDECAR (KEP-753): an init-declared
// container with restart_policy ALWAYS. A sidecar is long-lived — spawned in its
// init-list position but not waited to completion — EXCLUDED from the mains-only
// terminal phase accounting (recomputePhaseLocked), reported under
// init_container_statuses, and stopped in reverse start order after the mains
// (stopSidecars). Per the apis restart_policy contract the field is meaningful
// ONLY on an init container, so a main container carrying ALWAYS is NOT a sidecar.
func (cp *containerProc) sidecar() bool {
	return cp.initDeclared &&
		cp.spec.GetRestartPolicy() == runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
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
		backend: selected,
		phase:   runtimev1.PodPhase_POD_PHASE_PENDING,
		podIP:   ip,
		supCtx:  podCtx,
		cancel:  podCancel,
	}

	// init_containers run first, sequentially; then the main containers start.
	// A plain init container (restart_policy UNSPECIFIED — the byte-legacy apis
	// contract) runs TO COMPLETION before the next init step, exactly as in M1.
	// An init container with restart_policy ALWAYS is a NATIVE SIDECAR (KEP-753,
	// M10.2): it is spawned in its init-list position through the same
	// startContainer machinery (same confinement class + rootfs resolution) but
	// NOT waited — the sequence proceeds once it is started (spawn-equals-started;
	// startup-probe gating of progression is deliberately out of scope per the
	// apis restart_policy contract). A sidecar joins p.containers so the status
	// stream and RestartContainer find it by name; it is excluded from the
	// mains-only phase accounting (recomputePhaseLocked) and torn down in reverse
	// start order after the mains (stopSidecars). runtimed performs NO exit-driven
	// sidecar restarts — the provider is the single restart authority via
	// RestartContainer. The supervision runs under podCtx (detached from the
	// request ctx), so an init container's exit is reaped even after CreatePod
	// returns.
	for _, c := range box.GetInitContainers() {
		cp, reason, err := r.startContainer(podCtx, p, rootfs, c, true)
		if err != nil {
			return nil, reason, err
		}
		if cp.sidecar() {
			p.mu.Lock()
			p.containers = append(p.containers, cp)
			p.mu.Unlock()
			continue
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

	// NOTE: the memory sampler is armed by the CALLER (CreatePod), strictly AFTER
	// the pod is registered in r.pods. armMemorySampler refuses to arm an
	// unregistered pod (its anti-stranding guard, B26), so arming here — before
	// registration — would silently leave every limited pod unenforced.

	return p, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// armMemorySampler starts the pod's memory sampler (M2.5): for a pod with a
// memory limit it samples ri_phys_footprint at ~1 Hz and, on breach, SIGKILLs the
// pod and records OOMKilled. The sampler's lifetime is the pod — cancelled on
// DeletePod and on any TRULY-terminal transition, Succeeded OR Failed
// (trulyTerminalLocked) — so the goroutine never leaks. A pod without a limit
// runs no sampler (the metering/OOM path is limit-driven in M2).
//
// It is called by CreatePod (after the pod is registered) and AGAIN by
// RestartContainer when a re-exec de-escalates a pod out of a terminal phase,
// because that terminal transition already cancelled the sampler: the
// replacement main must never run without the OOM enforcement its limit
// promises. Any predecessor sampler is therefore cancelled here, so EXACTLY ONE
// sampler ever enforces the limit. Call with p.mu NOT held — the cancel is issued
// outside the lock (the sampler's onBreach callback takes p.mu), per the
// callbacks-outside-locks discipline.
//
// ANTI-STRANDING (B26). A sampler is a root-daemon goroutine whose breach path
// SIGKILLs a process GROUP, so it must never outlive its pod. Two independent
// stoppers close that, in the r.mu → p.mu lock order the whole package uses:
//
//  1. It REFUSES to arm a pod that is no longer registered in r.pods. DeletePod
//     removes the pod under r.mu BEFORE it cancels, so an arm that loses that
//     race is dropped rather than stranded on a deleted pod. (RestartContainer
//     resolves *pod up front and then blocks in GracefulStop for the whole grace
//     window before reaching here, so the losing interleaving is reachable, not
//     theoretical.)
//  2. The sampler ctx is rooted at the pod-lifetime p.supCtx, NOT
//     context.Background(). If the delete instead lands just after the check
//     above, p.cancel (DeletePod) tears this sampler down too. The two stoppers
//     are therefore ORDER-INDEPENDENT: whichever side wins, the goroutine dies.
func (r *Runtime) armMemorySampler(p *pod) {
	limit := podMemoryLimitBytes(p.box)
	if limit == 0 {
		return
	}
	r.mu.Lock()
	registered := r.pods[p.box.GetPodId()] == p
	r.mu.Unlock()
	if !registered {
		// Deleted (or replaced) while we were getting here: arming now would strand
		// a root SIGKILL-capable goroutine on a pod nothing will ever cancel.
		r.log.Debug("skip memory sampler arm for an unregistered pod", "pod", p.box.GetPodId())
		return
	}
	sampCtx, cancel := context.WithCancel(p.supCtx)
	sampler := supervisor.NewMemorySampler(r.footprinter, p.containerPIDs, limit, func(footprint uint64) {
		r.oomKill(p, footprint)
	})
	p.mu.Lock()
	prev := p.memCancel
	p.memSampler = sampler
	p.memCancel = cancel
	p.mu.Unlock()
	if prev != nil {
		prev()
	}
	sampler.Start(sampCtx, r.sampleInterval())
}

// createVMPod is the M5.1 vm-backend routing target (SKELETON). The vm path is
// deliberately SEPARATE from the host-process spine (createPod above): it does NOT
// resolveBinary, ad-hoc codesign / gateSignature, generate+apply an SBPL profile,
// or set up lo0 networking — a Linux guest runs none of those. It hands the pod's
// sizing (vm_vcpus / vm_memory_bytes) + rootfs + the virtiofs volume share plan
// (B106, computed below) to the vm backend's CreateVM.
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
	// Compute the virtiofs share-device plan from the box's volumes (B106) —
	// pure data: no filesystem access and no chown (the planner plans; the VZ
	// device config enforces writability, guest-init composes the binds —
	// B102). The pod dir is derived LOCALLY (r.podDir) and the planner ignores
	// box.rootfs_path for share roots: that field is caller-supplied and
	// unvalidated (rootfsPath below still honors it for the host-side
	// VMSpec.RootfsPath, unchanged here).
	//
	// A planner reject maps to INVALID_POD_BOX via the errInvalidPodBox house
	// pattern (validate.go) — deliberately NOT the ROOTFS_SETUP the native
	// spine folds mount.Materialize failures into (createPod above): that
	// conflation is the native path's own divergence; here nothing has touched
	// disk — the box itself is unplannable.
	plan, err := mount.ComputeSharePlan(box, r.podDir(box.GetPodId()), r.cfg.Root, r.binder.Class())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: vm volume share plan for pod %s: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	spec := sandbox.VMSpec{
		PodID:       box.GetPodId(),
		Vcpus:       sp.GetVmVcpus(),
		MemoryBytes: sp.GetVmMemoryBytes(),
		RootfsPath:  r.rootfsPath(box),
		Network:     netcfg,
		Volumes:     vmVolumePlan(plan),
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

// vmVolumePlan maps the pkg/mount share plan onto the sandbox DTO, value for
// value. createVMPod is the NAMED MAPPER on this seam: sandbox must not import
// pkg/mount (the GuestNetworkConfig decoupling precedent — sandbox.VMVolumePlan
// is plain data), and pkg/mount stays the single volume/path authority.
func vmVolumePlan(plan mount.SharePlan) sandbox.VMVolumePlan {
	out := sandbox.VMVolumePlan{}
	if len(plan.Shares) > 0 {
		out.Shares = make([]sandbox.VMShare, 0, len(plan.Shares))
		for _, s := range plan.Shares {
			out.Shares = append(out.Shares, sandbox.VMShare{Tag: s.Tag, Root: s.Root, Writable: s.Writable})
		}
	}
	if len(plan.Binds) > 0 {
		out.Binds = make(map[string][]sandbox.VMBind, len(plan.Binds))
		for name, bs := range plan.Binds {
			mapped := make([]sandbox.VMBind, 0, len(bs))
			for _, b := range bs {
				mapped = append(mapped, sandbox.VMBind{
					VolumeName: b.VolumeName,
					ShareTag:   b.ShareTag,
					SourceRel:  b.SourceRel,
					MountPath:  b.MountPath,
					SubPath:    b.SubPath,
					ReadOnly:   b.ReadOnly,
				})
			}
			out.Binds[name] = mapped
		}
	}
	if len(plan.Tmpfs) > 0 {
		out.Tmpfs = make(map[string][]sandbox.VMTmpfs, len(plan.Tmpfs))
		for name, ts := range plan.Tmpfs {
			mapped := make([]sandbox.VMTmpfs, 0, len(ts))
			for _, tm := range ts {
				mapped = append(mapped, sandbox.VMTmpfs{
					VolumeName: tm.VolumeName,
					MountPath:  tm.MountPath,
					SubPath:    tm.SubPath,
					SizeLimit:  tm.SizeLimit,
					ReadOnly:   tm.ReadOnly,
				})
			}
			out.Tmpfs[name] = mapped
		}
	}
	return out
}

// oomKill is the memory sampler's onBreach callback (M2.5): it marks the pod
// OOMKilled and SIGKILLs every container's process group. The kqueue reaper then
// collects the exits and watchContainerExit records the OOMKilled termination
// reason. Called from the sampler goroutine; it takes p.mu only to snapshot state
// and signals OUTSIDE the lock (the re-entrancy rule).
func (r *Runtime) oomKill(p *pod, footprint uint64) {
	p.mu.Lock()
	p.oomKilled = true
	// Only LIVE containers are signalled: PID() still reports the last pid of a
	// reaped container, and darwin recycles pgids, so signalling a terminated
	// container's group is a root SIGKILL aimed at an unrelated process group
	// (see liveContainersLocked).
	live := liveContainersLocked(p)
	procs := make([]*supervisor.Process, 0, len(live))
	for _, cp := range live {
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
// isInit records that c was declared in the pod's init list (containerProc.
// initDeclared), from which sidecar() derives the lifecycle class. It does NOT
// alter confinement: the SBPL profile is pod-scoped (p.profile) and the rootfs
// resolution is pod-scoped too (the caller passes r.rootfsPath), identical for
// init, sidecar, and main containers.
//
// ctx is the pod-lifetime SUPERVISION context (createPod's podCtx; restart passes a
// context.WithoutCancel) — NOT the CreatePod request ctx. It scopes the spawn, the
// kqueue reaper, and the watchContainerExit drain-wait to the pod's lifetime so they
// survive the unary RPC's return under the daemon split.
func (r *Runtime) startContainer(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container, isInit bool) (*containerProc, runtimev1.FailureReason, error) {
	binPath, argv, hostBinary, err := r.resolveBinary(ctx, p, rootfs, c)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, err
	}

	// Enforce the signature policy in the correct order relative to ad-hoc signing
	// (M2.6), BEFORE exec. A host binary is never ad-hoc re-signed (hostBinary).
	if err := r.gateSignature(ctx, p.box.GetSignaturePolicy(), binPath, hostBinary); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED, err
	}

	// Resolve the container's securityContext identity plus the pod's rlimit plan
	// and qos decision (one supervisor.LaunchSpec — B7), then wrap the command so
	// the spawned exec-shim applies the limits, drops to the identity, backgrounds
	// itself if BestEffort, confines itself to the profile, and then execs the pod
	// binary — in that irreversible order (M2.3/B7). env is preserved.
	cred := resolveCredential(p.box, c)
	shimPath, shimArgv, cleanup, err := r.backend.WrapCommand(ctx, p.profile, argv, resolveLaunchSpec(p.box, cred))
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
		name:         c.GetName(),
		spec:         c,
		initDeclared: isInit,
		logs:         logs,
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

	// Durably record the spawned process group BEFORE the spawn is acknowledged
	// (the startup pod reap's input, podreap.go). Failure fails the container:
	// an unrecorded pod process would be invisible to the reap and could orphan
	// across a daemon death — exactly the hole the record exists to close. The
	// just-spawned group is torn down through the injected seam (not a direct
	// supervisor call) so the failure path is unit-observable.
	if err := r.recordPodProc(p.box.GetPodId(), c.GetName(), proc.PID()); err != nil {
		_ = r.signalGroup(proc.PID(), killSignal)
		_ = cleanup()
		return nil, runtimev1.FailureReason_FAILURE_REASON_SPAWN,
			fmt.Errorf("record container %s process group: %w", c.GetName(), err)
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

	// Drop the durable reap record ONLY once the process GROUP is empty. The
	// leader exit that unblocked Wait does not imply forked grandchildren are
	// gone (the drain-wait below exists precisely because they commonly are
	// not), and on the ctx-cancel arm the leader itself may still be alive — so
	// removing the record here unconditionally would erase a live process's
	// record. A record left behind is harmless (identity-guarded) and is
	// retired by DeletePod's teardown or the next startup reap's group probe.
	if members, ok := r.procGroup(cp.proc.PID()); ok && len(members) == 0 {
		r.removePodProcRecord(p.box.GetPodId(), cp.proc.PID())
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
	// Snapshot the restart flag under the SAME lock that guards the state write,
	// so the publish decision at the bottom cannot straddle a concurrent
	// RestartContainer claiming this container.
	restarting := cp.restarting
	r.recomputePhaseLocked(p)

	// The mains just concluded the pod (mains-only accounting above). If that
	// conclusion is TRULY terminal, claim the irreversible teardown — stop the
	// memory sampler and stop the native sidecars in REVERSE start order — BEFORE
	// the terminal publish below. See trulyTerminalLocked for the predicate and
	// claimTerminalTeardownLocked for the exactly-once claim.
	td := claimTerminalTeardownLocked(p)
	p.mu.Unlock()

	// One pod-level grace budget, anchored NOW: the mains exited on their own
	// (voluntary completion) and consumed none of it, so the sidecars share the
	// whole configured budget in reverse start order (see stopSidecars).
	r.runTerminalTeardown(ctx, p, td)

	// Suppress the TRANSIENT terminated publish of a container the provider is
	// already restarting (B26). The state write above stands — RestartContainer
	// reads it back for last_termination_state — but publishing it would show
	// the provider a "new" exit for a restart IT issued, and its terminationKey
	// idempotency would schedule a SECOND restart for the same death. The
	// authoritative event for this exit is the one RestartContainer publishes
	// after the swap, carrying the bumped restart_count. On a FAILED restart
	// clearRestarting drops the flag, so the exit is published by the next
	// status transition and normal accounting resumes.
	if restarting {
		return
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

// trulyTerminalLocked reports whether the pod has reached a state it can NEVER
// leave on its own — the ONLY transition allowed to fire the two IRREVERSIBLE
// pod-teardown side effects (cancelling the memory sampler that ENFORCES the
// pod's limit, and stopping the native sidecars, which cannot be resurrected).
// Caller holds p.mu, and must have recomputed the phase first.
//
// The predicate is: a terminal PHASE (Succeeded OR Failed) with NO container
// mid-restart.
//
// Both halves are load-bearing:
//
//   - Failed MUST be included. A restartPolicy Never/OnFailure pod whose main
//     fails is genuinely finished — nothing will ever restart it — yet Kubernetes
//     RETAINS it: the Job controller keeps the failed pod under
//     backoffLimit/podFailurePolicy (ttlSecondsAfterFinished is commonly unset)
//     and podgc only collects at --terminated-pod-gc-threshold (default 12500).
//     "DeletePod is the backstop" is therefore FALSE for exactly the workload
//     native sidecars exist to serve. On k3sm a pod is native Darwin processes
//     with no cgroup/namespace parent to collect them, so a teardown that never
//     fires is PERMANENT: N such pods leave N ~1 Hz sampler goroutines (each able
//     to root-SIGKILL a process group) and N live sidecar process trees, unbounded
//     and with no operator-visible signal.
//
//   - The mid-restart guard is what makes including Failed SAFE, and it is sound
//     precisely because recomputePhaseLocked de-escalates: a MAIN mid-restart
//     holds the phase at Running (allTerminated is false), so a Failed phase
//     already implies no main is restarting — the scan below is a defensive
//     restatement for the mains and the REAL work for SIDECARS, which
//     recomputePhaseLocked skips entirely. Tearing down a sidecar that
//     RestartContainer is mid-swap on would stop the OLD process and then let the
//     replacement spawn into a pod nothing will ever tear down again — the same
//     orphan this predicate exists to prevent. RestartContainer re-evaluates this
//     predicate after the swap (and clearRestarting after a failed one), so the
//     deferred teardown is never merely skipped.
//
// The CrashLoopBackOff surface is preserved by RestartContainer, not by
// withholding the teardown: a re-exec de-escalates the pod back to Running and
// re-arms the memory sampler, so a resurrected main never runs unenforced.
//
// RESIDUAL, documented: sidecars stopped by a terminal transition are NOT
// resurrected by a later re-exec. This applies to a restartPolicy:Always pod
// whose main exits 0 or crashes — runtimed cannot tell it apart from Never/
// OnFailure, because PodBox carries no POD-level restartPolicy (only the
// container-level KEP-753 field, meaningful on init containers). Closing it needs
// an apis field, which is out of scope here; the leak above is the strictly worse
// failure, and this is the delivered M10.2/B74 teardown behaviour unchanged.
func trulyTerminalLocked(p *pod) bool {
	switch p.phase {
	case runtimev1.PodPhase_POD_PHASE_SUCCEEDED, runtimev1.PodPhase_POD_PHASE_FAILED:
	default:
		return false
	}
	for _, cp := range p.containers {
		if cp.restarting {
			return false
		}
	}
	return true
}

// terminalTeardown is the irreversible teardown work claimed by a truly-terminal
// transition. It is assembled UNDER p.mu (claimTerminalTeardownLocked) and RUN
// outside it (runTerminalTeardown), because both halves block: the sampler cancel
// races the sampler's own onBreach callback, which takes p.mu, and the sidecar
// stop spans a whole grace window.
type terminalTeardown struct {
	cancel   context.CancelFunc
	sidecars []*containerProc
}

// claimTerminalTeardownLocked evaluates trulyTerminalLocked and, when it holds,
// CLAIMS the teardown: it hands back the memory-sampler cancel and — at most once
// per pod — the sidecars to stop. The once-only claim (p.sidecarTeardown, guarded
// by p.mu) means concurrent main exits initiate the sidecar stop exactly once, and
// DeletePod claims it up front so a delete-driven main exit defers to the delete's
// own two-phase stop. A non-terminal pod yields the zero value (a no-op).
// Caller holds p.mu.
func claimTerminalTeardownLocked(p *pod) terminalTeardown {
	if !trulyTerminalLocked(p) {
		return terminalTeardown{}
	}
	td := terminalTeardown{cancel: p.memCancel}
	if !p.sidecarTeardown {
		p.sidecarTeardown = true
		td.sidecars = sidecarsLocked(p)
	}
	return td
}

// runTerminalTeardown executes a claimed teardown with p.mu NOT held: it cancels
// the memory sampler (no root-SIGKILL-capable goroutine outlives the pod) and
// stops the claimed sidecars in reverse start order against one whole pod grace
// budget anchored now — the mains exited on their own, so they consumed none of it.
func (r *Runtime) runTerminalTeardown(ctx context.Context, p *pod, td terminalTeardown) {
	if td.cancel != nil {
		td.cancel()
	}
	if len(td.sidecars) > 0 {
		r.stopSidecars(ctx, p.box.GetPodId(), td.sidecars, time.Now().Add(graceDuration(0, p)))
	}
}

// recomputePhaseLocked updates the pod phase from its MAIN containers' states.
// Native sidecars are EXCLUDED from the terminal accounting (the mains-only rule
// of the apis restart_policy contract): when every main has terminated the pod
// goes Succeeded/Failed on the mains alone, even with sidecars still running (the
// Job-with-sidecar case), and a crashed/exited sidecar never concludes the pod by
// itself. Caller holds p.mu.
//
// The phase is a pure FUNCTION of the current main-container states, NEVER a
// latch: it de-escalates back to Running as soon as a main is running again (see
// the default arm). Every consumer of p.phase may therefore read it as
// state-derived — trulyTerminalLocked depends on it, and specifically on the fact
// that a MAIN mid-restart holds the phase at Running.
func (r *Runtime) recomputePhaseLocked(p *pod) {
	mains := 0
	allTerminated := true
	anyFailed := false
	for _, cp := range p.containers {
		if cp.sidecar() {
			continue
		}
		mains++
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
	if mains == 0 {
		return
	}
	switch {
	case allTerminated && anyFailed:
		p.phase = runtimev1.PodPhase_POD_PHASE_FAILED
	case allTerminated:
		p.phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	default:
		// DE-ESCALATION (B26). At least one main is live again — it never
		// terminated, or RestartContainer swapped in a running replacement, or a
		// main is mid-restart (skipped above). Falling back to Running is
		// REQUIRED, not cosmetic: without this arm the terminal phase is a
		// one-way latch, so a restartPolicy:Always pod that crashes once and
		// then successfully re-execs reports phase:Failed forever. Upstream
		// reads that as a dead pod — the ReplicaSet deletes and replaces it,
		// podgc reaps it, and a Job counts it against backoffLimit — which is
		// exactly the CrashLoopBackOff surface B26 exists to make honest.
		p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
	}
}

// gateSignature enforces the SignaturePolicy in the correct order relative to the
// ad-hoc-sign step (M2.6-d2), fail-closed, BEFORE exec:
//
//   - hostBinary (native pod / host-path convention): NEVER ad-hoc sign. A host
//     binary is an already-signed system or operator binary at a read-only host
//     path — `codesign -s - -f /bin/sh` fails ("internal error in Code Signing
//     subsystem": a SIP-protected Apple platform binary cannot be re-signed) and
//     would strip a real authority on any notarized one. Only CHECK the existing
//     signature (ADHOC_OK accepts an Apple-signed /bin/sh and an ad-hoc-signed
//     host helper alike), so the binary execs unmodified.
//   - ADHOC_OK (pulled image): ad-hoc signing is the point (an unsigned arm64
//     Mach-O in the writable pod rootfs is signed so it execs under AMFI with a
//     later DYLD insert) — so SIGN, then Check confirms the signature took.
//   - REQUIRE_SIGNED / REQUIRE_NOTARIZED: enforce the policy on the AS-PULLED
//     binary and NEVER ad-hoc sign it — `codesign -s - -f` would strip an existing
//     notarization / replace a real authority with an ad-hoc signature, silently
//     downgrading the binary past the policy. A failing image is rejected here.
//   - UNSPECIFIED / unknown: Check fails closed (ErrPolicyUnspecified); no signing.
//
// Both Sign and Check errors are returned wrapped (ErrSignatureRejected /
// ErrPolicyUnspecified), which the caller maps to SIGNATURE_REJECTED.
func (r *Runtime) gateSignature(ctx context.Context, policy runtimev1.SignaturePolicy, path string, hostBinary bool) error {
	if hostBinary {
		// Already signed + read-only: verify the existing signature, never re-sign.
		return r.signer.Check(ctx, policy, path)
	}
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

// NativeImage is the k3sm HostProcess sentinel image reference (DESIGN §M0;
// examples/hello-native.yaml). A container whose image is "native" runs its
// command[0] as an absolute HOST binary in place — no registry pull, no rootfs
// materialization — which is how every M2 conformance pod (and hello-native.yaml)
// executes. It is the with-command analog of the empty-command host-binary
// convention below (there the image itself is the path; here command[0] is).
const NativeImage = "native"

// resolveBinary determines the pod binary path + argv for a container. M1
// convention (mirrors the proto): if command+args are empty the image reference
// is the host binary path; if the image is the "native" sentinel the command runs
// in place as a host binary; otherwise the image is pulled+materialized and argv =
// command+args. The returned path is the on-disk executable to confine.
//
// hostBinary reports whether the resolved binary is a HOST binary (the native
// sentinel or the empty-command host-path convention) rather than a pulled-image
// payload. A host binary is already validly signed and lives at a read-only host
// path, so it must NEVER be ad-hoc re-signed (see gateSignature) — only a pulled,
// possibly-unsigned image payload in the writable pod rootfs is ad-hoc signed.
// p supplies BOTH the PodBox (for the imagePullSecret lookup) and the RESOLVED
// sandbox backend the pull's image-platform policy is derived from — see
// pullPolicy and the pod.backend field.
func (r *Runtime) resolveBinary(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container) (path string, argv []string, hostBinary bool, err error) {
	cmd := c.GetCommand()

	// Native HostProcess sentinel: run command[0] as an absolute host binary with
	// no pull. Checked BEFORE the pull path — a "native" pod carries a command, so
	// it would otherwise fall through and fail trying to fetch docker.io/library/native.
	if c.GetImage() == NativeImage {
		if len(cmd) == 0 {
			return "", nil, false, fmt.Errorf("container %s: image %q requires a command (the host binary to run)", c.GetName(), NativeImage)
		}
		bin := cmd[0]
		if !filepath.IsAbs(bin) {
			return "", nil, false, fmt.Errorf("container %s: native command %q must be an absolute host path", c.GetName(), bin)
		}
		return bin, append(append([]string{}, cmd...), c.GetArgs()...), true, nil
	}

	if len(cmd) == 0 && len(c.GetArgs()) == 0 {
		// Host-binary convention: image is an absolute path run in place.
		bin := c.GetImage()
		if !filepath.IsAbs(bin) {
			return "", nil, false, fmt.Errorf("container %s: image %q is not an absolute host path and no command given", c.GetName(), bin)
		}
		return bin, []string{bin}, true, nil
	}

	// Resolve the imagePullSecret credential (M2.6) via the consumer-side seam. It
	// is passed ONLY to the pull client below and is NEVER written to the pod dir.
	cred, err := r.pullCredential(ctx, p.box, c.GetImage())
	if err != nil {
		return "", nil, false, err
	}

	// Pull + materialize the image into the pod rootfs, then run command/args.
	if _, err := r.puller.Pull(ctx, c.GetImage(), cred, pullPolicy(p.backend)); err != nil {
		return "", nil, false, fmt.Errorf("pull image %q: %w", c.GetImage(), err)
	}
	// M1 materialization placeholder: the cache holds the blobs; a layer-applying
	// materializer lands with the rootfs format. For now argv[0] is command[0]
	// resolved against the rootfs if relative, else as-is.
	bin := cmd[0]
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(rootfs, bin)
	}
	argv = append(append([]string{}, cmd...), c.GetArgs()...)
	argv[0] = bin
	return bin, argv, false, nil
}

// pullPolicy is the image-platform policy for a pull, built from the pod's
// RESOLVED sandbox backend (pod.backend, recorded by createPod) — which is
// exactly what image.PlatformPolicy.Backend is documented to carry. The resolved
// value is threaded rather than restated as a constant so the contract and the
// call site cannot drift: a future native rung whose image-platform class
// differed would be refused by image.Candidates instead of silently mis-selected
// through a valid enum value.
//
// backend is always a NATIVE rung here — the host-process (Mach-O) spine is the
// only spine that pulls today (B99). createPod routes a resolved vm backend to
// createVMPod BEFORE resolveBinary is reached, and createVMPod pulls nothing
// yet; when the vm path grows a pull (the OCI -> Linux-rootfs builder, a later
// deliverable) it passes its own resolved backend through this same seam.
//
// HostRosetta is false: the host-Rosetta capability probe is B103. Until it
// lands, a darwin/amd64-only image is REFUSED at pull with a legible
// image.ErrNoPlatformMatch instead of being silently mis-selected.
func pullPolicy(backend runtimev1.SandboxBackend) image.PlatformPolicy {
	return image.PlatformPolicy{Backend: backend}
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

// pathShimRootfsEnv / pathShimMountsEnv are the env the path-rebase shim reads
// (shim/pathrebase_shim.c): the pod data volume the mounts are rebased under, and
// the ':'-joined absolute mount prefixes to rebase.
const (
	pathShimRootfsEnv = "K3SM_ROOTFS"
	pathShimMountsEnv = "K3SM_MOUNT_PATHS"
)

// containerEnv builds the child environment: the container's EnvVars plus the DYLD
// inserts that make cluster features work in-pod — the path-rebase shim (so an
// absolute volume mount resolves to its materialized copy under the pod data
// volume, no chroot) and the DNS shim (box annotation). DYLD_INSERT_LIBRARIES is
// appended last so an explicit container env can override it (rare). A container
// that sets DYLD_INSERT_LIBRARIES itself opts out of both shims.
func (r *Runtime) containerEnv(box *runtimev1.PodBox, c *runtimev1.Container) []string {
	env := make([]string, 0, len(c.GetEnv())+3)
	for _, e := range c.GetEnv() {
		env = append(env, e.GetName()+"="+e.GetValue())
		if e.GetName() == dyldInsertEnv {
			return env // explicit container DYLD wins; do not inject shims
		}
	}

	var inserts []string
	// Path-rebase shim: only when the shim is configured AND this container mounts
	// a volume (nothing to rebase otherwise). K3SM_ROOTFS/K3SM_MOUNT_PATHS configure
	// it; a workload NOT loading the shim (a SIP platform binary) just ignores them.
	if paths := containerMountPaths(c); r.cfg.PathShimPath != "" && len(paths) > 0 {
		inserts = append(inserts, r.cfg.PathShimPath)
		env = append(env,
			pathShimRootfsEnv+"="+r.rootfsPath(box),
			pathShimMountsEnv+"="+strings.Join(paths, ":"))
	}
	if ins := box.GetAnnotations()[dyldInsertAnnotation]; ins != "" {
		inserts = append(inserts, ins)
	}
	if len(inserts) > 0 {
		env = append(env, dyldInsertEnv+"="+strings.Join(inserts, ":"))
	}
	return env
}

// containerMountPaths returns c's absolute volume-mount container paths (the
// prefixes the path-rebase shim rewrites under the pod data volume).
func containerMountPaths(c *runtimev1.Container) []string {
	var paths []string
	for _, vm := range c.GetVolumeMounts() {
		if p := vm.GetMountPath(); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
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
