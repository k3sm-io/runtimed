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
	"errors"
	"fmt"
	"log/slog"
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

	"google.golang.org/protobuf/proto"

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

	// backend is the sandbox backend sandbox.SelectBackend resolved for this pod,
	// not the one the PodBox requested. Recorded once by createPod; read on every
	// (re-)spawn including RestartContainer, which re-enters startContainer long
	// after CreatePod returned — hence it lives on the pod, not as a parameter.
	// image.PlatformPolicy.Backend derives from it, so a pull always runs under
	// the rung the pod is actually confined by. Immutable after createPod; a
	// zero value fails closed at the next pull (UNSPECIFIED has no platform
	// candidates).
	backend runtimev1.SandboxBackend

	mu         sync.Mutex
	phase      runtimev1.PodPhase
	reason     string
	message    string
	podIP      string
	containers []*containerProc

	// Memory metering/OOM state. oomKilled is set by the sampler before it
	// SIGKILLs the pod, so watchContainerExit records the OOMKilled reason.
	// memSampler/memCancel are nil only if arming was refused (an unregistered
	// pod); every pod is metered, and the sampler enforces an OOM threshold only
	// when the pod carries a memory limit — see armMemorySampler.
	oomKilled  bool
	memSampler *supervisor.MemorySampler
	memCancel  context.CancelFunc

	// vm-pod metering state, guarded by mu. A vm pod is metered
	// from the guest — memSampler/memCancel above are always nil for one
	// (armMemorySampler refuses a vm pod).
	//
	// guestStats is the outcome of the last on-demand guest-agent Stats call,
	// rendered as the GuestStatsConditionType pod condition so an omitted sample
	// is a stated fact rather than silence.
	guestStats guestStatsRecord
	// guestContainers holds the per-container statuses folded from the agent's
	// ContainerEvents stream — the only source of a vm pod's OOMKilled — keyed by
	// container name, with guestContainerOrder preserving first-sight order so
	// the reported list is stable. A vm pod's containers are guest processes, so
	// they have no containerProc and cannot ride the p.containers list.
	guestContainers     map[string]*runtimev1.ContainerStatus
	guestContainerOrder []string

	// cpuAcc carries each container's cumulative CPU across restarts so the value
	// ListPodStats reports is monotone for the pod's whole life: a restarted
	// container is a new pid whose raw counter starts over, and the metrics
	// consumer rejects a counter that goes backwards (cpuAccumulator). It has its
	// own lock, not p.mu — it is written from the stats read path, which must not
	// contend with the pod lifecycle.
	cpuAcc cpuAccumulator

	// supCtx / cancel are the pod-lifetime supervision context and its cancel —
	// the scope of the per-container reapers (supervisor.Process.reap), the
	// watchContainerExit drain-wait, and the memory sampler. Derived from
	// context.Background(), not the CreatePod request ctx (canceled when the
	// unary RPC returns under the daemon split); fired on pod teardown
	// (DeletePod).
	//
	// Storing this context is a deliberate, narrow exception to "never store a
	// Context in a struct" (docs/GO-STANDARDS.md §Context) — the same reason
	// net/http.Server keeps a BaseContext: the field is the object's own
	// lifetime, not a request scope, and goroutines started long after
	// CreatePod returns (RestartContainer re-arming the memory sampler) must be
	// rooted at it. Without that, a re-armed sampler rooted at
	// context.Background() could not be stopped by p.cancel, leaving a root
	// daemon goroutine able to SIGKILL a process group forever. Never pass
	// supCtx to a request-scoped call; it outlives every RPC.
	supCtx context.Context
	cancel context.CancelFunc

	// sidecarTeardown marks the terminal sidecar teardown as claimed (guarded by
	// mu): the first main-container exit that concludes the pod stops the native
	// sidecars exactly once, even when several mains terminate concurrently (see
	// claimTerminalTeardownLocked / stopSidecars). It is a one-shot latch, so it
	// cannot cover a sidecar spawned after the claim — RestartContainer re-claims
	// the live sidecars of a still-terminal pod for exactly that reason.
	sidecarTeardown bool

	// vm-pod live transport address state, guarded by mu. Both are zero for
	// every host-process pod: a Seatbelt-confined pod has no guest, so nothing
	// arms the watcher for one (armGuestLeaseWatcher, guestlease.go).
	//
	// guestLease is the address the guest agent last reported and this host
	// accepted, in canonical form — PodStatus.guest_transport_address. It is
	// non-empty IFF the most recent poll returned a valid lease; see
	// watchGuestLease for why a failed poll clears it rather than leaving a
	// stale address standing.
	guestLease string
	// guestLeaseStopped is closed when the pod's lease-watcher goroutine
	// returns. It doubles as the arm latch (non-nil ⇒ armed), so the pod can
	// never carry two watchers, and it is the observable edge that the watcher
	// really stopped when the pod-lifetime context was cancelled.
	guestLeaseStopped chan struct{}

	// The guest agent's advertised capability set, recorded by the same Health
	// poll that reads the lease (guestlease.go) and guarded by mu.
	//
	// TWO FIELDS, because there are THREE states and they are not
	// interchangeable. guestCapsObserved false means no Health response has
	// been read yet — the pod may have just been created, or the agent may be
	// unreachable — and a request is let through on that, because refusing a
	// verb on the strength of never having asked would break every exec issued
	// before the first poll landed. guestCapsObserved true with the token
	// ABSENT is a positive statement by a guest that answered: it named its
	// capabilities and this was not among them, so the request is refused with
	// a legible reason instead of a bare Unimplemented from the far end.
	//
	// guestCaps holds only tokens this daemon KNOWS (knownGuestCapability), so
	// nothing guest-chosen is ever retained here — the map is bounded by the
	// host's own vocabulary rather than by what the agent chose to send.
	guestCapsObserved bool
	guestCaps         map[string]struct{}
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

// liveContainersLocked returns the pod's containers that have not terminated.
//
// The filter is load-bearing: supervisor.Process.PID() keeps returning the last
// pid after the reaper collects the process, so an unfiltered walk hands a dead
// pid to containerPIDs (the memory sampler's PID set) and, worse, to oomKill,
// which SIGKILLs the whole process group as root. Darwin recycles pids/pgids, so
// a stale entry aims an uncatchable root signal at whatever now owns that group.
// This is the defense-in-depth half of that; the other half is the
// truly-terminal teardown that stops the sampler at all (trulyTerminalLocked).
// Caller holds p.mu.
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
	// being terminated and replaced, so recomputePhaseLocked must not treat its
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
	// env and workingDir are the RESOLVED launch environment and working
	// directory this container was spawned with (resolvedBinary, plus
	// startContainer's pod-data-volume default for an unset working directory).
	// They are retained rather than re-derived because an Exec session must
	// enter the same environment the container runs in — for a pulled image that
	// includes the image config's own $PATH, which the container spec alone does
	// not carry, and re-deriving it in Exec would mean a second pull.
	env        []string
	workingDir string
}

// sidecar reports whether cp is a native sidecar (KEP-753): an init-declared
// container with restart_policy always. A sidecar is long-lived — spawned in its
// init-list position but not waited to completion — excluded from the mains-only
// terminal phase accounting (recomputePhaseLocked), reported under
// init_container_statuses, and stopped in reverse start order after the mains
// (stopSidecars). Per the apis restart_policy contract the field is meaningful
// only on an init container, so a main container carrying always is not a sidecar.
func (cp *containerProc) sidecar() bool {
	return cp.initDeclared &&
		cp.spec.GetRestartPolicy() == runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS
}

// createPod is the CreatePod spine (called with no lock held). It materializes
// each container rootfs, ad-hoc signs, gates the signature policy before exec,
// generates+validates the SBPL, and spawns each container through the exec-shim
// backend with DYLD_INSERT_LIBRARIES carried through. It returns the started pod
// or a typed failure.
//
// The pod's guest network config is not a parameter: it is derived on the vm
// route alone, from the optional GuestNetworker seam a Deps.Network may implement
// (see guestNetworkConfig). A caller-supplied value alongside that derivation
// would be a second authority for one field with no stated precedence, and the
// host-process spine has no use for it in any case — a host process binds a /32
// lo0 alias via r.network.Setup and never reads a guest config.
func (r *Runtime) createPod(ctx context.Context, box *runtimev1.PodBox) (_ *pod, _ runtimev1.FailureReason, retErr error) {
	sp := box.GetSandboxProfile()
	if sp == nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("pod %s: sandbox_profile is required", box.GetPodId())
	}

	// Fail-closed backend selection: honor the backend the provider
	// stamped on the SandboxProfile. UNSPECIFIED — the host-process default —
	// walks the host-OS-gated Seatbelt ladder (not-root drops the uidjail rung;
	// an unavailable Seatbelt degrades only to the stronger vm rung, else
	// refuses — never runs unconfined). A pod that requested the vm backend
	// (Linux image / untrusted tenancy) on a host without
	// Virtualization.framework + the entitlement is refused here, never silently
	// downgraded to the weaker Seatbelt rung.
	selected, err := sandbox.SelectBackend(sp.GetBackend(), os.Geteuid() == 0, r.backend.Available(), r.vmBackend.Available())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("select sandbox backend for pod %s: %w", box.GetPodId(), err)
	}

	// Route the vm rung away from the host-process (Mach-O) spine: a Linux guest
	// has no host binary to resolve, ad-hoc codesign, signature-gate, SBPL-confine,
	// or attach to lo0. The guest network config is resolved only beyond this
	// branch, inside createVMPod; the host-process path below is reached only for
	// the Seatbelt rungs.
	if selected == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return r.createVMPod(ctx, box, sp)
	}

	ip, err := r.network.Setup(ctx, box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			fmt.Errorf("network setup pod %s: %w", box.GetPodId(), err)
	}
	// Unwind the successful Setup if a later create step fails: without this a
	// failed create leaks the pod's /32 (real IPAM allocates one per Setup and
	// DeletePod never runs for a pod that was never created). Best-effort
	// log-and-continue, mirroring the delete-path Teardown.
	defer func() {
		if retErr != nil {
			if terr := r.network.Teardown(box.GetPodId()); terr != nil {
				r.log.Warn("network teardown after failed create", "pod", box.GetPodId(), "err", terr)
			}
		}
	}()

	rootfs, err := r.rootfsPath(box)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("create rootfs %s: %w", rootfs, err)
	}
	// The pod's temp directory, before anything can need it. See
	// provisionPodTmpDir for why a pod has none otherwise.
	if err := provisionPodTmpDir(rootfs); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP, err
	}
	// Give the pod dir its reachability record the moment the dir exists, even
	// for a pod that will never pull (a native host-binary pod). The image GC
	// reads an absent record as "this pod's references are unknown" and refuses
	// to reclaim anything at all (image.ErrRootsIncomplete) — an outage of the GC
	// rather than a risk to the pod, but still an outage, so creating the record
	// here keeps absence a genuine anomaly.
	if err := r.recordPodReferences(box.GetPodId()); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP, err
	}

	// Materialize volume sources (configMap / secret / emptyDir / downwardAPI /
	// projected) into the pod data volume. Secrets + the projected
	// SA-token come back as credential paths that get the SBPL read-only
	// sub-scope below. PVC sources are skipped here and bound by the
	// volume.Binder below — they are durable, lifecycle-decoupled, and live
	// outside the pod data volume.
	var credPaths []string
	if len(box.GetVolumes()) > 0 {
		layout, merr := mount.Materialize(ctx, box, rootfs, ip, r.resolver)
		if merr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("materialize volumes for pod %s: %w", box.GetPodId(), merr)
		}
		credPaths = layout.CredentialPaths()
	}

	// Bind APFS-backed persistent volumes (PVCs): ensure each claim's
	// stable dir on the storage root (empty-create / seed-once), symlink it into
	// the pod rootfs, and collect its dir as the SBPL read/write scope. The dir
	// lives outside the pod tree, so DeletePod's removePodDir never touches it
	// (ReclaimPolicy Retain).
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

	// The data volume the profile is about to re-allow read+write must be one this
	// runtime derived for this pod. Checked here, immediately before the
	// only call that consumes it: sandbox.Generate emits it after the protected
	// denies, where last-match-wins makes an unchecked value beat every one of
	// them, and uses it as the carve-out base for every other caller-supplied
	// path. validatePodBox asks the same question earlier for the CreatePod
	// ingress; a caller that reached this spine another way is refused here.
	if _, err := r.dataVolumePath(box); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	// Having accepted either derived spelling, emit the narrower one: the accept
	// set is a compatibility surface (the producer sends the pod dir), but nothing
	// a Seatbelt pod needs lives above <podDir>/rootfs — materialization, PV
	// binds, the resolved binary and the fsGroup walk are all rootfs-scoped.
	// Narrowing here closes "a future artifact under <podDir> becomes
	// pod-writable silently" with no cross-repo change. sp is the caller's
	// message, so copy before mutating it.
	sp = proto.Clone(sp).(*runtimev1.SandboxProfile)
	sp.DataVolumePath = rootfs

	// Generate the SBPL after materialization + PV binding so the credential mounts
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
			// The VIPs are plumbing-only (DNS env/status): they render
			// no SBPL rule — per-IP network filters do not compile on macOS 26
			// (sandbox.Generate's AllowNetwork stanza).
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
	// root-side, before any container's privilege drop (a uid-dropped, sandboxed
	// process can no longer chown). The supervisor runs this synchronously here,
	// strictly before posix_spawn → the exec-shim drop.
	//
	// The walk's bound is this pod's own dir, not the shared pods root: rootfs is
	// already the validated derivation (rootfsPath), so this is defence at the
	// sink — the recursive group-rwx + setgid grant refuses any root outside that
	// dir regardless of how the caller obtained it, the same shape
	// removePodDir puts on its RemoveAll. A pods-root bound would be one level too
	// wide to be a real second layer — <PodsRoot>/<victim-id>/rootfs is strictly
	// under it, so it would wave through the cross-pod case that is hazard #1 for
	// the primary guard, and the two layers would fail together.
	podDir, err := r.podDir(box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	if fsGroup := int(box.GetPodSecurityContext().GetFsGroup()); fsGroup > 0 {
		if err := supervisor.ChownForFSGroup(podDir, rootfs, fsGroup); err != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("fsGroup chown for pod %s: %w", box.GetPodId(), err)
		}
	}

	// Pod-lifetime supervision context. The per-container reaper and the
	// watchContainerExit drain-wait must outlive the CreatePod RPC: under the
	// daemon split the request ctx is canceled when the unary handler returns,
	// which would otherwise make the kqueue reaper record a bogus
	// context-canceled exit and the drain-wait snapshot an empty tail the instant
	// CreatePod replies. Derive a fresh cancelable ctx from Background instead —
	// the same pattern the memory sampler uses — stored on the pod and
	// fired on teardown. On a failed create (a later container won't start),
	// unwind the supervision already launched instead of leaking it.
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
	// contract) runs to completion before the next init step, as it always has.
	// An init container with restart_policy always is a native sidecar (KEP-753,
	// KEP-753): spawned in its init-list position through the same startContainer
	// machinery (same confinement class + rootfs resolution) but not waited — the
	// sequence proceeds once it is started (spawn-equals-started; startup-probe
	// gating of progression is out of scope per the apis restart_policy
	// contract). A sidecar joins p.containers so the status stream and
	// RestartContainer find it by name; it is excluded from the mains-only phase
	// accounting (recomputePhaseLocked) and torn down in reverse start order
	// after the mains (stopSidecars). runtimed performs no exit-driven sidecar
	// restarts — the provider is the single restart authority via
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

	// The memory sampler is armed by the caller (CreatePod), strictly after
	// the pod is registered in r.pods. armMemorySampler refuses to arm an
	// unregistered pod (its anti-stranding guard), so arming here — before
	// registration — would silently leave every limited pod unenforced.

	return p, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// armMemorySampler starts the pod's resource sampler: it samples
// ri_phys_footprint at ~1 Hz and, for a pod that carries a memory limit, SIGKILLs
// the pod and records OOMKilled on the first breach. The sampler's lifetime is
// the pod — cancelled on DeletePod and on any truly-terminal transition,
// Succeeded or Failed (trulyTerminalLocked) — so the goroutine never leaks.
//
// Every pod is sampled, limit or none: the limit selects OOM enforcement only
// (supervisor.NewMemorySampler with limitBytes == 0 is meter-only and never
// fires onBreach). An unlimited pod with no sampler would be silently absent
// from PodMetrics/ListPodStats/`kubectl top pod` — worse than reporting a pod
// with no limit, since a memory limit is optional and commonly unset. The cost
// is one goroutine and one proc_pid_rusage per container per second per pod,
// which is what a kubelet does.
//
// Called by CreatePod (after the pod is registered) and again by
// RestartContainer when a re-exec de-escalates a pod out of a terminal phase —
// that terminal transition already cancelled the sampler, and the replacement
// main must never run without the OOM enforcement its limit promises. Any
// predecessor sampler is cancelled here, so exactly one sampler ever enforces
// the limit. Call with p.mu not held — the cancel is issued outside the lock
// (the sampler's onBreach callback takes p.mu), per the callbacks-outside-locks
// discipline.
//
// Anti-stranding. A sampler is a root-daemon goroutine whose breach path
// SIGKILLs a process group, so it must never outlive its pod. Two independent
// stoppers close that, in the r.mu → p.mu lock order the whole package uses:
//
//  1. It refuses to arm a pod that is no longer registered in r.pods. DeletePod
//     removes the pod under r.mu before it cancels, so an arm that loses that
//     race is dropped rather than stranded on a deleted pod. (RestartContainer
//     resolves *pod up front and then blocks in GracefulStop for the whole grace
//     window before reaching here, so the losing interleaving is reachable.)
//  2. The sampler ctx is rooted at the pod-lifetime p.supCtx, not
//     context.Background(); if the delete instead lands just after the check
//     above, p.cancel (DeletePod) tears this sampler down too. The two stoppers
//     are order-independent: whichever side wins, the goroutine dies.
func (r *Runtime) armMemorySampler(p *pod) {
	// A vm pod is never host-sampled. Its working set lives in the
	// guest's cgroup2 hierarchy (pulled on demand by vmPodStats — a host sample
	// would meter the vmhost helper, not the workload), and its memory ceiling
	// is the VZ memorySize the hypervisor itself enforces; an OOM arrives as a
	// guest ContainerEvent, not as something the host could observe in time.
	// This refusal also makes the kill-reason fork total: no sampler means no
	// onBreach means no path by which a host figure could reach oomKill for a
	// vm pod (which refuses one anyway, defence in depth).
	if p.isVM() {
		r.log.Debug("vm pod: no host memory sampler (guest-agent metering; VZ memorySize is the ceiling)",
			"pod", p.box.GetPodId())
		return
	}
	// limit == 0 means unlimited: still metered, never OOM-enforced.
	limit := podMemoryLimitBytes(p.box)
	r.mu.Lock()
	registered := r.pods[p.box.GetPodId()] == p
	r.mu.Unlock()
	if !registered {
		// Deleted (or replaced) while we were getting here: arming now would
		// strand a root SIGKILL-capable goroutine on a pod nothing will cancel.
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

// createVMPod is the vm-backend routing target. The vm path is deliberately
// separate from the host-process spine (createPod above): it does not
// resolveBinary, ad-hoc codesign / gateSignature, generate+apply an SBPL
// profile, or set up lo0 networking — a Linux guest runs none of those. It
// hands the pod's sizing (vm_vcpus / vm_memory_bytes) + rootfs + the virtiofs
// volume share plan (computed below) + its resolved containers to the vm
// backend's CreateVM.
//
// It DOES materialize, on both halves, and must — a guest reads its whole world
// out of host directories that have to be populated before it boots:
//
//   - the pooled proj/vols share roots and their per-volume content, by
//     mount.MaterializeShares (the share plan itself is pure data). Essentially
//     every pod binds an automounted ServiceAccount token out of the proj share,
//     and a bind of a host directory that does not exist is an ENOENT that kills
//     guest init;
//   - the pod's image layers into the rootfs share, by the unpacker seam inside
//     resolveVMContainers. An empty rootfs share boots a guest with no /bin/sh,
//     whose container exits instantly;
//   - each PVC's stable dir on the storage root, by volume.Binder.Provision. VZ
//     stats every share root when it builds the machine, so a planned PVC share
//     whose dir was never created refuses the whole VM.
//
// It does pull: the guest runs no merge and reads no image config, so the
// image's Entrypoint/Cmd/Env/WorkingDir/User have to be merged with the pod
// spec here, and holding a verified config means having pulled it. What the
// host-process spine does with a pulled image afterwards — resolve argv[0]
// against a host rootfs, sign it, gate it — none of that happens here. See resolveVMContainers.
//
// VMSpec.Network is resolved here, at the one boundary that consumes it,
// through the optional GuestNetworker seam (guestNetworkConfig): the guest's
// DNS configuration plus the NAT advisory fields the vm backend applies. This
// path runs no IPAM, no supervisor.PodNetwork.Setup, and binds no lo0 alias — a
// NAT-attached guest is reached over the VZNATNetworkDeviceAttachment. The
// config is plain data because runtimed cannot import darwin-net (see
// sandbox.GuestNetworkConfig); the k3sm provider is the producer/mapper. With
// no producer wired the value is the inert zero value and the miss is logged,
// never passed on silently.
//
// The VM is live by the time this returns: CreateVM writes the machine
// description, spawns the k3sm-vmhost helper and waits for the guest agent to
// answer a Health RPC, so a nil error means a booted guest. On a non-entitled
// host SelectBackend already failed the pod closed (vmBackend.Available() ==
// false) before this path was reached.
//
// The pod this assembles has no containerProc — its containers are guest
// processes, so their statuses arrive over the agent's ContainerEvents stream
// (watchGuestContainerEvents) and its metering is on-demand from the agent
// (vmPodStats). Two host-side supervision goroutines are rooted at the
// pod-lifetime supCtx: that event fold, and the helper exit watch, which keeps
// a post-boot hypervisor crash from leaving the pod at Running forever.
func (r *Runtime) createVMPod(ctx context.Context, box *runtimev1.PodBox, sp *runtimev1.SandboxProfile) (*pod, runtimev1.FailureReason, error) {
	// The pod's resolved sandbox backend, named once. createPod reaches this
	// function only when sandbox.SelectBackend returned the vm rung, so naming
	// it here keeps the image-platform policy of the pulls below and the
	// backend recorded on the assembled pod reading from one value.
	const vmPodBackend = runtimev1.SandboxBackend_SANDBOX_BACKEND_VM

	// fsGroup is refused before anything is derived or created, because it is a
	// property of the box alone and the answer cannot change later. See
	// errVMFsGroupUnsupported for why refusing beats the two alternatives.
	//
	// ANY non-zero value, not just a positive one. fs_group is pod-scoped in the
	// proto (runtime.proto is explicit that there is no container-level field), so
	// "requests fsGroup" has exactly one reading and no ambiguity to resolve; the
	// != 0 test is nonetheless the conservative one, since the host-process spine
	// acts only on > 0 and a negative value is a malformed request this path
	// should not quietly pass over either.
	if fsGroup := box.GetPodSecurityContext().GetFsGroup(); fsGroup != 0 {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: pod %s: %w", errInvalidPodBox, box.GetPodId(), errVMFsGroupUnsupported)
	}

	// Compute the virtiofs share-device plan from the box's volumes —
	// pure data: no filesystem access and no chown (the planner plans; the VZ
	// device config enforces writability, guest-init composes the binds —
	// guest-init composes the binds). The pod dir is derived locally (r.podDir), and the planner ignores
	// box.rootfs_path for share roots; rootfsPath below derives the host-side
	// VMSpec.RootfsPath the same way, accepting a caller-supplied rootfs_path
	// only when it is byte-equal to that derivation.
	//
	// A planner reject maps to INVALID_POD_BOX via the errInvalidPodBox house
	// pattern (validate.go): the plan is computed before this path touches
	// disk, so a reject means the box itself is unplannable. Rendering that
	// plan onto disk comes later (mount.MaterializeShares below) and folds into
	// ROOTFS_SETUP, exactly as the native spine folds mount.Materialize.
	podDir, err := r.podDir(box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	vmRootfs, err := r.rootfsPath(box)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	plan, err := mount.ComputeSharePlan(box, podDir, r.cfg.Root, r.binder.Class())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: vm volume share plan for pod %s: %w", errInvalidPodBox, box.GetPodId(), err)
	}
	// The agent socket is derived here, by the same function the daemon's own
	// GuestDialer uses, and stamped onto the spec — so the socket the helper
	// binds and the socket Exec/GetLogs dial are one string by construction. It
	// lives outside the pod dir; see guestAgentSocket for why that is a layout
	// property.
	agentSocket, err := guestAgentSocket(r.cfg.Root, box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	// The pod dir must exist before anything writes into it. The vm path creates
	// it here rather than sharing the host-process spine's MkdirAll (that spine
	// also provisions a tmp dir, an image reachability record and a rootfs the
	// guest composes for itself), and before the pulls below, whose reachability
	// record would otherwise create it first at its own, wider mode.
	if err := os.MkdirAll(podDir, 0o750); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("create pod dir %s: %w", podDir, err)
	}
	// The pod dir's reachability record, at the same point in the sequence the
	// host-process spine writes it: the moment the dir exists, and BEFORE any
	// pull. The vm spine only ever called recordPodImage, which runs after a
	// successful pull, so a vm pod whose first pull failed left a pod dir with no
	// record at all — and the image GC reads an ABSENT record as "this pod's
	// references are unknown" and refuses to reclaim anything node-wide
	// (image.ErrRootsIncomplete). One failed pull was a node-wide GC outage.
	//
	// Writing it here makes absence a genuine anomaly rather than an ordinary
	// consequence of a bad image reference, which is the property the GC's
	// fail-closed reading depends on to be useful.
	if err := r.recordPodReferences(box.GetPodId()); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP, err
	}
	// Resolved once, and used three times: the guest's DNS/NAT configuration on
	// the spec below, the status.podIP a downward-API projection resolves to, and
	// the pod's PUBLISHED IDENTITY on the assembled pod.
	//
	// The two halves of this config have different failure policies, and the
	// split is the point. The DNS and NAT-advisory half DEGRADES: a producer that
	// is not wired, or that has no config for this pod, is logged and the guest
	// boots without a resolver (guestNetworkConfig documents that, and it is
	// survivable — a pod that cannot resolve names is still a pod). The IDENTITY
	// half does NOT. pod_ip is the podCIDR /32 that reaches EndpointSlice, DNS and
	// the downward API (runtime.proto), the vm spine runs no IPAM of its own, and
	// this seam is its ONLY source — so an absent PodIP is not a degraded pod, it
	// is an unroutable one: a Service selecting it gets an EndpointSlice with no
	// addresses and traffic blackholes with nothing anywhere saying why.
	//
	// So it fails closed here, before the machine is built, with INTERNAL — the
	// same reason the host-process spine reports when its own network setup
	// fails, because it is the same condition: no address for the pod.
	netCfg := r.guestNetworkConfig(box.GetPodId())
	if !netCfg.PodIP.IsValid() {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			fmt.Errorf("no pod IP for vm pod %s: the GuestNetworker producer supplied none, "+
				"and a vm pod has no other source of a published identity", box.GetPodId())
	}
	podIP := netCfg.PodIP.String()
	// Render the plan onto disk: the pod-dir share roots, the projected-class
	// volumes' content under the proj share, and the emptyDir directories under
	// the vols share. The guest binds these host directories, so they must exist
	// and be populated BEFORE CreateVM boots it. PVC shares are skipped (the
	// binder owns their dirs), and a bind's subPath is applied guest-side.
	if err := mount.MaterializeShares(ctx, box, plan, podIP, r.resolver); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("materialize vm volume shares for pod %s: %w", box.GetPodId(), err)
	}
	// Provision each PVC's stable dir on the storage root. MaterializeShares
	// deliberately skips these — pkg/volume owns a claim's lifecycle — and until
	// this call nothing on the vm spine created them at all, so the share plan
	// rooted a k3sm.pvc<i> device at a path that did not exist and VZ refused the
	// share before the machine started ("stat …/storage/default/pgdata: no such
	// file or directory").
	//
	// Provision, not Bind: Bind additionally symlinks each claim into the pod
	// rootfs, which is how a Seatbelt-confined host process reaches it. A guest
	// reaches its claim through the share device instead, and that symlink would
	// land inside <podDir>/rootfs — the read-only image lower layer — pointing at
	// a host path with no meaning in the guest's namespace. See volume.Provision.
	//
	// Nothing here deletes or re-seeds: an existing claim dir is reused untouched
	// (ReclaimPolicy Retain), which is what makes a PVC durable across the pod
	// recreations a vm pod's failure path performs.
	if hasPersistentVolume(box) {
		if _, berr := r.binder.Provision(ctx, box); berr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("provision persistent volumes for pod %s: %w", box.GetPodId(), berr)
		}
	}
	// Every container is resolved host-side: the four-quadrant merge of
	// each container's pod spec against its image config, its expanded
	// environment, its numeric identity and the share-plan tag its rootfs lower
	// layer arrives under. The guest performs no merge and reads no image
	// config, which is what lets it boot with no cluster access — see
	// resolveVMContainers for what this pulls and the fail-closed refusals (a
	// host-binary image, a native sidecar, an unresolvable image USER, and a pod
	// whose containers name more than one image, which the single pod-wide
	// rootfs share cannot represent).
	//
	// vmRootfs is handed down because the same pass MATERIALIZES the pod's image
	// into it: the rootfs share the guest overlays is exported from that
	// directory, and until it holds the image's files the guest boots with an
	// empty root.
	containers, reason, err := r.resolveVMContainers(ctx, box, plan, vmPodBackend, vmRootfs)
	if err != nil {
		return nil, reason, err
	}
	spec := sandbox.VMSpec{
		PodID:       box.GetPodId(),
		Vcpus:       sp.GetVmVcpus(),
		MemoryBytes: sp.GetVmMemoryBytes(),
		RootfsPath:  vmRootfs,
		Network:     netCfg,
		Containers:  containers,
		Volumes:     vmVolumePlan(plan),
		PodDir:      podDir,
		// one grace budget for both ends of the shutdown: the helper is given
		// the pod's own termination grace, and DeletePod's escalation never
		// waits less than what the helper will honour. Two independently-clocked
		// timers across the process boundary is the power-cut bug.
		AgentSocketPath: agentSocket,
		StopGrace:       time.Duration(box.GetTerminationGracePeriodSeconds()) * time.Second,
	}
	if err := r.vmBackend.CreateVM(ctx, spec); err != nil {
		// Every sub-cause is SANDBOX_SETUP at the enum level — the runtime/v1
		// taxonomy has no finer bucket for "the guest did not come up" — the
		// error's own message names which one and where the console log is.
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("create vm for pod %s: %w", box.GetPodId(), err)
	}

	// The guest is up. Assemble the pod and start its two supervision goroutines.
	//
	// supCtx is rooted at context.Background(), not the CreatePod request ctx,
	// for the reason the host-process spine gives: the RPC's ctx is cancelled
	// when the unary call returns, and these goroutines live for the pod.
	supCtx, cancel := context.WithCancel(context.Background())
	p := &pod{
		box:     box,
		backend: vmPodBackend,
		// RUNNING at assembly, not PENDING, and the guest's own ordering is why:
		// it starts every container BEFORE it serves the agent (the agent's
		// Health is CreateVM's boot probe, so it must not answer before there is
		// a pod to answer about). CreateVM having returned therefore means the
		// containers are already running, and PENDING here would be a claim the
		// guest has already disproved — one the provider reads as authoritative
		// ("the pod has not started") and short-circuits on. From here the phase
		// is state-derived: the ContainerEvents fold re-derives it on every
		// transition (recomputeVMPhaseLocked), which is what carries the pod to
		// Succeeded/Failed when its containers finish.
		phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		// The PUBLISHED IDENTITY, which this spine never set: PodStatus.pod_ips
		// was empty for every vm pod, so status.podIP was empty, a Service
		// selecting one got an EndpointSlice with no addresses, and the pod was
		// unroutable. The value was already in hand — it is the same one the
		// downward-API projection above resolves — and simply never reached here.
		//
		// It is NOT the guest's DHCP lease, and the two must not converge.
		// p.guestLease carries that separately (the lease watcher fills it) and
		// surfaces as PodStatus.guest_transport_address, which runtime.proto
		// forbids publishing into EndpointSlice, DNS or status.podIP. One address
		// is who the pod IS, the other is where the host dials it.
		podIP:  podIP,
		supCtx: supCtx,
		cancel: cancel,
	}
	// No memory sampler, and no armMemorySampler call anywhere on this path. A vm
	// pod's memory ceiling is the hypervisor's VZ memorySize, and its OOM truth
	// is the guest cgroup's, reported over ContainerEvents; a host rusage sample
	// would measure the vmhost helper.
	go r.watchVMPodEvents(supCtx, p)
	go r.watchVMHelperExit(supCtx, p)
	return p, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// vmVolumePlan maps the pkg/mount share plan onto the sandbox DTO, value for
// value. This is the named mapper on this seam: sandbox must not import
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

// oomKill is the memory sampler's onBreach callback: it marks the pod
// OOMKilled and SIGKILLs every container's process group. The kqueue reaper then
// collects the exits and watchContainerExit records the OOMKilled termination
// reason. Called from the sampler goroutine; it takes p.mu only to snapshot state
// and signals outside the lock (the re-entrancy rule).
func (r *Runtime) oomKill(p *pod, footprint uint64) {
	// The kill-reason fork: a vm pod's OOMKilled comes from the guest
	// agent's ContainerEvents stream and nowhere else — the kill happens in the
	// guest kernel's cgroup, so a host rusage figure is not evidence of it, it
	// measures the vmhost helper. armMemorySampler already refuses to arm a vm
	// pod, so nothing should reach here; this is the second, independent
	// stopper, because the failure it prevents is silent and expensive
	// (upstream reads OOMKilled as the pod's own fault and counts it against a
	// Job's backoff) and the alternative kill path would SIGKILL host process
	// groups a vm pod does not own.
	if p.isVM() {
		r.log.Error("refusing a host-sampler OOM kill for a vm pod: guest OOM is observable only via the agent's ContainerEvents",
			"pod", p.box.GetPodId(), "footprint_bytes", footprint)
		return
	}
	p.mu.Lock()
	p.oomKilled = true
	// Only live containers are signalled: PID() still reports the last pid of a
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
// initDeclared), from which sidecar() derives the lifecycle class. It does not
// alter confinement: the SBPL profile is pod-scoped (p.profile) and the rootfs
// resolution is pod-scoped too (the caller passes r.rootfsPath), identical for
// init, sidecar, and main containers.
//
// ctx is the pod-lifetime supervision context (createPod's podCtx; restart
// passes a context.WithoutCancel), not the CreatePod request ctx. It scopes the
// spawn, the kqueue reaper, and the watchContainerExit drain-wait to the pod's
// lifetime so they survive the unary RPC's return under the daemon split.
func (r *Runtime) startContainer(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container, isInit bool) (*containerProc, runtimev1.FailureReason, error) {
	rb, err := r.resolveBinary(ctx, p, rootfs, c)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, err
	}

	// Enforce the signature policy in the correct order relative to ad-hoc
	// signing, before exec. A host binary is never ad-hoc re-signed
	// (hostBinary).
	if err := r.gateSignature(ctx, p.box.GetSignaturePolicy(), rb.path, rb.hostBinary); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED, err
	}

	// Resolve the container's securityContext identity plus the pod's rlimit plan
	// and qos decision (one supervisor.LaunchSpec), then wrap the command so
	// the spawned exec-shim applies the limits, drops to the identity, backgrounds
	// itself if BestEffort, confines itself to the profile, and then execs the pod
	// binary — in that irreversible order. env is preserved.
	cred := resolveCredential(p.box, c)
	shimPath, shimArgv, cleanup, err := r.backend.WrapCommand(ctx, p.profile, rb.argv, resolveLaunchSpec(p.box, cred))
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("wrap command for %s: %w", c.GetName(), err)
	}

	env, err := r.containerEnv(p.box, c, rb.env)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX, err
	}
	// The pod cwd: the merged working directory — the pod's working_dir,
	// else the image config's (image.MergeRunSpec) — is what the child chdirs
	// into. When neither is set the default is the pod data volume, never the
	// inherited cwd: this daemon's cwd is its own working directory, denied by
	// the pod's SBPL profile (and the user homes above it), so a pod that
	// inherited it started in a directory it may not even stat (a real
	// failure mode). The supervisor now refuses an unusable Dir (supervisor.ErrWorkingDir)
	// rather than falling back to it.
	//
	// It is the same default and precedence an exec session already resolves
	// (exec.go), so `kubectl exec` and the container it enters agree on where
	// they are. Applies uniformly to the host-binary routes (the native
	// sentinel and the absolute-path convention).
	workingDir := rb.workingDir
	if workingDir == "" {
		workingDir = rootfs
	}
	logs := newLogBuffer(r.log.With("pod", p.box.GetPodId(), "container", c.GetName()))
	spec := supervisor.SpawnSpec{
		Path: shimPath,
		Argv: shimArgv,
		Env:  env,
		Dir:  workingDir,
	}
	cp := &containerProc{
		name:         c.GetName(),
		spec:         c,
		initDeclared: isInit,
		logs:         logs,
		env:          env,
		workingDir:   workingDir,
		state: &runtimev1.ContainerStatus{
			Name:  c.GetName(),
			Image: c.GetImage(),
			// The image's content identity (config digest), empty on the two
			// host-binary routes — see resolvedBinary.imageID.
			ImageId: rb.imageID,
			State: &runtimev1.ContainerState{
				Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()},
			},
			// Lossless status mirrors of the container's spec fields (volume_mounts,
			// user) so kubectl Pod state does not degrade across the boundary.
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

	// Durably record the spawned process group before the spawn is acknowledged
	// (the startup pod reap's input, podreap.go). Failure fails the container:
	// an unrecorded pod process would be invisible to the reap and could orphan
	// across a daemon death. The just-spawned group is torn down through the
	// injected seam (not a direct supervisor call) so the failure path is
	// unit-observable.
	rec, err := r.recordPodProc(p.box.GetPodId(), c.GetName(), proc.PID())
	if err != nil {
		_ = r.signalGroup(proc.PID(), killSignal)
		_ = cleanup()
		return nil, runtimev1.FailureReason_FAILURE_REASON_SPAWN,
			fmt.Errorf("record container %s process group: %w", c.GetName(), err)
	}

	// Publish this incarnation's identity, derived from the reap record just
	// written (podProcRecord.containerID) — the same (pgid, leader start) pair
	// the reap matches on, never a second scheme. Written here, before the
	// reaper goroutine below exists, so cp is still owned solely by this
	// goroutine and no lock is needed; every later reader takes pod.mu.
	cp.state.ContainerId = rec.containerID()

	// Reap-completion goroutine: when the container exits, record terminated
	// state, clean up the staged profile, and publish a status update. Runs
	// under the pod-lifetime supervision ctx (above), so it outlives the
	// CreatePod RPC and is canceled on pod teardown.
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

	// Drop the durable reap record only once the process group is empty. The
	// leader exit that unblocked Wait does not imply forked grandchildren are
	// gone (the drain-wait below exists precisely because they commonly are
	// not), and on the ctx-cancel arm the leader itself may still be alive — so
	// removing the record here unconditionally would erase a live process's
	// record. A record left behind is harmless (identity-guarded) and is
	// retired by DeletePod's teardown or the next startup reap's group probe.
	if members, ok := r.procGroup(cp.proc.PID()); ok && len(members) == 0 {
		r.removePodProcRecord(p.box.GetPodId(), cp.proc.PID())
	}

	// Wait for the container's log pump to copy the dying child's combined output
	// to EOF before snapshotting it below for the FallbackToLogsOnError
	// termination message. The supervisor's pump drains the final bytes — the
	// panic / stack trace that is the most diagnostic part of a failure —
	// independently of the kqueue reaper that just unblocked Wait; snapshotting
	// straight away races the pump and intermittently loses those last lines.
	// This drain-wait sits outside pod.mu so the lock order stays leaf-ward
	// (pod.mu → logBuffer.mu, never inverted).
	//
	// The wait is bounded by drainGrace, independent of ctx: a pod process
	// commonly forks a grandchild (shell → daemon) that inherits and holds the
	// stdout/stderr pipe write-end open after the direct child exits, so the
	// pump never reaches EOF and LogsDrained never closes. Without the timeout
	// this select would block forever — and for a restarted container ctx is a
	// context.WithoutCancel whose Done() never fires, so LogsDrained would be
	// the only reachable arm. The terminated-status path must finalize
	// regardless (else the pod shows Running while dead and restartPolicy never
	// fires), so on the deadline we snapshot whatever the pump has buffered so
	// far — a partial tail is still diagnostic.
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
		// This container's own id — the incarnation that just died. The
		// terminated mirror is read as the identity of the run being reported,
		// so it must never be filled from a live containerProc that replaced
		// it: a successor's id published as the predecessor's is exactly the
		// confusion CRI container ids exist to prevent.
		ContainerId: cp.state.GetContainerId(),
	}
	switch {
	case p.oomKilled && (sig != 0 || code != 0):
		// The memory sampler SIGKILLed this pod for a limit breach: a
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

	// terminationMessagePolicy=FallbackToLogsOnError: when a container fails
	// (non-zero exit or a signal-kill, including OOMKilled) and nothing above
	// set a message, fill term.Message from the tail of its combined log.
	// runtimed applies this policy unconditionally — there is no per-container
	// terminationMessagePolicy in apis, and the default `File` policy is
	// unimplementable on darwin (no /dev/termination-log bind mount), so every
	// container is treated as FallbackToLogsOnError; a documented
	// divergent-by-design choice, strictly more diagnostic than the unavoidable
	// File-empty message. Only term.Message is touched: term.Reason keeps the
	// tested OOMKilled/Completed/Error strings, an already-set wait-error
	// message (above) is never clobbered, and a successful (exit-0) container
	// keeps an empty message (upstream NodeConformance asserts that).
	if (code != 0 || sig != 0) && term.Message == "" {
		if msg := terminationMessageFromLogs(cp.logs); msg != "" {
			term.Message = msg
		}
	}

	cp.state.State = &runtimev1.ContainerState{Terminated: term}
	// Snapshot the restart flag under the same lock that guards the state write,
	// so the publish decision at the bottom cannot straddle a concurrent
	// RestartContainer claiming this container.
	restarting := cp.restarting
	r.recomputePhaseLocked(p)

	// The mains just concluded the pod (mains-only accounting above). If that
	// conclusion is truly terminal, claim the irreversible teardown — stop the
	// memory sampler and stop the native sidecars in reverse start order — before
	// the terminal publish below. See trulyTerminalLocked for the predicate and
	// claimTerminalTeardownLocked for the exactly-once claim.
	td := claimTerminalTeardownLocked(p)
	p.mu.Unlock()

	// One pod-level grace budget, anchored NOW: the mains exited on their own
	// (voluntary completion) and consumed none of it, so the sidecars share the
	// whole configured budget in reverse start order (see stopSidecars).
	r.runTerminalTeardown(ctx, p, td)

	// Suppress the transient terminated publish of a container the provider is
	// already restarting. The state write above stands — RestartContainer
	// reads it back for last_termination_state — but publishing it would show
	// the provider a "new" exit for a restart it issued, and its terminationKey
	// idempotency would schedule a second restart for the same death. The
	// authoritative event for this exit is the one RestartContainer publishes
	// after the swap, carrying the bumped restart_count. On a failed restart
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
// the larger 4096 cap is the /dev/termination-log File-read cap, which does not apply
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
	// The byte-count tail cut can land inside a multi-byte UTF-8 rune, leaving
	// orphan continuation bytes at the front, so it goes through utf8TailBytes
	// (shared with logBuffer.write's oversized-line admission): term.Message stays
	// valid UTF-8, and because the rounding only ever trims, the <=2048-byte cap
	// still holds (the tail end, the most diagnostic bytes, is untouched).
	msg := utf8TailBytes(bytes.Join(lines, []byte("\n")), maxTerminationMessageLogBytes)
	return string(msg)
}

// trulyTerminalLocked reports whether the pod has reached a state it can never
// leave on its own — the only transition allowed to fire the two irreversible
// pod-teardown side effects (cancelling the memory sampler that enforces the
// pod's limit, and stopping the native sidecars, which cannot be resurrected).
// Caller holds p.mu, and must have recomputed the phase first.
//
// The predicate is: a terminal phase (Succeeded or Failed) with no container
// mid-restart.
//
// Both halves are load-bearing:
//
//   - Failed must be included. A restartPolicy Never/OnFailure pod whose main
//     fails is genuinely finished — nothing will ever restart it — yet Kubernetes
//     retains it: the Job controller keeps the failed pod under
//     backoffLimit/podFailurePolicy (ttlSecondsAfterFinished is commonly unset)
//     and podgc only collects at --terminated-pod-gc-threshold (default 12500).
//     "DeletePod is the backstop" is therefore false for exactly the workload
//     native sidecars exist to serve. On k3sm a pod is native Darwin processes
//     with no cgroup/namespace parent to collect them, so a teardown that never
//     fires is permanent: N such pods leave N ~1 Hz sampler goroutines (each able
//     to root-SIGKILL a process group) and N live sidecar process trees, unbounded
//     and with no operator-visible signal.
//
//   - The mid-restart guard is what makes including Failed safe, and it is sound
//     precisely because recomputePhaseLocked de-escalates: a main mid-restart
//     holds the phase at Running (allTerminated is false), so a Failed phase
//     already implies no main is restarting — the scan below is a defensive
//     restatement for the mains and the real work for sidecars, which
//     recomputePhaseLocked skips entirely. Tearing down a sidecar that
//     RestartContainer is mid-swap on would stop the old process and then let the
//     replacement spawn into a pod nothing will ever tear down again. RestartContainer
//     re-evaluates this predicate after the swap (and clearRestarting after a
//     failed one), so the deferred teardown is never merely skipped.
//
// The CrashLoopBackOff surface is preserved by RestartContainer, not by
// withholding the teardown: a re-exec de-escalates the pod back to Running and
// re-arms the memory sampler, so a resurrected main never runs unenforced.
//
// Residual, documented: sidecars stopped by a terminal transition are not
// resurrected by a later re-exec. This applies to a restartPolicy:Always pod
// whose main exits 0 or crashes — runtimed cannot tell it apart from Never/
// OnFailure, because PodBox carries no pod-level restartPolicy (only the
// container-level KEP-753 field, meaningful on init containers). Closing it
// needs an apis field, out of scope here; the leak above is the strictly worse
// failure, and this is the delivered native-sidecar teardown behaviour, unchanged.
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
// transition. It is assembled under p.mu (claimTerminalTeardownLocked) and run
// outside it (runTerminalTeardown), because both halves block: the sampler cancel
// races the sampler's own onBreach callback, which takes p.mu, and the sidecar
// stop spans a whole grace window.
type terminalTeardown struct {
	cancel   context.CancelFunc
	sidecars []*containerProc
}

// claimTerminalTeardownLocked evaluates trulyTerminalLocked and, when it holds,
// claims the teardown: it hands back the memory-sampler cancel and — at most once
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

// runTerminalTeardown executes a claimed teardown with p.mu not held: it cancels
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

// recomputePhaseLocked updates the pod phase from its main containers' states.
// Native sidecars are excluded from the terminal accounting (the mains-only rule
// of the apis restart_policy contract): when every main has terminated the pod
// goes Succeeded/Failed on the mains alone, even with sidecars still running (the
// Job-with-sidecar case), and a crashed/exited sidecar never concludes the pod by
// itself. Caller holds p.mu.
//
// The phase is a pure function of the current main-container states, never a
// latch: it de-escalates back to Running as soon as a main is running again (see
// the default arm). Every consumer of p.phase may therefore read it as
// state-derived — trulyTerminalLocked depends on it, and specifically on the fact
// that a main mid-restart holds the phase at Running.
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
		// De-escalation: at least one main is live again — it never
		// terminated, or RestartContainer swapped in a running replacement, or a
		// main is mid-restart (skipped above). Falling back to Running is
		// required, not cosmetic: without this arm the terminal phase is a
		// one-way latch, so a restartPolicy:Always pod that crashes once and
		// then successfully re-execs reports phase:Failed forever. Upstream
		// reads that as a dead pod — the ReplicaSet deletes and replaces it,
		// podgc reaps it, and a Job counts it against backoffLimit — exactly
		// the CrashLoopBackOff surface this restart accounting exists to make honest.
		p.phase = runtimev1.PodPhase_POD_PHASE_RUNNING
	}
}

// gateSignature enforces the SignaturePolicy in the correct order relative to the
// ad-hoc-sign step, fail-closed, before exec:
//
//   - hostBinary (native pod / host-path convention): never ad-hoc sign. A host
//     binary is an already-signed system or operator binary at a read-only host
//     path — `codesign -s - -f /bin/sh` fails ("internal error in Code Signing
//     subsystem": a SIP-protected Apple platform binary cannot be re-signed) and
//     would strip a real authority on any notarized one. Only check the existing
//     signature (ADHOC_OK accepts an Apple-signed /bin/sh and an ad-hoc-signed
//     host helper alike), so the binary execs unmodified.
//   - ADHOC_OK (pulled image): ad-hoc signing is the point (an unsigned arm64
//     Mach-O in the writable pod rootfs is signed so it execs under AMFI with a
//     later DYLD insert) — but check first and sign only if the check fails. An
//     ad-hoc signature is content-addressed and survives clonefile verbatim, so a
//     pod rootfs cloned from an already-signed tree needs no signing at all; an
//     unconditional `codesign -s - -f` would rewrite argv[0] on every start and
//     de-CoW it, turning a free clone into a full copy each time the pod restarts.
//     When the first check fails the binary is signed and re-checked, so the
//     signature is still confirmed before exec.
//   - REQUIRE_SIGNED / REQUIRE_NOTARIZED: enforce the policy on the as-pulled
//     binary and never ad-hoc sign it — `codesign -s - -f` would strip an existing
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
		// Already valid: return without signing — this is the clone-preserving path
		// (see the ADHOC_OK bullet above). A check that fails for a reason other than
		// an absent signature (a codesign tool failure) also falls through to sign +
		// re-check, which surfaces the underlying error rather than hiding it.
		if err := r.signer.Check(ctx, policy, path); err == nil {
			return nil
		}
		if err := r.signer.Sign(ctx, path); err != nil {
			return fmt.Errorf("ad-hoc sign %s: %w", path, err)
		}
		return r.signer.Check(ctx, policy, path)
	}
	// require-signed / require-notarized / unspecified: check the as-pulled binary;
	// do not ad-hoc sign (no silent downgrade).
	return r.signer.Check(ctx, policy, path)
}

// NativeImage is the k3sm HostProcess sentinel image reference
// (examples/hello-native.yaml). A container whose image is "native" runs its
// command[0] as an absolute HOST binary in place — no registry pull, no rootfs
// materialization — which is how every host-process conformance pod (and
// hello-native.yaml) executes. It is the with-command analog of the empty-command host-binary
// convention below (there the image itself is the path; here command[0] is).
const NativeImage = "native"

// resolvedBinary is what resolveBinary determined for one container: the on-disk
// executable to confine, its argv, whether it is a host binary, and the image
// identity to publish for it.
type resolvedBinary struct {
	// path is the on-disk executable to confine and spawn.
	path string
	// argv is the child's argument vector (argv[0] is path).
	argv []string
	// hostBinary reports whether path is a HOST binary (the native sentinel or
	// the empty-command host-path convention) rather than a pulled-image payload.
	// A host binary is already validly signed and lives at a read-only host path,
	// so it must never be ad-hoc re-signed (see gateSignature).
	hostBinary bool
	// imageID is the pulled image's config digest ("<algo>:<hex>") — the
	// per-platform content identity of the image this container runs, and what
	// ContainerStatus.image_id publishes. It comes from the manifest the pull
	// path itself resolved and verified (every blob is checked against that
	// manifest's descriptors at commit), so it is never re-derived from registry
	// bytes at status time.
	//
	// It is empty, correctly, for both host-binary routes: the native sentinel
	// and the absolute-host-path convention run an already-present host
	// executable with no registry round trip and no manifest at all, so there is
	// no content digest to report. An empty image_id degrades visibly (kubectl
	// shows a blank IMAGE ID); a substitute — the mutable image reference, a
	// synthesized value — would be a lie in a content-addressable field: a
	// scanner or admission-audit tool would resolve the wrong artifact silently.
	imageID string
	// env is the container's merged environment in "K=V" form — the image
	// config's Env with the pod's env overriding by name (image.MergeRunSpec).
	// It is nil on both host-binary routes, where there is no image config to
	// merge and containerEnv keeps its behaviour of building the
	// environment from the container spec alone.
	env []string
	// workingDir is the container's effective working directory: the pod's
	// working_dir when set, else the image config's, else empty. On a
	// host-binary route it is the pod's value verbatim.
	workingDir string
}

// resolveBinary determines the pod binary path + argv for a container.
//
// # The discriminator
//
// What happens is decided by the shape of the image reference, not by the
// emptiness of command (apis runtime/v1 Container.command):
//
//   - the "native" sentinel — command[0] is an absolute host binary, run in
//     place, no pull;
//   - an absolute path with no command/args — the host-binary convention:
//     the reference is the binary, unchanged. It stays the native path's way
//     to run a host binary with no image at all;
//   - an OCI reference — pull, materialize, and merge the image config with the
//     container spec (image.MergeRunSpec). This replaced an earlier placeholder
//     that made argv literally command+args and therefore panicked on a
//     container with args and no command, and refused a container with
//     neither even though its image declared an Entrypoint.
//
// The discriminator decides argv[0] too, and only the discriminator does: on
// the OCI arm argv[0] names a file in the image, so it is resolved inside the
// pod's materialized rootfs whether or not it leads with a slash
// (resolveImageArgv0); on the two host-binary arms it names a host path and is
// taken verbatim. argv's own shape is never consulted — see resolveImageArgv0
// for the failure that rule produced.
//
// p supplies both the PodBox (for the imagePullSecret lookup) and the resolved
// sandbox backend the pull's image-platform policy and the unpack dialect are
// derived from — see pullPolicy, unpackPolicy and the pod.backend field.
func (r *Runtime) resolveBinary(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container) (resolvedBinary, error) {
	cmd := c.GetCommand()

	// Native HostProcess sentinel: run command[0] as an absolute host binary with
	// no pull. Checked before the pull path — a "native" pod carries a command, so
	// it would otherwise fall through and fail trying to fetch docker.io/library/native.
	if c.GetImage() == NativeImage {
		if len(cmd) == 0 {
			return resolvedBinary{}, fmt.Errorf("container %s: image %q requires a command (the host binary to run)", c.GetName(), NativeImage)
		}
		bin := cmd[0]
		if !filepath.IsAbs(bin) {
			return resolvedBinary{}, fmt.Errorf("container %s: native command %q must be an absolute host path", c.GetName(), bin)
		}
		// No manifest exists on this route, so imageID stays empty (see the field).
		return resolvedBinary{
			path:       bin,
			argv:       append(append([]string{}, cmd...), c.GetArgs()...),
			hostBinary: true,
			workingDir: c.GetWorkingDir(),
		}, nil
	}

	if c.GetImage() == "" {
		return resolvedBinary{}, fmt.Errorf("container %s: image is required", c.GetName())
	}

	// The discriminator, on the no-command route: the shape of the reference
	// decides, not the emptiness (apis runtime/v1 Container.command).
	//
	// An absolute path is the host-binary convention and is unchanged — the
	// reference is the binary, run in place with no pull. An OCI reference falls
	// through to the pull path below, where the image config's Entrypoint/Cmd
	// supply the argv. Previously this branch refused an OCI-referenced
	// container with no command, so a perfectly ordinary `image: nginx` pod
	// could not run.
	if len(cmd) == 0 && len(c.GetArgs()) == 0 && image.IsHostPathReference(c.GetImage()) {
		bin := c.GetImage()
		// No manifest exists on this route either — imageID stays empty.
		return resolvedBinary{path: bin, argv: []string{bin}, hostBinary: true, workingDir: c.GetWorkingDir()}, nil
	}

	// Resolve the imagePullSecret credential via the consumer-side seam. It
	// is passed only to the pull client below and never written to the pod dir.
	cred, err := r.pullCredential(ctx, p.box, c.GetImage())
	if err != nil {
		return resolvedBinary{}, err
	}

	// Pull + materialize the image into the pod rootfs, then run command/args.
	// The container's imagePullPolicy is forwarded exactly as the provider
	// stamped it: the puller decides Always/IfNotPresent/Never against
	// the node's local image store, and an unset value is the legacy
	// pull-through. Nothing here re-derives a policy from the image tag.
	res, err := r.puller.Pull(ctx, c.GetImage(), cred, pullPolicy(p.backend), c.GetImagePullPolicy())
	if err != nil {
		return resolvedBinary{}, fmt.Errorf("pull image %q: %w", c.GetImage(), err)
	}
	// Record the root, then release the lease — in that order, never reversed.
	// Pull returns with its blobs pinned by a lease precisely because they are
	// on disk and named by nothing yet; recording the reference is what makes
	// them reachable, so releasing first would reopen the window a concurrent
	// reclaim deletes into. The record is what a later prune consults, the
	// lease is what covers the instant before it exists.
	if err := r.recordPodImage(p.box.GetPodId(), res.Manifest); err != nil {
		res.Lease.Release()
		return resolvedBinary{}, err
	}
	res.Lease.Release()

	// Materialize. This was once a placeholder: the blobs were in
	// the cache, the pod rootfs was empty, and argv[0] was resolved against a
	// directory that held nothing, so a container whose command lived in its
	// image could never start. The unpacker applies the image's layers in order
	// into a content-addressed tree and CoW-clones that tree into this pod's
	// rootfs, so a relative command[0] now names a real file.
	//
	// It runs after the lease release deliberately: the reachability root
	// recorded just above is what protects these blobs from a concurrent
	// reclaim for the whole of the unpack, and it is a durable record rather
	// than an expiring pin.
	//
	// A failure here fails the container. There is no "materialize what we can"
	// degradation: a partial rootfs is a pod that starts and then behaves in a
	// way no manifest describes, and the tree is committed atomically precisely
	// so the only two outcomes are the whole image or an error.
	policy, err := unpackPolicy(p.backend)
	if err != nil {
		return resolvedBinary{}, fmt.Errorf("container %s: %w", c.GetName(), err)
	}
	mat, err := r.unpacker.MaterializeTree(ctx, res.Manifest, policy, rootfs)
	if err != nil {
		return resolvedBinary{}, fmt.Errorf("materialize image %q: %w", c.GetImage(), err)
	}
	r.log.Debug("materialized image tree",
		"pod", p.box.GetPodId(), "container", c.GetName(), "image", c.GetImage(),
		"tree", mat.Tree.Key, "tree_cache_hit", mat.Tree.CacheHit, "cloned", mat.Cloned)

	// Merge the image config with the container spec: the k8s four-quadrant
	// command/args table, $(VAR) expansion, the image's Env under the pod's, the
	// image's WorkingDir under the pod's, and upstream's runAsNonRoot rule. This
	// is the one producer of argv on this route.
	//
	// The uid handed to the merge is the same one the spawn will drop to
	// (resolveCredential, from the container > pod > box precedence chain), so
	// the runAsNonRoot verdict is made about the identity that actually runs and
	// not about a second reading of the security context.
	runCfg, err := r.unpacker.ImageRunConfig(res.Manifest)
	if err != nil {
		return resolvedBinary{}, fmt.Errorf("read image config for %q: %w", c.GetImage(), err)
	}
	run, err := image.MergeRunSpec(runCfg, image.RunSpecRequest{
		Container:    c,
		RunAsUID:     int64(resolveCredential(p.box, c).UID),
		RunAsNonRoot: effectiveRunAsNonRoot(c),
	})
	if err != nil {
		return resolvedBinary{}, err
	}

	// argv[0] is the merged program resolved inside this pod's materialized
	// rootfs — whether or not it carries a leading slash. See resolveImageArgv0
	// for why the leading slash carries no meaning on this route.
	bin, err := resolveImageArgv0(rootfs, run.Argv[0])
	if err != nil {
		return resolvedBinary{}, fmt.Errorf("container %s: %w", c.GetName(), err)
	}
	argv := append([]string{}, run.Argv...)
	argv[0] = bin
	// The config digest, not the index digest and not the reference: it is the
	// per-platform content identity (the same value a containerd-backed kubelet
	// reports), whereas an index digest is shared by every platform of a
	// multi-platform image and a reference is a mutable tag — both would resolve
	// the wrong artifact in a field consumers read as content-addressable. It is
	// the digest recorded as this pod's reachability root (recordPodImage above,
	// image.ImageRoot.Config), so status and GC name the same blob.
	return resolvedBinary{
		path:       bin,
		argv:       argv,
		imageID:    res.Manifest.GetConfig().GetDigest(),
		env:        run.Env,
		workingDir: run.WorkingDir,
	}, nil
}

// ErrImageArgvEscapes reports that a pulled image's argv[0] resolves outside the
// pod rootfs it must run from. It is a sentinel so a caller (and a test) can
// name the refusal without matching on the message.
var ErrImageArgvEscapes = errors.New("image program escapes the pod rootfs")

// resolveImageArgv0 resolves a pulled image's argv[0] against the pod's
// materialized rootfs and refuses anything that lands outside it.
//
// # Why a leading slash means nothing here
//
// The absolute-path-is-a-host-binary rule belongs to the image-reference
// discriminator, not to argv: resolveBinary decides between "run a host binary
// in place" and "pull, materialize, merge" by the shape of the image reference
// (image.IsHostPathReference — an OCI reference can never begin with '/'), and
// this function is only ever reached on the second arm, after MaterializeTree
// has populated rootfs. On that arm argv[0] came out of image.MergeRunSpec —
// the image's own Entrypoint/Cmd or the pod's command — all naming paths in
// the image's filesystem, where a leading slash means the image root and
// nothing else.
//
// Keying on argv's own shape instead resolved a pulled image's absolute
// argv[0] as a HOST path: mlx-serve's
// Entrypoint is /bin/python3.12, so the previous "absolute means the host
// supplies it" rule sent the signature gate at the host's /bin/python3.12,
// which on a stock macOS does not exist — the pod failed
// FAILURE_REASON_SIGNATURE_REJECTED with "no such file or directory" while the
// byte-identical image with a relative argv[0] ran to completion. A path that
// resolved to a host binary would be worse than a failure: it would run host
// code with the pod's identity under the pod's profile.
//
// # Containment
//
// filepath.Join cleans, so "../.." and "/../../usr/bin/env" are resolved before
// the check rather than pattern-matched, and the result must be a proper
// descendant of rootfs. The refusal is fail-closed: the merged argv is partly
// image-supplied, and an image that could name a path above its own root would
// choose which host binary the daemon signs and spawns.
//
// It is a containment check, not a sandbox: rootfs is not a chroot (DESIGN §5a
// — confinement is Seatbelt at host paths), so a symlink inside the tree that
// points out of it still resolves out of it at exec time. Resolving symlinks
// here would not close that (the tree is writable by the pod, so any answer is
// stale the moment it is given); the profile is what bounds what the process
// may then touch, and this check is what keeps the daemon from being the one
// that walks out.
func resolveImageArgv0(rootfs, argv0 string) (string, error) {
	if argv0 == "" {
		return "", errors.New("image program is empty")
	}
	bin := filepath.Join(rootfs, argv0)
	if !mount.IsStrictlyUnder(bin, rootfs) {
		return "", fmt.Errorf("%w: %q resolves to %q, outside %q", ErrImageArgvEscapes, argv0, bin, rootfs)
	}
	return bin, nil
}

// effectiveRunAsNonRoot resolves runAsNonRoot for a container.
//
// It reads the container's securityContext only, a faithful reading of the
// contract available to it: apis PodSecurityContext carries fs_group,
// run_as_user and run_as_group but no run_as_non_root, so a pod-scoped
// `securityContext.runAsNonRoot: true` has nowhere to land on the wire.
// resolveCredential has the same shape for the same reason.
//
// Known contract gap, not closed here: a pod-level runAsNonRoot is therefore
// not enforced on a container that does not repeat it. Closing it is an apis
// change (an additive PodSecurityContext.run_as_non_root plus the k3sm
// provider stamping it), not a runtimed merge function. Composition, when the
// field arrives, is a logical OR: the proto's bool has no presence, so a
// container-level false cannot be distinguished from unset and must never
// weaken a pod-level assertion.
func effectiveRunAsNonRoot(c *runtimev1.Container) bool {
	return c.GetSecurityContext().GetRunAsNonRoot()
}

// pullPolicy is the image-platform policy for a pull, built from the pod's
// resolved sandbox backend (pod.backend, recorded by createPod) — exactly what
// image.PlatformPolicy.Backend is documented to carry. The resolved value is
// threaded rather than restated as a constant so the contract and the call
// site cannot drift: a future native rung whose image-platform class differed
// would be refused by image.Candidates instead of silently mis-selected
// through a valid enum value.
//
// Both spines pull through this seam, each passing the backend its own pod
// resolved: the host-process spine from pod.backend (resolveBinary), and the vm
// spine from the rung SelectBackend routed it on (resolveVMContainers, which
// pulls for the image config the guest-side merge needs). So the platform a pull
// selects always follows the rung the pod is actually confined by, and neither
// spine can pull a Mach-O image for a Linux guest or the reverse.
//
// HostRosetta is false deliberately, not for want of a probe: the probe exists
// (sandbox.ProbeHostRosetta, advertised on GetRuntimeInfo as the
// RosettaHostAvailable condition). The pull path does not consume it until the
// Seatbelt x Rosetta spawn is proven, for two reasons:
//
//   - a darwin/amd64 payload's behaviour inside a Seatbelt profile is unverified, so
//     selecting one would trade a legible pull-time refusal for an unexplained
//     runtime failure;
//   - AMFI does not kill an unsigned x86_64 Mach-O the way it kills an unsigned
//     arm64 one (measured), so selecting amd64 payloads would silently drop the
//     kernel backstop that stands behind the signature policy.
//
// So a darwin/amd64-only image stays refused at pull with a legible
// image.ErrNoPlatformMatch. Do not flip this to r.rosettaHost without that proof.
func pullPolicy(backend runtimev1.SandboxBackend) image.PlatformPolicy {
	return image.PlatformPolicy{Backend: backend}
}

// unpackPolicy is the layer-application dialect a materialization uses, derived
// from the pod's resolved sandbox backend (pod.backend, recorded by createPod) —
// the same value pullPolicy threads into the image-platform policy, so the
// platform a pull selects and the dialect its layers are applied in can never
// disagree about which spine the pod is on.
//
// It fails closed on an unset or unknown backend (image.UnpackPolicyFor): a
// missing dialect is an error at create time rather than a silent fall-through
// to the native rules, which would apply Mach-O semantics to a Linux image and
// commit the result under a key claiming otherwise.
//
// Every live caller is still native: the vm spine resolves its containers
// without materializing anything (composing the guest's rootfs lower layer out
// of the pulled blobs is the rootfs-builder deliverable — see
// resolveVMContainers), so the Linux dialect is exercised by tests until that
// lands.
func unpackPolicy(backend runtimev1.SandboxBackend) (image.UnpackPolicy, error) {
	return image.UnpackPolicyFor(backend)
}

// pullCredential resolves the registry pull credential for ref from the pod's
// imagePullSecrets via the consumer-side CredentialResolver seam. It
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

// tmpDirEnv is the environment variable every POSIX temp-file API consults, and
// podTmpDirName is the directory inside the pod data volume runtimed provisions
// for it.
const (
	tmpDirEnv     = "TMPDIR"
	podTmpDirName = "tmp"
)

// podTmpDir is the pod's own temp directory: one subdirectory of the pod data
// volume, and the single derivation of that path — provisionPodTmpDir creates it
// and containerEnv publishes it, so the directory a pod is told about is the
// directory that was made.
func podTmpDir(dataVol string) string { return filepath.Join(dataVol, podTmpDirName) }

// provisionPodTmpDir creates the pod's temp directory inside its data volume.
//
// Why this exists: a confined pod has no usable temp directory at all. The SBPL
// profile does not write-allow /tmp or /var/tmp, and nothing sets TMPDIR, so a
// workload that asks the platform for one exhausts its whole candidate list and
// fails — Python's tempfile.gettempdir() raising after /tmp, /var/tmp and
// $TMPDIR all fail is a real failure mode under Seatbelt confinement, and it takes the whole process down
// before any of its own code runs. The data volume is already the pod's
// read/write scope in the generated profile, so a directory inside it needs no
// SBPL change; this is the one place the writable tree a pod already has is
// given the name the platform looks for.
//
// Created at create time, before any container is spawned and before the
// fsGroup walk, so the directory a container's TMPDIR names always exists by
// the time that container runs and inherits the fsGroup grant when one is set.
//
// 0700 is deliberate: a pod temp directory holds whatever the workload puts
// there and no other pod's process has a reason to read it. Residual, recorded
// rather than hidden: same-node pods share this daemon's uid (the documented
// host-process ceiling — untrusted tenancy routes to the vm RuntimeClass), so
// 0700 is defence against an unrelated local uid, not against another pod. A
// container that drops to a different uid reaches this directory only through
// fsGroup, exactly as it reaches the rest of the data volume.
func provisionPodTmpDir(dataVol string) error {
	dir := podTmpDir(dataVol)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create pod tmp dir %s: %w", dir, err)
	}
	return nil
}

// containerEnv builds the child environment: a base set, plus TMPDIR pointing
// into the pod data volume, plus the DYLD inserts that make cluster features work
// in-pod — the path-rebase shim (so an absolute volume mount resolves to its
// materialized copy under the pod data volume, no chroot) and the DNS shim (box
// annotation). DYLD_INSERT_LIBRARIES is appended last so an explicit container
// env can override it (rare). A container that sets DYLD_INSERT_LIBRARIES itself
// opts out of both shims.
//
// TMPDIR is injected only when the base does not already carry one, so a
// container that names its own temp directory keeps it — the same
// spec-beats-injection rule DYLD_INSERT_LIBRARIES follows. It is injected here,
// at the one seam both the container spawn and an Exec session pass through, so
// a `kubectl exec` shell has the same temp directory the container does.
//
// base is the merged environment resolveBinary produced for a pulled image (the
// image config's Env under the container's, image.MergeRunSpec) — the source of
// $PATH, $HOME and everything else an image ships. It is nil on the two
// host-binary routes, and then the base is the container's own EnvVars, the
// behaviour unchanged from before image-config env merging existed. TMPDIR is injected on every one of those routes: a
// host-process pod is confined by the same profile and has the same
// no-usable-tmp problem.
func (r *Runtime) containerEnv(box *runtimev1.PodBox, c *runtimev1.Container, base []string) ([]string, error) {
	if base == nil {
		base = make([]string, 0, len(c.GetEnv()))
		for _, e := range c.GetEnv() {
			base = append(base, e.GetName()+"="+e.GetValue())
		}
	}
	env := make([]string, 0, len(base)+4)
	if !envHasName(base, tmpDirEnv) {
		dataVol, err := r.rootfsPath(box)
		if err != nil {
			return nil, err
		}
		env = append(env, tmpDirEnv+"="+podTmpDir(dataVol))
	}
	explicitDyld := false
	for _, e := range base {
		env = append(env, e)
		if name, _, _ := strings.Cut(e, "="); name == dyldInsertEnv {
			explicitDyld = true
		}
	}
	if explicitDyld {
		// Explicit container DYLD wins; do not inject shims. The full base is
		// already appended above: an explicit DYLD entry mid-slice must
		// not truncate whatever base env follows it.
		return env, nil
	}

	var inserts []string
	// Path-rebase shim: only when the shim is configured and this container mounts
	// a volume (nothing to rebase otherwise). K3SM_ROOTFS/K3SM_MOUNT_PATHS configure
	// it; a workload not loading the shim (a SIP platform binary) just ignores them.
	if paths := containerMountPaths(c); r.cfg.PathShimPath != "" && len(paths) > 0 {
		rootfs, err := r.rootfsPath(box)
		if err != nil {
			return nil, err
		}
		inserts = append(inserts, r.cfg.PathShimPath)
		env = append(env,
			pathShimRootfsEnv+"="+rootfs,
			pathShimMountsEnv+"="+strings.Join(paths, ":"))
	}
	if ins := box.GetAnnotations()[dyldInsertAnnotation]; ins != "" {
		inserts = append(inserts, ins)
	}
	if len(inserts) > 0 {
		env = append(env, dyldInsertEnv+"="+strings.Join(inserts, ":"))
	}
	return env, nil
}

// envHasName reports whether env (in "K=V" form) already sets name. It is how
// an injected entry stays out of the way of one the spec supplied.
func envHasName(env []string, name string) bool {
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); k == name {
			return true
		}
	}
	return false
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

// errUncontainedRootfs is the sentinel for a box whose rootfs_path is not this
// pod's own derived data volume. Callers surface it as an invalid-argument
// failure (FAILURE_REASON_INVALID_POD_BOX); it is never retried, since the value
// cannot become acceptable without the caller changing it.
var errUncontainedRootfs = errors.New("rootfs_path is not the pod's derived data volume")

// rootfsPath returns the on-disk pod data volume for box: always the
// cache-derived <Root>/pods/<pod_id>/rootfs. A non-empty box.rootfs_path is
// accepted only when it is byte-equal to that derived path; anything else is
// refused with errUncontainedRootfs and no path at all, so no caller can act on
// a value that was never checked. createPod, createVMPod, containerEnv, Exec and
// RestartContainer share it, so the pod cwd / SBPL scope / VM rootfs is resolved
// one way.
//
// Why this is a root-daemon hole: rootfs_path arrives over the runtimed gRPC
// seam, and the daemon's socket is not denied by the default pod sandbox
// profile (only the netd helper socket is) while pods run at the daemon's own
// uid — so a confined pod can issue CreatePod itself. The value then flows into
// os.MkdirAll, mount.Materialize, volume.Binder.Bind, supervisor.ChownForFSGroup
// (a recursive Lchown + Chmod that grants the group the owner's rwx and sets
// setgid on every directory), the resolved binary path, the K3SM_ROOTFS shim env,
// the Exec cwd and sandbox.VMSpec.RootfsPath. Unvalidated, that is
// privilege-escalation-from-a-confined-pod, not merely a control-plane-compromise
// amplifier.
//
// Why byte-equality and not "strictly under the pods root": a containment
// predicate is weaker in three distinct ways, each of which byte-equality makes
// structurally impossible without resolving anything on disk:
//
//   - Cross-pod. <PodsRoot>/<victim-id>/rootfs passes any prefix test, handing
//     the caller another pod's materialized secrets and projected SA-token — and
//     removePodDir derives its target from the attacker's id, so the damage is
//     never cleaned up.
//   - Symlink-blind. A lexical check cannot see that <PodsRoot>/<own-id>/rootfs/
//     link is a symlink to /var/lib/k3sm/server: the pod's own data volume is
//     writable at both the POSIX and the SBPL layer (it is re-allowed after the
//     protected denies), and MkdirAll / Materialize follow the link.
//   - Case aliasing. The default APFS volume is case-insensitive, so an
//     uppercase spelling of another pod's id names that pod's directory — the
//     same class podIDRe's lowercase-only rule closed for pod_id itself.
//
// Firmlink spellings (/var vs /private/var) are likewise refused, because the
// derived path is the only accepted spelling — fail-closed: normalizing aliases
// would mean resolving the path, and a resolver that mis-parses fails open.
// Every producer today leaves the field empty (no caller in k3sm sets it), so
// the guard is behaviour-neutral: the accept branch can only ever return the
// value the derivation already computes.
//
// Scope, honestly: this closes the rootfs_path daemon-input hole only. It does
// not make same-node pods mutually isolated — pods still share the daemon's uid,
// so untrusted multi-tenancy still routes to the vm RuntimeClass. The sibling
// wire path SandboxProfile.data_volume_path is validated separately, by
// dataVolumePath below (which accepts only this pod's own two derived
// spellings); do not read either check as "wire paths are validated" in general.
func (r *Runtime) rootfsPath(box *runtimev1.PodBox) (string, error) {
	id, err := image.ParsePodID(box.GetPodId())
	if err != nil {
		return "", err
	}
	derived := r.cache.PodRootfs(id)
	if rootfs := box.GetRootfsPath(); rootfs != "" && rootfs != derived {
		return "", fmt.Errorf("%w: %q is not %q", errUncontainedRootfs, rootfs, derived)
	}
	return derived, nil
}

// errUnderivedDataVolume is the sentinel for a box whose
// sandbox_profile.data_volume_path is not one of this pod's own derived data
// volumes. Like errUncontainedRootfs it surfaces as FAILURE_REASON_INVALID_POD_BOX
// and is never retried: the value cannot become acceptable without the caller
// changing it.
var errUnderivedDataVolume = errors.New("data_volume_path is not the pod's derived data volume")

// dataVolumePath returns the SandboxProfile.data_volume_path box is entitled to.
// It accepts exactly the two runtime-derived spellings for the box's own pod id —
// <Root>/pods/<pod_id> (the pod dir) and <Root>/pods/<pod_id>/rootfs (the rootfs
// under it) — and refuses everything else with errUnderivedDataVolume and no
// path, so no caller can act on a value that was never checked.
//
// What the value reaches: data_volume_path is a producer-set field on the
// cross-repo SandboxProfile that flows into sandbox.Generate, which emits it as
// (allow file-read* file-write* (subpath dataVol)) in the narrow re-allow tier —
// after the protected denies. SBPL is last-match-wins, so a hostile value
// overrides the whole deny-set (user homes, the pods root, the podreap store,
// and the control-plane/daemon trees added to close a storage-path escape) in
// a single emitted line. It is
// also the carve-out base in validateExtraPaths (`if isUnder(p, cleanData) {
// continue }`), so one hostile value additionally disarms the protected-prefix
// validator for every other path in the same box.
//
// Why an equality check here and containment at the sink: sandbox.Generate
// receives no pod id, so it cannot ask this question at all — the strongest
// thing it can do is bound the value to the pods root
// (sandbox.ErrDataVolumeUnbounded), which by construction accepts
// <PodsRoot>/<victim-id>/rootfs. pkg/runtime is where the authoritative value is
// derived, so this is where cross-pod is refused. The two layers fail on
// different input classes — the property a second layer must have to be a
// layer: this one catches cross-pod and every absolute path
// off the pods tree, the sink catches the ancestor/whole-tree class ("/",
// "/var/lib", the work-dir itself) for any future caller of the exported
// Generate.
//
// Why both spellings are accepted — not laziness:
//
//   - PodDir is what the only producer sends. The k3sm provider stamps
//     data_volume_path from its podRoot(id) == <root>/pods/<id> (pkg/provider,
//     translate.go), and k3sm's go.mod carries `replace k3sm.io/runtimed =>
//     ../runtimed`, so there is no version-skew window: accepting only the rootfs
//     spelling would refuse every pod on every node on the next build, reported
//     per-pod as an invalid box — a node-wide outage wearing a per-pod costume.
//   - PodRootfs is one level deeper, i.e. strictly less privilege, and is what
//     the tests and in-repo prototypes pass. Accepting a strictly narrower value
//     is safe by construction.
//
// Residual, recorded rather than hidden: PodDir grants one directory level more
// than any Seatbelt pod needs. Everything a pod runs against is materialized
// under <podDir>/rootfs; the k3sm.proj / k3sm.vols siblings are vm-only and the
// vm path never calls sandbox.Generate, and the staged .sb profile lives under
// <Root>, not the pod dir. So a future artifact placed under <podDir> outside
// rootfs/ becomes pod-writable silently. Narrowing to PodRootfs alone is a
// producer-side change in k3sm (send the deeper spelling), not a change here.
func (r *Runtime) dataVolumePath(box *runtimev1.PodBox) (string, error) {
	id, err := image.ParsePodID(box.GetPodId())
	if err != nil {
		return "", err
	}
	podDir, rootfs := r.cache.PodDir(id), r.cache.PodRootfs(id)
	dataVol := box.GetSandboxProfile().GetDataVolumePath()
	if dataVol != podDir && dataVol != rootfs {
		return "", fmt.Errorf("%w: %q is neither %q nor %q", errUnderivedDataVolume, dataVol, podDir, rootfs)
	}
	return dataVol, nil
}

// recordPodReferences creates the pod's empty image-reachability record. It is
// called as the pod dir is created; see image.Cache.EnsurePodReferences for why
// a pod that pulls nothing still gets one.
func (r *Runtime) recordPodReferences(podID string) error {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	if err := r.cache.EnsurePodReferences(id); err != nil {
		return fmt.Errorf("record image references for pod %s: %w", podID, err)
	}
	return nil
}

// recordPodImage records that podID references mfst's blobs, making them
// reachable to the image GC.
//
// This is the daemon authoring a reachability root from what it itself resolved
// for a pod it itself created — the only provenance a root may have. The
// manifest's registry-supplied bytes contribute the digests; they do not
// contribute the decision that this pod references them.
func (r *Runtime) recordPodImage(podID string, mfst *runtimev1.ImageManifest) error {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidPodBox, err)
	}
	root := image.ImageRoot{Reference: mfst.GetReference(), Config: mfst.GetConfig().GetDigest()}
	for _, l := range mfst.GetLayers() {
		root.Layers = append(root.Layers, l.GetDigest())
	}
	if err := r.cache.RecordPodImage(id, root); err != nil {
		return fmt.Errorf("record image references for pod %s: %w", podID, err)
	}
	return nil
}

// podDir returns the per-pod directory under the cache root. It returns an error
// rather than a path for an invalid id, so a caller cannot act on a directory
// derived from an identifier that was never checked.
func (r *Runtime) podDir(podID string) (string, error) {
	id, err := image.ParsePodID(podID)
	if err != nil {
		return "", err
	}
	return r.cache.PodDir(id), nil
}

// removePodDir deletes a pod's on-disk dir (best-effort, on delete).
//
// It removes only <Root>/pods/<podID>. Persistent-volume dirs live under
// <Root>/storage (a sibling of the pods root), so a PVC's data is intentionally
// not removed here — lifecycle decoupling (ReclaimPolicy Retain): the
// PV survives pod stop/restart/delete and the next pod that mounts the same
// claim reuses it. A PVC's pod-side symlink lives inside the pod dir and is
// removed, but os.RemoveAll unlinks the symlink without following it, so the
// target dir under <Root>/storage is untouched.
func (r *Runtime) removePodDir(podID string) error {
	dir, err := r.podDir(podID)
	if err != nil {
		// An id that is not a legal path component never produced a directory,
		// so there is nothing to remove and nothing to report.
		return nil
	}
	// Defence in depth behind the validated id. The previous guard was a bare
	// strings.HasPrefix on the root, which is not containment: with root
	// /var/lib/k3sm it admits /var/lib/k3sm-evil (a sibling whose name merely
	// starts the same), and it admits any path that stays inside the root but
	// outside the pods tree — including the control-plane state dir. The
	// separator-aware check bounds the target strictly under <root>/pods, which
	// is the only tree this function is ever entitled to delete.
	if !mount.IsStrictlyUnder(dir, r.cache.PodsRoot()) {
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
// Bounded by bytes, not by line count (logBufferMaxBytes): the retention budget
// has to be denominated in the resource it protects. A line-count cap is not a
// memory bound at all — the supervisor's pump admits a single token up to 1 MiB
// (supervisor.pumpLogs' bufio.Scanner max), so "keep the last 5000 lines" is
// "keep up to 5 GiB" in the worst case. The byte cap bounds both shapes with one
// number, and is the unit the read side already speaks
// (GetLogsRequest.limit_bytes in k3sm.io/apis).
//
// Eviction is true ring behaviour: the oldest lines go first, so the newest
// output — what `kubectl logs` and the FallbackToLogsOnError termination
// message actually ask for — always survives. A reader is not told that
// eviction happened: LogEntry carries no truncation marker (an apis change),
// and synthesizing a "N lines dropped" line into the stream would be
// indistinguishable from container output, worse than silence. The signal
// instead goes to the operator: the first eviction on a buffer logs one warning
// naming the pod/container (once per buffer — the pump calls write per line and
// a chatty pod would otherwise flood the daemon log).
//
// Concurrency: mu guards lines, bytes, the drop counters and subs; write (the
// supervisor.LogSink, called from the supervisor's pump goroutine) appends under
// mu, evicts under mu, and fans out to each follower under the same lock; a
// follower's cancel removes it under mu. So a follower never receives after
// cancel and the log pump never blocks (a slow follower drops lines rather than
// stalling the pump; the one-shot eviction warning is emitted after the unlock,
// so logging never widens the critical section).
type logBuffer struct {
	log *slog.Logger

	mu    sync.Mutex
	lines []logLine
	// bytes is the accounted retention cost of lines (payload + per-line
	// overhead), kept incrementally so write stays O(evicted) rather than
	// O(retained).
	bytes        int
	droppedLines int
	droppedBytes int
	warned       bool
	subs         map[int]chan logLine
	nextSub      int
}

// logLine is one retained line together with the wall-clock instant runtimed
// received it. The timestamp is what GetLogs evaluates since_time against and
// what it renders for the timestamps option, so it has to be captured at write
// time: the supervisor's LogSink hands over bytes only, and nothing downstream
// can reconstruct when a line was produced once it is sitting in the ring.
type logLine struct {
	at   time.Time
	line []byte
}

const (
	// logBufferMaxBytes is the accounted retention budget for one container's
	// buffer. 256 KiB is chosen against both ends of the trade: a chatty pod
	// emitting ~100-byte lines still keeps ~2.5k lines of tail — far more than
	// the 80-line termination message or a typical `kubectl logs --tail` window
	// — while the node-wide worst case stays affordable: runtimed holds one
	// buffer per container of every pod on the node, so at the upstream default
	// of 110 pods with two containers each the ceiling is ~55 MiB of daemon
	// heap. A 1 MiB cap would make that same ceiling ~220 MiB of unpageable heap
	// in the daemon whose death takes every pod's supervision with it, to buy
	// tail nobody reads.
	logBufferMaxBytes = 256 << 10

	// logLineOverheadBytes is charged per retained line on top of its payload,
	// so a flood of empty lines is bounded too: without it, "0 bytes of
	// payload" would retain unbounded lines, each still costing a logLine entry
	// in the lines slice plus a heap allocation. 72 ≈ the 48-byte logLine entry
	// (a 24-byte slice header plus the 24-byte time.Time stamp GetLogs filters
	// and renders on) plus a minimum-size allocation, which also caps the
	// retained line count at logBufferMaxBytes/72. A retention budget, not an
	// exact heap measure — but it must never understate the entry, or the cap
	// above stops being the ceiling it is documented to be.
	logLineOverheadBytes = 72
)

// newLogBuffer returns an empty bounded buffer. log receives the one-shot
// warning emitted when the buffer first evicts (nil = no warning; the caller
// should pass a logger already tagged with the pod and container).
func newLogBuffer(log *slog.Logger) *logBuffer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &logBuffer{log: log}
}

// logLineCost is a retained line's charge against logBufferMaxBytes.
func logLineCost(line []byte) int { return len(line) + logLineOverheadBytes }

// write appends a line (the supervisor.LogSink), evicts the oldest lines until
// the buffer is back within logBufferMaxBytes, and fans the new line out to live
// followers.
func (l *logBuffer) write(line []byte) {
	// A single line can exceed the whole budget (the pump admits up to 1 MiB).
	// Evicting everything else would still leave the buffer over cap, so an
	// oversized line is stored truncated to its tail — the same bias
	// terminationMessageFromLogs applies, for the same reason (the most recent
	// bytes are the most diagnostic), and with the same rune-boundary rounding
	// so the retained bytes stay valid UTF-8.
	if maxLine := logBufferMaxBytes - logLineOverheadBytes; len(line) > maxLine {
		line = utf8TailBytes(line, maxLine)
	}
	ent := logLine{at: time.Now(), line: make([]byte, len(line))}
	copy(ent.line, line)

	l.mu.Lock()
	l.lines = append(l.lines, ent)
	l.bytes += logLineCost(ent.line)
	// Evict oldest-first. The newest line is never evicted (len > 1): it is
	// admitted pre-truncated to fit, so the loop always terminates within cap.
	for l.bytes > logBufferMaxBytes && len(l.lines) > 1 {
		evicted := l.lines[0]
		l.bytes -= logLineCost(evicted.line)
		l.droppedLines++
		l.droppedBytes += len(evicted.line)
		// Drop the reference before reslicing so the evicted payload is
		// collectable immediately rather than pinned by the backing array.
		l.lines[0] = logLine{}
		l.lines = l.lines[1:]
	}
	warn := l.droppedLines > 0 && !l.warned
	var droppedLines, droppedBytes int
	if warn {
		l.warned = true
		droppedLines, droppedBytes = l.droppedLines, l.droppedBytes
	}
	for _, ch := range l.subs {
		select {
		case ch <- ent: // ent.line is never mutated after this, so sharing it is safe
		default: // slow follower: drop rather than block the supervisor's log pump
		}
	}
	l.mu.Unlock()

	if warn {
		l.log.Warn("container log buffer full; oldest output evicted",
			"cap_bytes", logBufferMaxBytes,
			"dropped_lines", droppedLines, "dropped_bytes", droppedBytes)
	}
}

// utf8TailBytes returns the last n bytes of b, advanced to the next UTF-8 rune
// start so the result never begins with orphan continuation bytes (this only
// ever trims, so the n-byte bound still holds).
func utf8TailBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	b = b[len(b)-n:]
	for len(b) > 0 && !utf8.RuneStart(b[0]) {
		b = b[1:]
	}
	return b
}

// subscribe registers a follower that receives lines written after the call,
// returning the channel and a cancel that deregisters it. The channel is buffered
// and is not closed by cancel (the consumer — Attach — exits on its own ctx /
// the container's Done, never on a channel close), so there is no sender/receiver
// close race.
func (l *logBuffer) subscribe() (<-chan logLine, func()) {
	ch := make(chan logLine, 256)
	l.mu.Lock()
	if l.subs == nil {
		l.subs = make(map[int]chan logLine)
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

// snapshotEntries returns a copy of the buffered lines with their timestamps,
// optionally only the last n (the tail_lines selection, which is POSITIONAL and
// therefore applied before any since_time filtering — the same order the kubelet
// uses when it seeks back n lines in a log file and then drops the ones older
// than --since).
func (l *logBuffer) snapshotEntries(tail int) []logLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	start := 0
	if tail > 0 && tail < len(l.lines) {
		start = len(l.lines) - tail
	}
	out := make([]logLine, 0, len(l.lines)-start)
	for _, ln := range l.lines[start:] {
		c := make([]byte, len(ln.line))
		copy(c, ln.line)
		out = append(out, logLine{at: ln.at, line: c})
	}
	return out
}

// snapshot returns a copy of the buffered lines, optionally only the last n, for
// the callers that need the bytes alone (the attach replay and the termination
// message).
func (l *logBuffer) snapshot(tail int) [][]byte {
	ents := l.snapshotEntries(tail)
	out := make([][]byte, len(ents))
	for i, e := range ents {
		out[i] = e.line
	}
	return out
}
