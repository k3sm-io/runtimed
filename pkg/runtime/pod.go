package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	// spec is the container's PodBox definition, retained so Exec can re-resolve
	// its securityContext/env/workingDir to re-enter the same confinement domain.
	spec *runtimev1.Container
	proc *supervisor.Process
	logs *logBuffer
	// state is updated as the container runs/terminates.
	state *runtimev1.ContainerStatus
}

// createPod is the CreatePod spine (called with no lock held). It materializes
// each container rootfs, ad-hoc signs, gates the signature policy BEFORE exec,
// generates+validates the SBPL, and spawns each container through the exec-shim
// backend with DYLD_INSERT_LIBRARIES carried through. It returns the started pod
// or a typed failure.
func (r *Runtime) createPod(ctx context.Context, box *runtimev1.PodBox) (*pod, runtimev1.FailureReason, error) {
	// Fail closed: the sandbox backend MUST be available, else refuse the pod
	// (never run unconfined).
	if !r.backend.Available() {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("sandbox backend %q unavailable: refusing to start pod unconfined", r.backend.Name())
	}

	sp := box.GetSandboxProfile()
	if sp == nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			fmt.Errorf("pod %s: sandbox_profile is required", box.GetPodId())
	}

	ip, err := r.network.Setup(ctx, box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			fmt.Errorf("network setup pod %s: %w", box.GetPodId(), err)
	}

	rootfs := box.GetRootfsPath()
	if rootfs == "" {
		rootfs = r.cache.PodRootfs(box.GetPodId())
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("create rootfs %s: %w", rootfs, err)
	}

	// Materialize volume sources (configMap / secret / emptyDir / downwardAPI /
	// projected) into the pod data volume. Secrets + the projected SA-token come
	// back as credential paths that get the SBPL read-only sub-scope below. (M2.2)
	var credPaths []string
	if len(box.GetVolumes()) > 0 {
		layout, merr := mount.Materialize(ctx, box, rootfs, ip, r.resolver)
		if merr != nil {
			return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
				fmt.Errorf("materialize volumes for pod %s: %w", box.GetPodId(), merr)
		}
		credPaths = layout.CredentialPaths()
	}

	// Generate the SBPL AFTER materialization so the credential mounts get the
	// read-only sub-scope. The generator validates any extra paths against the
	// protected deny-set and emits the protected denies last (last-match-wins).
	profile, err := sandbox.Generate(sp, sandbox.GenerateOptions{ReadOnlyPaths: credPaths})
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

	p := &pod{
		box:     box,
		profile: profile,
		phase:   runtimev1.PodPhase_POD_PHASE_PENDING,
		podIP:   ip,
	}

	// init_containers run first, sequentially, each to completion; then the main
	// containers start. M1 starts all main containers and tracks them; the
	// per-container sequencing of init containers is honored by starting+waiting
	// them in order.
	for _, c := range box.GetInitContainers() {
		cp, reason, err := r.startContainer(ctx, p, rootfs, c, true)
		if err != nil {
			return nil, reason, err
		}
		code, _, werr := cp.proc.Wait(ctx)
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
		cp, reason, err := r.startContainer(ctx, p, rootfs, c, false)
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
	// state, clean up the staged profile, and publish a status update. Lifetime
	// is bounded by the process exit.
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

// recomputePhaseLocked updates the pod phase from its containers' states. Caller
// holds p.mu.
func (r *Runtime) recomputePhaseLocked(p *pod) {
	if len(p.containers) == 0 {
		return
	}
	allTerminated := true
	anyFailed := false
	for _, cp := range p.containers {
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

// podDir returns the per-pod directory under the cache root.
func (r *Runtime) podDir(podID string) string {
	return filepath.Dir(r.cache.PodRootfs(podID))
}

// removePodDir deletes a pod's on-disk dir (best-effort, on delete).
func (r *Runtime) removePodDir(podID string) error {
	dir := r.podDir(podID)
	if dir == "" || dir == "/" || !strings.HasPrefix(dir, r.cfg.Root) {
		return nil
	}
	return os.RemoveAll(dir)
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
