package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
}

// containerProc is one running container within a pod.
type containerProc struct {
	name string
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

	profile, err := sandbox.Generate(sp)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			fmt.Errorf("generate sbpl for pod %s: %w", box.GetPodId(), err)
	}

	ip, err := r.network.Setup(ctx, box.GetPodId())
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_INTERNAL,
			fmt.Errorf("network setup pod %s: %w", box.GetPodId(), err)
	}

	p := &pod{
		box:     box,
		profile: profile,
		phase:   runtimev1.PodPhase_POD_PHASE_PENDING,
		podIP:   ip,
	}

	rootfs := box.GetRootfsPath()
	if rootfs == "" {
		rootfs = r.cache.PodRootfs(box.GetPodId())
	}
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_ROOTFS_SETUP,
			fmt.Errorf("create rootfs %s: %w", rootfs, err)
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
	return p, runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, nil
}

// startContainer resolves the container's binary (image path convention),
// ad-hoc signs + gates it, and spawns it under the pod's Seatbelt profile via the
// exec-shim backend. It returns the running containerProc.
func (r *Runtime) startContainer(ctx context.Context, p *pod, rootfs string, c *runtimev1.Container, isInit bool) (*containerProc, runtimev1.FailureReason, error) {
	binPath, argv, err := r.resolveBinary(ctx, p.box, rootfs, c)
	if err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, err
	}

	// Ad-hoc sign on pull, then enforce the signature policy BEFORE exec.
	if err := r.signer.Sign(ctx, binPath); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED,
			fmt.Errorf("ad-hoc sign %s: %w", binPath, err)
	}
	if err := r.signer.Check(ctx, p.box.GetSignaturePolicy(), binPath); err != nil {
		return nil, runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED, err
	}

	// Wrap the command so the spawned process confines itself to the profile and
	// then execs the pod binary, preserving env.
	shimPath, shimArgv, cleanup, err := r.backend.WrapCommand(ctx, p.profile, argv)
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
		logs: logs,
		state: &runtimev1.ContainerStatus{
			Name:  c.GetName(),
			Image: c.GetImage(),
			State: &runtimev1.ContainerState{
				Running: &runtimev1.ContainerStateRunning{StartedAt: nowProto()},
			},
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
	if err != nil {
		term.Reason = "Error"
		term.Message = err.Error()
	} else if code == 0 {
		term.Reason = "Completed"
	} else {
		term.Reason = "Error"
	}
	cp.state.State = &runtimev1.ContainerState{Terminated: term}
	r.recomputePhaseLocked(p)
	p.mu.Unlock()

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

	// Pull + materialize the image into the pod rootfs, then run command/args.
	if _, err := r.puller.Pull(ctx, c.GetImage()); err != nil {
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

// logBuffer is an in-memory ring of a container's combined output for GetLogs.
//
// Concurrency: mu guards lines; write is the LogSink (called from the
// supervisor's pump goroutine).
type logBuffer struct {
	mu    sync.Mutex
	lines [][]byte
}

func newLogBuffer() *logBuffer { return &logBuffer{} }

// write appends a line (the supervisor.LogSink).
func (l *logBuffer) write(line []byte) {
	cp := make([]byte, len(line))
	copy(cp, line)
	l.mu.Lock()
	l.lines = append(l.lines, cp)
	l.mu.Unlock()
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
