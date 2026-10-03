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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/execsession"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Resident shims: every host-process container runs beside its own resident
// shim (the containerd-shim shape; supervisor.NewShimProcess and the
// k3sm-execshim serve mode). The shim leads the pod's process group, holds the
// container's stdio, writes its CRI log, reaps it and persists its exit status,
// so a daemon restart costs the container nothing: AttachPod reconnects to the
// shim (ConnectShim), the exit code reported later is the real one, and Exec,
// Attach and log rotation reach the container through the shim.
//
// What a shim-served Exec means for authorization: the session runs inside the
// pod's confinement (the shim profile) with the container's environment, and
// it is the daemon that serves the node's Exec RPC to the shim, after the
// apiserver's pods/exec RBAC and audit have run. The shim's socket itself
// bypasses both, and every pod profile denies connect(2) to every shim socket
// (sandbox.ShimSubdir), so only a caller already outside every pod's
// confinement, at the daemon's own uid, can reach it.
//
// Upgrade and rollback (a hard cut): a daemon binary bump changes the build
// fingerprint, so the first daemon of a new build re-attaches nothing and the
// node recreates every pod on it, shims included — there is no adoption across
// builds. Rolling back, the older daemon reaps the newer build's shim groups by
// the same (Pgid, StartUnixNano) records it always used; the resident-shim
// fields it does not know are ignored.

// LogStreamLost reasons. RuntimeRestarted is a container spawned without a
// shim whose pipes died with the previous daemon. ShimCrashed is a container
// whose shim died under it: its output after that is not captured and its exit
// status is unknowable. ShimUnresponsive is a live shim that did not answer two
// Status calls when the daemon reconnected.
const (
	logStreamLostRuntimeRestarted = "RuntimeRestarted"
	logStreamLostShimCrashed      = "ShimCrashed"
	logStreamLostShimUnresponsive = "ShimUnresponsive"
)

// logStreamLostMessages is the condition message per reason.
var logStreamLostMessages = map[string]string{
	logStreamLostRuntimeRestarted: logStreamLostMarker,
	logStreamLostShimCrashed:      "k3sm: a container's resident shim exited; its later output is not captured and its exit status is unknown",
	logStreamLostShimUnresponsive: "k3sm: a container's resident shim did not answer after a daemon restart; its output and exit status are not followed",
}

// errShimLost refuses Exec on a container whose shim crashed or does not answer:
// the session would have to enter an environment only the shim holds.
var errShimLost = errors.New("exec is not supported in a container whose resident shim exited or does not answer")

// shimDirIDBytes is the random part of a shim dir name (8 hex characters).
const shimDirIDBytes = 4

// hostsResidentShim reports whether backend's helper can stay resident as a
// container's shim. Only the production exec-shim helper can: it is the binary
// that implements the serve mode. Any other Backend (the test fakes) spawns the
// container directly with daemon-held pipes, which do not survive a restart.
func hostsResidentShim(backend sandbox.Backend) bool {
	_, ok := backend.(*sandbox.ExecShimBackend)
	return ok
}

// shimRoot is this daemon's resident-shim root, <Root>/run/shim.
func (r *Runtime) shimRoot() string { return sandbox.ShimRoot(r.cfg.Root) }

// allocShimDir creates a fresh, empty shim dir under shimRoot.
func (r *Runtime) allocShimDir() (string, error) {
	root := r.shimRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create the shim root %s: %w", root, err)
	}
	for range 8 {
		b := make([]byte, shimDirIDBytes)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("shim dir id: %w", err)
		}
		dir := filepath.Join(root, hex.EncodeToString(b))
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create shim dir %s: %w", dir, err)
		}
	}
	return "", errors.New("could not allocate a unique shim dir")
}

// allocShimDirs gives every container of box its shim dir, at create time and
// before the profile is compiled, so a container's dir is fixed for the pod's
// life: RestartContainer and StartContainer re-use it (containerShimDir), and
// the reap record names it. On error the dirs already made are removed.
func (r *Runtime) allocShimDirs(box *runtimev1.PodBox) (map[string]string, error) {
	dirs := make(map[string]string)
	for _, c := range append(append([]*runtimev1.Container{}, box.GetInitContainers()...), box.GetContainers()...) {
		dir, err := r.allocShimDir()
		if err != nil {
			removeShimDirs(dirs)
			return nil, err
		}
		dirs[c.GetName()] = dir
	}
	return dirs, nil
}

// containerShimDir returns name's shim dir, allocating one for a container the
// create did not know (an ephemeral container).
func (r *Runtime) containerShimDir(p *pod, name string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if dir, ok := p.shimDirs[name]; ok {
		return dir, nil
	}
	dir, err := r.allocShimDir()
	if err != nil {
		return "", err
	}
	if p.shimDirs == nil {
		p.shimDirs = make(map[string]string)
	}
	p.shimDirs[name] = dir
	return dir, nil
}

// removeShimDirs removes shim dirs (best-effort): at pod teardown, after every
// shim is gone, and on a failed create.
func removeShimDirs(dirs map[string]string) {
	for _, dir := range dirs {
		_ = os.RemoveAll(dir)
	}
}

// shimLaunchPlan is what startContainer hands spawnBesideShim.
type shimLaunchPlan struct {
	podID, container string
	shimPath         string
	shimArgv         []string // WrapCommand's argv: [shim, launch, <tokens>...]
	env, execEnv     []string
	workingDir       string
	logPath          string
}

// spawnBesideShim builds the Process of a container that runs beside a resident
// shim: it creates the container's log file (the shim opens it for append),
// renders the shim profile — the pod profile plus the shim grant, written beside
// the staged pod profile so cleanup and the startup sweep remove both — clears
// any earlier instance's exit record from the dir, and returns the Process plus
// the cleanup extended to the shim profile.
//
// The shim is spawned with an EMPTY environment: the pod environment, DYLD
// interposes included, reaches only the container, over the shim's stdin.
func (r *Runtime) spawnBesideShim(p *pod, plan shimLaunchPlan, dir string, cleanup func() error) (*supervisor.Process, func() error, error) {
	w, err := crilog.Open(plan.logPath)
	if err != nil {
		return nil, cleanup, fmt.Errorf("create container log %s: %w", plan.logPath, err)
	}
	_ = w.Close()
	shimText, err := sandbox.ShimProfile(p.profile, sandbox.ShimGrant{Dir: dir, LogPath: plan.logPath})
	if err != nil {
		return nil, cleanup, err
	}
	if len(plan.shimArgv) < 3 {
		return nil, cleanup, fmt.Errorf("unexpected exec-shim argv %q", plan.shimArgv)
	}
	launch := plan.shimArgv[2:]
	podProfile := launch[5]
	shimProfile := podProfile + ".shim.sb"
	if err := os.WriteFile(shimProfile, []byte(shimText), 0o600); err != nil {
		return nil, cleanup, fmt.Errorf("stage the shim profile: %w", err)
	}
	both := func() error {
		_ = os.Remove(shimProfile)
		return cleanup()
	}
	if err := supervisor.RemoveExitRecord(dir); err != nil {
		return nil, both, err
	}
	proc := supervisor.NewShimProcess(r.spawner, r.waiter,
		supervisor.SpawnSpec{Path: plan.shimPath, Argv: []string{plan.shimPath, supervisor.ShimModeServe}, Env: []string{}, Dir: plan.workingDir},
		supervisor.ShimLaunch{
			Spec: supervisor.ShimSpec{
				Container:   plan.container,
				Dir:         dir,
				LogPath:     plan.logPath,
				ShimProfile: shimProfile,
				Launch:      launch,
				Env:         plan.env,
				ExecEnv:     plan.execEnv,
				ExecDir:     plan.workingDir,
			},
			Dialer:    r.shimDialer,
			ProcStart: r.procStart,
			Kill:      r.signalGroup,
		})
	return proc, both, nil
}

// noteLogStreamLost records the pod's log-stream-lost condition, keeping the
// first reason. Caller holds p.mu.
func noteLogStreamLostLocked(p *pod, reason string, at time.Time) {
	if p.logStreamLostReason != "" {
		return
	}
	p.logStreamLostReason = reason
	p.logStreamLostAt = at
}

// shimCrashed handles a live container whose shim died without an exit record
// (supervisor.ErrShimCrashed): when the container itself is still alive under
// its exact identity it is watched on (supervisor.AdoptChild) with no output,
// no exit status and no exec, and the pod says so (ShimCrashed). It reports
// whether the container was taken over; false means it is gone and the caller
// records the termination.
func (r *Runtime) shimCrashed(ctx context.Context, p *pod, cp *containerProc) bool {
	child, start := cp.proc.ChildPID(), cp.proc.ChildStartUnixNano()
	pgid := cp.proc.PID()
	r.log.Warn("a container's resident shim exited without recording an exit status",
		"pod", p.box.GetPodId(), "container", cp.name, "shim", pgid, "container_pid", child)
	p.mu.Lock()
	noteLogStreamLostLocked(p, logStreamLostShimCrashed, time.Now())
	p.mu.Unlock()
	if child == pgid || start == 0 {
		return false
	}
	if got, ok := r.procStart(child); !ok || got != start {
		return false
	}
	proc, err := supervisor.AdoptChild(p.supCtx, r.adoptWaiter, pgid, child)
	if err != nil {
		return false
	}
	p.mu.Lock()
	next := *cp
	next.proc = proc
	next.execRefusal = errShimLost
	replaced := false
	for i, c := range p.containers {
		if c == cp {
			p.containers[i] = &next
			replaced = true
		}
	}
	p.mu.Unlock()
	if !replaced {
		return false
	}
	go r.watchContainerExit(ctx, p, &next, nil)
	r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
	return true
}

// execViaShim proxies an Exec on a shim-backed container to the shim's
// ContainerShim.Exec. A non-tty session is a frame-for-frame proxy. A tty
// session gets a pty this daemon allocates (a confined shim cannot): the slave
// is handed to the shim, the master stays here, and the session's bytes and
// resizes move between the client and the master directly while the shim stream
// carries the exit.
func (r *Runtime) execViaShim(stream runtimev1.Runtime_ExecServer, conn *supervisor.ShimConn, cp *containerProc, first *runtimev1.ExecRequest) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	req := cloneExecRequest(first, cp.name)
	if !first.GetTty() {
		sc, err := conn.Exec(ctx)
		if err != nil {
			return status.Errorf(codes.Unavailable, "exec: reach the container's shim: %v", err)
		}
		if err := sc.Send(req); err != nil {
			return status.Errorf(codes.Unavailable, "exec: %v", err)
		}
		go func() {
			for {
				in, err := stream.Recv()
				if err != nil {
					_ = sc.CloseSend()
					return
				}
				if err := sc.Send(in); err != nil {
					return
				}
			}
		}()
		for {
			resp, err := sc.Recv()
			if err != nil {
				return status.Errorf(codes.Unavailable, "exec: the shim ended the session: %v", err)
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
			if resp.GetExit() != nil {
				return nil
			}
		}
	}

	master, slave, err := execsession.OpenPTY()
	if err != nil {
		return status.Errorf(codes.Internal, "exec: allocate tty: %v", err)
	}
	defer func() { _ = master.Close() }()
	sc, err := conn.ExecTTY(ctx, slave)
	_ = slave.Close() // the shim holds its own copy now
	if err != nil {
		return status.Errorf(codes.Unavailable, "exec: reach the container's shim: %v", err)
	}
	if err := sc.Send(req); err != nil {
		return status.Errorf(codes.Unavailable, "exec: %v", err)
	}
	var sendMu sync.Mutex
	send := func(resp *runtimev1.ExecResponse) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(resp)
	}
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		execsession.PumpReader(master, func(b []byte) error { return send(&runtimev1.ExecResponse{Stdout: b}) })
	}()
	go func() {
		for {
			in, err := stream.Recv()
			if err != nil {
				_ = sc.CloseSend()
				return
			}
			if d := in.GetStdinData(); len(d) > 0 && first.GetStdin() {
				if _, err := master.Write(d); err != nil {
					return
				}
			}
			if rs := in.GetResize(); rs != nil {
				_ = execsession.SetWinsize(master, uint16(rs.GetWidth()), uint16(rs.GetHeight()))
			}
		}
	}()
	for {
		resp, err := sc.Recv()
		if errors.Is(err, io.EOF) || err != nil {
			return status.Errorf(codes.Unavailable, "exec: the shim ended the session: %v", err)
		}
		if resp.GetExit() == nil {
			continue
		}
		// The session's last output is still in the master: drain it (the read
		// ends once the slave's last holder is gone), bounded so a grandchild
		// holding the terminal cannot hold the exit.
		select {
		case <-pumped:
		case <-time.After(time.Second):
		}
		return send(resp)
	}
}

// cloneExecRequest is first with its container stated, the name the shim asserts.
func cloneExecRequest(first *runtimev1.ExecRequest, container string) *runtimev1.ExecRequest {
	return &runtimev1.ExecRequest{
		PodId:     first.GetPodId(),
		Container: container,
		Command:   first.GetCommand(),
		Tty:       first.GetTty(),
		Stdin:     first.GetStdin(),
		StdinData: first.GetStdinData(),
		Resize:    first.GetResize(),
	}
}

// attachViaShim follows a shim-backed container's live output through the shim's
// Follow stream until the container exits.
func (r *Runtime) attachViaShim(stream runtimev1.Runtime_AttachServer, conn *supervisor.ShimConn) error {
	fs, err := conn.Follow(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unavailable, "attach: reach the container's shim: %v", err)
	}
	for {
		resp, err := fs.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return status.Errorf(codes.Unavailable, "attach: %v", err)
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
		if resp.GetExit() != nil {
			return nil
		}
	}
}

// reopenViaShim is the rotation half for a shim-backed container: the node has
// renamed the file, this daemon creates the new empty one at the path (owned as
// every log file is), and the shim reopens it — it may append to that one file
// and create nothing.
func reopenViaShim(ctx context.Context, conn *supervisor.ShimConn, logPath string) error {
	// crilog.Open is the one place a log file's flags and mode live.
	w, err := crilog.Open(logPath)
	if err != nil {
		return fmt.Errorf("create the rotated log: %w", err)
	}
	_ = w.Close()
	return conn.ReopenLog(ctx)
}
