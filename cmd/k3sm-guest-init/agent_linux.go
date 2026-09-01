//go:build linux

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

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"k3sm.io/runtimed/pkg/guestagent"
	"k3sm.io/runtimed/pkg/guestinit"
)

// cgroup2Root is where the guest mounts the unified cgroup2 hierarchy
// (guestinit.PseudoMounts puts it there). A container's leaf is a directory under
// it named for the container.
const cgroup2Root = "/sys/fs/cgroup"

// vsockBacklog bounds the listen queue. The daemon opens a connection per RPC and
// a pod's control traffic is exec/logs/stats, not throughput, so a deep queue would
// only delay the moment a wedged agent becomes visible.
const vsockBacklog = 16

// guestStatus is the Statusr seam: the guest's own readiness and identity.
//
// Ready flips exactly once, when the boot sequence has gone far enough to answer
// the other RPCs. It is not a health check of the workload — a pod whose container
// crashed still has a ready AGENT, and conflating the two would make a crashlooping
// pod look like an unreachable guest.
type guestStatus struct {
	mu                sync.Mutex
	ready             bool
	guestIP           string
	rosettaRegistered bool
}

func (g *guestStatus) Status(context.Context) guestagent.Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return guestagent.Status{
		Ready:             g.ready,
		GuestIP:           g.guestIP,
		RosettaRegistered: g.rosettaRegistered,
	}
}

func (g *guestStatus) setReady(rosetta bool) {
	g.mu.Lock()
	g.ready = true
	g.rosettaRegistered = rosetta
	g.mu.Unlock()
}

// reaperRunner is the Runner seam: the pod's declared container roster and the
// shutdown verb, both delegated to the plan and the reaper that already own them.
type reaperRunner struct {
	names  []string
	reaper *guestinit.Reaper
}

// Containers returns the roster in declared order — inits first, then mains,
// exactly as guestinit.StartOrder produced it. The order is what the host reports
// back, so a set reordered per call would make a stats table jump between scrapes.
func (r *reaperRunner) Containers() []string {
	out := make([]string, len(r.names))
	copy(out, r.names)
	return out
}

// Stop delegates to the reaper's shutdown state machine, which is the one place
// the term -> grace -> KILL -> sync -> poweroff sequence lives. Reimplementing any
// of it here would give the ordering two homes, and the one that ships would not
// be the one guestinit's tests pin.
func (r *reaperRunner) Stop(ctx context.Context, grace time.Duration) error {
	return r.reaper.Stop(ctx, grace)
}

// cgroupSampler is the Sampler seam: one container's cgroup2 files, read on
// demand.
//
// per-CONTAINER cgroup2 leaves are not yet created by this init (see the package
// doc's "not yet IN this BINARY" list), so on today's guest every Sample reports
// that no leaf exists and the server omits that container from the response. That
// is the honest answer — absence rather than zeros, exactly as guest.proto requires
// — and it is why this type is wired now rather than later: when the leaves land,
// the reader is already here and already correct.
type cgroupSampler struct {
	root string
}

// Sample reads the container's cpu.stat and memory files.
//
// A container with no leaf is guestagent.ErrNotFound, which the server treats as
// "omit". A leaf whose files exist but cannot be parsed is a different error and is
// also omitted — a partially-read sample is not a sample, and reporting the half
// that parsed would put a CPU counter next to a working set of zero.
func (c *cgroupSampler) Sample(_ context.Context, container string) (guestagent.ContainerSample, error) {
	dir := path.Join(c.root, container)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return guestagent.ContainerSample{}, fmt.Errorf("%w: no cgroup2 leaf at %s", guestagent.ErrNotFound, dir)
	}
	cpuStat, err := os.ReadFile(path.Join(dir, "cpu.stat"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read cpu.stat: %w", err)
	}
	usage, err := guestagent.CPUUsageUsec(string(cpuStat))
	if err != nil {
		return guestagent.ContainerSample{}, err
	}
	current, err := os.ReadFile(path.Join(dir, "memory.current"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read memory.current: %w", err)
	}
	memStat, err := os.ReadFile(path.Join(dir, "memory.stat"))
	if err != nil {
		return guestagent.ContainerSample{}, fmt.Errorf("read memory.stat: %w", err)
	}
	ws, err := guestagent.WorkingSet(string(current), string(memStat))
	if err != nil {
		return guestagent.ContainerSample{}, err
	}
	return guestagent.ContainerSample{CPUUsageUsec: usage, MemoryWorkingSetBytes: ws}, nil
}

// procExecer is the Execer seam: fork/exec one command inside a container's
// composed rootfs.
//
// It reuses the same ProcAttr shape the container spawn uses — chroot into the
// container's root, the container's credential and environment, the working
// directory applied after the chroot so it is a path inside the container — because
// an exec that ran under a different identity or a different view of the filesystem
// from the container it claims to be in is not `kubectl exec`, it is a different
// program with the same name.
//
// PID 1 IS the only WAITER. This process does not wait(2) on the child: the reaper
// owns every exit, so the exec registers the child with it under a private name and
// waits on the reaper instead. A second waiter would race it for the status and one
// of the two would get ECHILD.
type procExecer struct {
	plans  map[string]guestinit.ContainerPlan
	reaper *guestinit.Reaper
	log    *slog.Logger

	mu  sync.Mutex
	seq int
}

// Exec runs spec's command in the named container and returns its exit status.
func (e *procExecer) Exec(ctx context.Context, spec guestagent.ExecSpec, io guestagent.ExecIO) (guestagent.ExecResult, error) {
	plan, ok := e.plans[spec.Container]
	if !ok {
		return guestagent.ExecResult{}, fmt.Errorf("%w: %s", guestagent.ErrNotFound, spec.Container)
	}
	// A TTY needs a pty pair allocated in the guest, which this init does not do
	// yet. REFUSING beats running the command without one: a client that asked for
	// a terminal and silently got pipes gets no echo, no job control and no
	// SIGWINCH, and debugs the wrong thing.
	if spec.TTY {
		return guestagent.ExecResult{}, errors.New("this guest cannot allocate a pseudo-terminal for an exec yet; retry without a tty")
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return guestagent.ExecResult{}, fmt.Errorf("exec stdin pipe: %w", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		closeAll(stdinR, stdinW)
		return guestagent.ExecResult{}, fmt.Errorf("exec stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		closeAll(stdinR, stdinW, stdoutR, stdoutW)
		return guestagent.ExecResult{}, fmt.Errorf("exec stderr pipe: %w", err)
	}

	groups := make([]uint32, 0, len(plan.Ident.Groups))
	for _, g := range plan.Ident.Groups {
		groups = append(groups, uint32(g))
	}
	dir := plan.WorkingDir
	if dir == "" {
		dir = "/"
	}
	attr := &syscall.ProcAttr{
		Dir:   dir,
		Env:   plan.Env,
		Files: []uintptr{stdinR.Fd(), stdoutW.Fd(), stderrW.Fd()},
		Sys: &syscall.SysProcAttr{
			Chroot: plan.Root,
			Credential: &syscall.Credential{
				Uid:    uint32(plan.Ident.UID),
				Gid:    uint32(plan.Ident.GID),
				Groups: groups,
			},
			Setsid: true,
		},
	}
	pid, err := syscall.ForkExec(spec.Argv[0], spec.Argv, attr)
	// The child's ends are closed in this process immediately after the fork:
	// holding stdoutW open here would mean the stdout reader never sees EOF, and
	// the exec would appear to hang after the command had already exited.
	closeAll(stdinR, stdoutW, stderrW)
	if err != nil {
		closeAll(stdinW, stdoutR, stderrR)
		return guestagent.ExecResult{}, fmt.Errorf("start %q in %s: %w", spec.Argv[0], spec.Container, err)
	}

	name := e.trackName(spec.Container)
	e.reaper.Track(name, pid)

	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() { defer pumps.Done(); _ = guestagent.CopyChunked(io.Stdout, stdoutR) }()
	go func() { defer pumps.Done(); _ = guestagent.CopyChunked(io.Stderr, stderrR) }()
	if io.Stdin != nil && spec.Stdin {
		go func() {
			defer func() { _ = stdinW.Close() }()
			_ = guestagent.CopyChunked(stdinW, io.Stdin)
		}()
	} else {
		_ = stdinW.Close()
	}

	st, werr := e.reaper.Wait(ctx, name)
	// The pumps are drained before the exit is reported: a client that received the
	// exit frame first and the last of stdout afterwards would see output arrive
	// after the command it came from had finished, which breaks every consumer that
	// treats the exit as end-of-stream.
	pumps.Wait()
	closeAll(stdoutR, stderrR)
	if werr != nil {
		return guestagent.ExecResult{}, fmt.Errorf("wait for the exec in %s: %w", spec.Container, werr)
	}
	if st.Signal != 0 {
		return guestagent.ExecResult{ExitCode: guestagent.ExitCodeForSignal(st.Signal)}, nil
	}
	return guestagent.ExecResult{ExitCode: int32(st.ExitCode)}, nil
}

// trackName gives one exec a reaper key that cannot collide with the container's
// own entry or with a concurrent exec in the same container.
func (e *procExecer) trackName(container string) string {
	e.mu.Lock()
	e.seq++
	n := e.seq
	e.mu.Unlock()
	return fmt.Sprintf("%s#exec-%d", container, n)
}

// closeAll closes every non-nil file, ignoring errors — these are pipe ends on a
// teardown path where there is nothing left to do about a failure.
func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// serveAgent starts the guest/v1 GuestAgent on the pod's vsock port and returns a
// stop func.
//
// It is started after the containers, and that order is deliberate: the agent's
// Health is the host's boot-deadline probe, so an agent answering before the pod
// exists would report a guest that is ready for a pod it has not started.
func serveAgent(podID string, port uint32, deps guestagent.Deps, log *slog.Logger) (func(), error) {
	lis, err := listenVsock(port, vsockBacklog)
	if err != nil {
		return nil, err
	}
	srv := grpc.NewServer()
	guestagent.NewServer(podID, deps).Register(srv)

	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := srv.Serve(lis); err != nil {
			log.Error("the guest agent stopped serving", "err", err)
		}
	}()
	log.Info("serving the guest agent", "vsock_port", port, "api_version", guestagent.APIVersion)

	return func() {
		srv.GracefulStop()
		<-served
	}, nil
}
