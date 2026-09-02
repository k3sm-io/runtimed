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
	"fmt"
	"io"
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

// setGuestIP records the address the guest's DHCP client leased.
//
// It is a SETTER and not a constructor argument because guest_ip is a LEASE, not
// an identity: guest.proto calls the field "the single live-address authority"
// and says the host re-reads it rather than caching it, so the guest must be able
// to report a NEW address without anything being rebuilt. Status already re-reads
// under the mutex on every Health call, so a future renewal loop only has to call
// this again.
//
// no RENEWAL LOOP exists yet, and that ceiling is recorded rather than implied:
// this is called exactly once, at boot. The S5 spike measured the lease stable
// across restarts given the host's deterministic MAC, so a v0.1 guest that never
// renews keeps its address for its own lifetime — but a lease whose duration
// expires mid-life would not be re-acquired, and the host would keep dialing an
// address the segment has reassigned.
func (g *guestStatus) setGuestIP(ip string) {
	g.mu.Lock()
	g.guestIP = ip
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
// The leaf it reads is created by spawn and joined by the kernel at fork
// (guestagent.CreateLeaf + SysProcAttr.UseCgroupFD), and the memory files exist
// because the boot delegated the memory controller to the hierarchy root's
// children first (guestagent.EnableSubtreeControllers). All three are best effort:
// a kernel missing a controller leaves the container unmetered rather than
// unstarted, so a Sample that finds nothing is still a normal outcome and is still
// reported as ABSENCE rather than as zeros — a zero working set is
// indistinguishable from an idle container.
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
//
// A TTY exec is served rather than refused: the pair is allocated from the
// container's own devpts before the fork. See Exec.
type procExecer struct {
	plans  map[string]guestinit.ContainerPlan
	reaper *guestinit.Reaper
	log    *slog.Logger

	mu  sync.Mutex
	seq int
}

// Exec runs spec's command in the named container and returns its exit status.
//
// # The terminal, when one is asked for
//
// A tty exec allocates its pty pair BEFORE the fork, and from the TARGET
// CONTAINER's own devpts instance rather than the guest's — guestinit.PTYOrigin
// states why that distinction is not cosmetic. Allocating first is what makes it
// survive the chroot: the child inherits DESCRIPTORS, not paths, so by the time
// its root changes the terminal is already open. Nothing inside the container
// could have opened it instead, since the exec'd process is the container's and
// has no privilege to allocate one.
//
// Every other choice — which descriptor becomes which of the child's three, the
// Setsid/Setctty shape, how many pumps run and onto which client stream, what is
// closed at the fork and what only after the reaper — belongs to
// guestinit.PlanExecIO, so it is decided in a pure function darwin's `go test
// -race` actually runs. This file only performs it.
func (e *procExecer) Exec(ctx context.Context, spec guestagent.ExecSpec, plumbing guestagent.ExecIO) (guestagent.ExecResult, error) {
	plan, ok := e.plans[spec.Container]
	if !ok {
		return guestagent.ExecResult{}, fmt.Errorf("%w: %s", guestagent.ErrNotFound, spec.Container)
	}

	// argv[0] is resolved execvp-style inside the TARGET CONTAINER's root, using
	// that container's own PATH — the same resolution spawn does for a container's
	// entrypoint, and for the same reason: ForkExec below is execve and does no
	// PATH search, so `kubectl exec -- sh` failed with ENOENT on every image.
	//
	// plan.Root, never the guest's own /: an exec claiming to run in a container
	// must resolve against that container's filesystem, or it would find the
	// guest init's binaries and run a different program under the container's
	// name. plan.Env is that container's environment, so the PATH searched is the
	// one the container itself would use.
	prog, err := guestinit.ResolveProgram(plan.Root, plan.WorkingDir, spec.Argv[0], guestinit.PathFromEnv(plan.Env))
	if err != nil {
		return guestagent.ExecResult{}, err
	}

	// A client that asked to keep stdin open but supplied no reader gets the
	// no-stdin wiring, whose plan closes the write end rather than leaving a
	// command that reads stdin blocked on a pipe nobody will ever write to.
	wiring := guestinit.PlanExecIO(spec.TTY, spec.Stdin && plumbing.Stdin != nil)
	fds, err := e.openExecFDs(wiring, plan)
	if err != nil {
		return guestagent.ExecResult{}, err
	}
	for _, id := range wiring.Open {
		if fds.file(id) == nil {
			fds.closeAll()
			return guestagent.ExecResult{}, fmt.Errorf("the exec wiring asks for the %s descriptor, which this executor does not open", id)
		}
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
		Dir: dir,
		Env: plan.Env,
		Files: []uintptr{
			fds.raw(wiring.ChildFiles[0]),
			fds.raw(wiring.ChildFiles[1]),
			fds.raw(wiring.ChildFiles[2]),
		},
		Sys: &syscall.SysProcAttr{
			Chroot: plan.Root,
			Credential: &syscall.Credential{
				Uid:    uint32(plan.Ident.UID),
				Gid:    uint32(plan.Ident.GID),
				Groups: groups,
			},
			Setsid:  wiring.Setsid,
			Setctty: wiring.Setctty,
			// Ctty indexes the CHILD's descriptors: Linux performs the TIOCSCTTY
			// ioctl after the fork's descriptor dance, not before it.
			Ctty: wiring.Ctty,
		},
	}
	pid, err := syscall.ForkExec(prog, spec.Argv, attr)
	// The child's ends are closed in this process immediately after the fork:
	// holding a pipe's write end open would mean its reader never sees EOF, and
	// holding the pty slave open would mean the master never sees EIO — either
	// way the exec appears to hang after the command has already exited.
	fds.close(wiring.CloseAfterFork...)
	if err != nil {
		fds.closeAll()
		return guestagent.ExecResult{}, fmt.Errorf("start %q (resolved to %s) in %s: %w", spec.Argv[0], prog, spec.Container, err)
	}

	name := e.trackName(spec.Container)
	e.reaper.Track(name, pid)

	var pumps sync.WaitGroup
	for _, p := range wiring.Outputs {
		src, sink := fds.file(p.Source), plumbing.Stdout
		if p.Stream == guestinit.StreamStderr {
			sink = plumbing.Stderr
		}
		var reader io.Reader = src
		if p.TTYEOF {
			// A pty master never reports EOF; it reports EIO once the last
			// descriptor on the slave side is gone. Without this every
			// successful tty exec would end on a read error.
			reader = guestinit.TTYReader(src)
		}
		pumps.Add(1)
		go func() { defer pumps.Done(); _ = guestagent.CopyChunked(sink, reader) }()
	}

	if sink := fds.file(wiring.StdinSink); sink != nil {
		closeOnEOF := wiring.CloseStdinSinkOnEOF
		go func() {
			// A pty master is deliberately NOT closed here: closing it hangs the
			// child's session up rather than giving it EOF. On a tty, ^D is what
			// the client sends and the line discipline turns it into the
			// zero-length read the command is waiting for.
			if closeOnEOF {
				defer func() { _ = sink.Close() }()
			}
			_ = guestagent.CopyChunked(sink, plumbing.Stdin)
		}()
	}

	if wiring.Resize && plumbing.Resize != nil {
		master := fds.file(guestinit.FDPTYMaster)
		go func() {
			// The goroutine ends when the server closes the resize channel,
			// which it does when the client's stream ends.
			err := guestinit.PumpResize(
				func() (guestinit.WinSize, bool) {
					sz, ok := <-plumbing.Resize
					return guestinit.WinSize{Rows: uint16(sz.Height), Cols: uint16(sz.Width)}, ok
				},
				func(sz guestinit.WinSize) error { return guestinit.SetWinsize(master, sz) },
			)
			if err != nil {
				// EBADF once the master has been closed at teardown is this
				// goroutine's ordinary end, not an operator's problem.
				e.log.Debug("the exec terminal stopped accepting resizes",
					"container", spec.Container, "err", err)
			}
		}()
	}

	st, werr := e.reaper.Wait(ctx, name)
	// The pumps are drained before the exit is reported: a client that received the
	// exit frame first and the last of stdout afterwards would see output arrive
	// after the command it came from had finished, which breaks every consumer that
	// treats the exit as end-of-stream.
	pumps.Wait()
	fds.close(wiring.CloseAfterWait...)
	if werr != nil {
		return guestagent.ExecResult{}, fmt.Errorf("wait for the exec in %s: %w", spec.Container, werr)
	}
	if st.Signal != 0 {
		return guestagent.ExecResult{ExitCode: guestagent.ExitCodeForSignal(st.Signal)}, nil
	}
	return guestagent.ExecResult{ExitCode: int32(st.ExitCode)}, nil
}

// openExecFDs creates the descriptors one exec's wiring plan names.
//
// On any failure it closes whatever it had already opened: a half-built exec
// that leaked a pipe end would leave PID 1 holding a descriptor no reader will
// ever drain, for the life of the pod.
func (e *procExecer) openExecFDs(w guestinit.ExecWiring, plan guestinit.ContainerPlan) (*execFDs, error) {
	fds := newExecFDs()
	if !w.TTY {
		for _, pair := range [][2]guestinit.ExecFD{
			{guestinit.FDStdinRead, guestinit.FDStdinWrite},
			{guestinit.FDStdoutRead, guestinit.FDStdoutWrite},
			{guestinit.FDStderrRead, guestinit.FDStderrWrite},
		} {
			r, wr, err := os.Pipe()
			if err != nil {
				fds.closeAll()
				return nil, fmt.Errorf("exec %s pipe: %w", pair[0], err)
			}
			fds.put(pair[0], r)
			fds.put(pair[1], wr)
		}
		return fds, nil
	}

	origin := guestinit.ExecPTYOrigin(plan)
	ptmx, pts, err := resolvePTYOrigin(origin)
	if err != nil {
		return nil, err
	}
	if !origin.Container {
		// Degraded, and said out loud. The exec still gets a working terminal
		// through its inherited descriptors, but the slave's index belongs to
		// the guest's devpts instance, so ttyname(3) — and therefore `tty`, ps's
		// TTY column, and anything that reopens its own terminal by name —
		// resolves to the wrong node or to none inside the container.
		e.log.Warn("this container has no private devpts, so its exec terminal is allocated from the guest's instance",
			"container", plan.Name, "ptmx", ptmx)
	}
	master, slave, err := guestinit.OpenPTY(ptmx, pts)
	if err != nil {
		return nil, fmt.Errorf("allocate a terminal for an exec in %s: %w", plan.Name, err)
	}
	fds.put(guestinit.FDPTYMaster, master)
	fds.put(guestinit.FDPTYSlave, slave)
	if err := guestinit.SetWinsize(master, w.InitialSize); err != nil {
		fds.closeAll()
		return nil, fmt.Errorf("size the terminal for an exec in %s: %w", plan.Name, err)
	}
	if err := guestinit.ChownTTY(slave, int(plan.Ident.UID), int(plan.Ident.GID)); err != nil {
		// Not fatal: the command runs on the descriptors it inherits either way.
		// What it loses is the ability to REOPEN its terminal by name, which is
		// what /dev/tty, `script`, and every prompt that bypasses stdin do.
		e.log.Warn("could not give the exec terminal to the container identity; reopening /dev/tty inside it will fail",
			"container", plan.Name, "uid", plan.Ident.UID, "gid", plan.Ident.GID, "err", err)
	}
	return fds, nil
}

// resolvePTYOrigin turns an origin's container-absolute paths into guest paths.
//
// The resolution is CHROOT-semantic (guestinit.ResolveTarget) rather than a
// path join, for the reason every container mount target is: the IMAGE decides
// what is a symlink, and an image shipping /dev as an absolute symlink would
// otherwise have it resolved against the GUEST's root — handing this exec the
// guest's own multiplexer while the plan believed it was using the container's.
func resolvePTYOrigin(o guestinit.PTYOrigin) (ptmx, pts string, err error) {
	if o.Root == "" {
		return o.Ptmx, o.Pts, nil
	}
	if ptmx, err = guestinit.ResolveTarget(o.Root, o.Ptmx); err != nil {
		return "", "", fmt.Errorf("resolve %s inside %s: %w", o.Ptmx, o.Root, err)
	}
	if pts, err = guestinit.ResolveTarget(o.Root, o.Pts); err != nil {
		return "", "", fmt.Errorf("resolve %s inside %s: %w", o.Pts, o.Root, err)
	}
	return ptmx, pts, nil
}

// execFDs holds one exec's open descriptors under the names its wiring plan
// gives them.
//
// It is NOT concurrency-safe and does not need to be: every put, close and
// lookup happens on the goroutine running the exec, and the pumps that outlive
// that goroutine capture the *os.File they need before any of them start.
type execFDs struct {
	m map[guestinit.ExecFD]*os.File
}

// newExecFDs returns an empty descriptor set.
func newExecFDs() *execFDs {
	return &execFDs{m: make(map[guestinit.ExecFD]*os.File, 6)}
}

// put records a descriptor under the plan's name for it.
func (f *execFDs) put(id guestinit.ExecFD, file *os.File) { f.m[id] = file }

// file returns the descriptor, or nil when the plan does not use it.
func (f *execFDs) file(id guestinit.ExecFD) *os.File { return f.m[id] }

// raw returns the descriptor number for ProcAttr.Files.
func (f *execFDs) raw(id guestinit.ExecFD) uintptr {
	if file := f.m[id]; file != nil {
		return file.Fd()
	}
	// Unreachable: Exec checks every descriptor the plan names before forking.
	// A wrong number here would give the child a descriptor belonging to
	// something else entirely, so it fails the exec rather than guessing.
	return ^uintptr(0)
}

// close closes the named descriptors and forgets them, so a later closeAll
// cannot close one twice.
func (f *execFDs) close(ids ...guestinit.ExecFD) {
	for _, id := range ids {
		if file := f.m[id]; file != nil {
			_ = file.Close()
			delete(f.m, id)
		}
	}
}

// closeAll closes everything still held. It is the failure path: after a
// successful fork the plan's two close sets own the descriptors instead.
func (f *execFDs) closeAll() {
	for id := range f.m {
		f.close(id)
	}
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
