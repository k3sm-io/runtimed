//go:build darwin && cgo

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

package execshim

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	shimv1 "k3sm.io/apis/shim/v1"

	"k3sm.io/runtimed/pkg/crilog"
	"k3sm.io/runtimed/pkg/supervisor"
)

// ringBytes bounds each output stream's backlog between the container's pipe and
// the log writer (see ring).
const ringBytes = 1 << 20

// drainGrace bounds how long the shim waits, after the container exited, for
// both pipes to reach EOF: a forked grandchild that inherited the container's
// stdout can hold a pipe open forever, and the exit record must not wait on it.
const drainGrace = 5 * time.Second

// stopGrace bounds how long an exec session still open when the container
// exited may keep the shim serving after the exit record is written.
const stopGrace = 2 * time.Second

// Serve is the resident shim (supervisor.ShimModeServe). It returns the process
// exit code.
//
// # Confinement order
//
// A second sandbox_apply in a process that already applied one fails on macOS,
// so the shim cannot confine itself first and the container second. It starts
// UNCONFINED, at the daemon's uid, exactly like the launch sequence before its
// own sandbox_apply, and in this order:
//
//  1. reads its launch spec from stdin (supervisor.ShimSpec — the pod
//     environment, Secret-derived variables and DYLD interposes included, read
//     once and never written anywhere) and its shim profile text;
//  2. checks both socket paths fit sun_path (a typed exit,
//     supervisor.ShimExitSunPath, on overflow), then binds and listens;
//  3. opens the container's CRI log for append and its exit record for
//     writing, and keeps both descriptors: after confinement the shim opens no
//     writable path at all (a rotated log arrives as a handed-over descriptor);
//  4. posix_spawns the container: itself in launch mode, marked
//     pcontrol-KILL, in the shim's own process group and session
//     (SpawnSpec.KeepGroup), with a pipe per output stream and the daemon's
//     exec-sync pipe relayed as fd 3. The launch child runs the launch sequence
//     verbatim — rlimits, drop, qos, sandbox_apply of the POD profile, marked
//     exec — so the container runs under exactly the pod profile;
//  5. on a root daemon whose spec carries a drop, chowns its shim dir and the
//     log to the pod credential and drops to it (no drop ever happens in the
//     shipped unprivileged posture);
//  6. sandbox_applies its SHIM profile: the pod profile plus the shim grant
//     (sandbox.ShimProfile), which writes nothing: reading its shim dir,
//     ioctls on a tty it was handed, and signals to its own children and group;
//  7. serves, and redirects its stdout and stderr to /dev/null: the daemon's
//     diagnostics pipe reaching EOF is the readiness signal.
//
// A failure at any step writes one line to stderr (the daemon reports it) and
// exits; a failure after step 4 SIGKILLs the container first, so nothing runs
// that the shim could not confine.
//
// What an exec session inherits: the shim forks it, so it runs under the shim
// profile — the pod profile plus that grant. Because the grant writes nothing, a
// session can neither forge the exit record nor rewrite the log. A shim-served Exec therefore reaches the pod's
// confinement without the apiserver's pods/exec RBAC or audit only for a caller
// that can already reach the shim's socket, which every pod profile denies.
//
// The shim exits after the container has, once both output streams drained (or
// drainGrace passed) and the exit record is persisted.
func Serve() int {
	// Before anything else: a SIGTERM delivered during bring-up must be held for
	// the container (run forwards it), never kill the shim by default action.
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	spec, err := supervisor.DecodeShimSpec(os.Stdin)
	if err != nil {
		return failf(supervisor.ShimExitSpec, "read launch spec: %v", err)
	}
	if err := redirectNull(0); err != nil {
		return failf(supervisor.ShimExitSetup, "stdin: %v", err)
	}
	s, code, err := bringUp(spec)
	if err != nil {
		return failf(code, "%v", err)
	}
	return s.run(sigs)
}

// failf reports a bring-up failure on stderr, which the daemon reads, and
// returns code.
func failf(code int, format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "k3sm-execshim serve: "+format+"\n", args...)
	return code
}

// redirectNull points descriptor fd at /dev/null.
func redirectNull(fd int) error {
	null, err := unix.Open(os.DevNull, unix.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer func() { _ = unix.Close(null) }()
	return unix.Dup2(null, fd)
}

// listen binds path as a unix socket. A stale socket left by a previous
// instance in the same dir is removed first; the listener does not unlink on
// close, because a confined shim may not.
func listen(path string) (*net.UnixListener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(false)
	return ln, nil
}

// bringUp runs steps 2-7 of Serve's order and returns the serving shim, or the
// exit code and error of the step that failed.
func bringUp(spec supervisor.ShimSpec) (*shimServer, int, error) {
	sock, ptySock := supervisor.ShimSockPath(spec.Dir), supervisor.ShimPtySockPath(spec.Dir)
	for _, p := range []string{sock, ptySock} {
		if err := supervisor.CheckSunPath(p); err != nil {
			return nil, supervisor.ShimExitSunPath, err
		}
	}
	shimProfile, err := os.ReadFile(spec.ShimProfile)
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("read shim profile: %w", err)
	}
	cred, err := supervisor.ParseCredential(spec.Launch[0], spec.Launch[1], spec.Launch[2])
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("parse credential: %w", err)
	}
	ln, err := listen(sock)
	if err != nil {
		return nil, supervisor.ShimExitSetup, err
	}
	ptyLn, err := listen(ptySock)
	if err != nil {
		return nil, supervisor.ShimExitSetup, err
	}
	logw, err := crilog.Open(spec.LogPath)
	if err != nil {
		return nil, supervisor.ShimExitSetup, err
	}
	exitFile, err := supervisor.OpenExitRecord(spec.Dir)
	if err != nil {
		return nil, supervisor.ShimExitSetup, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("locate self: %w", err)
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("stderr pipe: %w", err)
	}
	env := spec.Env
	var syncFD uintptr
	if spec.ExecSync {
		env = append(append([]string{}, env...), fmt.Sprintf("%s=%d", supervisor.ExecSyncFDEnv, supervisor.ExecSyncChildFD))
		syncFD = supervisor.ExecSyncChildFD
	}
	child, err := supervisor.PosixSpawner{PressureKill: true}.Spawn(context.Background(), supervisor.SpawnSpec{
		Path:       self,
		Argv:       append([]string{self, supervisor.ShimModeLaunch}, spec.Launch...),
		Env:        env,
		StdoutFD:   outW.Fd(),
		StderrFD:   errW.Fd(),
		ExecSyncFD: syncFD,
		KeepGroup:  true,
	})
	_, _ = outW.Close(), errW.Close()
	if spec.ExecSync {
		// The container holds the exec-sync pipe now; this copy must go so the
		// daemon's read end reaches EOF exactly at the container's exec.
		_ = unix.Close(supervisor.ExecSyncChildFD)
	}
	if err != nil {
		return nil, supervisor.ShimExitSetup, fmt.Errorf("spawn the container: %w", err)
	}
	childStart, _ := supervisor.ProcStartTimeNano(child)
	start, _ := supervisor.ProcStartTimeNano(os.Getpid())

	s := &shimServer{
		spec:       spec,
		self:       self,
		pid:        os.Getpid(),
		start:      start,
		child:      child,
		childStart: childStart,
		logw:       logw,
		out:        newRing(ringBytes),
		errs:       newRing(ringBytes),
		exited:     make(chan struct{}),
		exitFile:   exitFile,
		handoffs:   newHandoffStore(),
	}
	s.pumps.Add(2)
	go s.pump(outR, s.out, crilog.StreamStdout)
	go s.pump(errR, s.errs, crilog.StreamStderr)

	abort := func(code int, err error) (*shimServer, int, error) {
		_ = unix.Kill(child, unix.SIGKILL)
		_, _, _ = supervisor.KqueueReaper{}.WaitExit(context.Background(), child)
		return nil, code, err
	}
	if err := dropShim(supervisor.UnixDropper{}, os.Chown, cred, os.Geteuid(), spec.Dir, spec.LogPath); err != nil {
		return abort(supervisor.ShimExitSetup, fmt.Errorf("drop the shim to the pod credential: %w", err))
	}
	if err := confine(string(shimProfile)); err != nil {
		return abort(supervisor.ShimExitSetup, fmt.Errorf("confine the shim: %w", err))
	}

	s.grpc = grpc.NewServer(grpc.KeepaliveEnforcementPolicy(supervisor.ShimKeepaliveEnforcement))
	shimv1.RegisterContainerShimServer(s.grpc, s)
	go func() { _ = s.grpc.Serve(ln) }()
	go s.acceptHandoffs(ptyLn)
	for _, fd := range []int{1, 2} {
		if err := redirectNull(fd); err != nil {
			return abort(supervisor.ShimExitSetup, fmt.Errorf("release the diagnostics pipe: %w", err))
		}
	}
	return s, 0, nil
}

// run reaps the container, persists its exit, and shuts the shim down. A
// SIGTERM, SIGINT or SIGHUP the shim receives (sigs, installed at the top of
// Serve) is forwarded to the container until it is reaped — never after, when
// its pid may already name another process.
func (s *shimServer) run(sigs chan os.Signal) int {
	go func() {
		for sig := range sigs {
			if s.reaped.Load() {
				continue
			}
			_ = unix.Kill(s.child, sig.(syscall.Signal))
		}
	}()

	code, sig, err := supervisor.KqueueReaper{}.WaitExit(context.Background(), s.child)
	s.reaped.Store(true)
	if err != nil {
		// Unreachable for a child of this process; report it as a kill so the
		// record never reads as success.
		code, sig = 128+int(syscall.SIGKILL), int(syscall.SIGKILL)
	}
	drained := make(chan struct{})
	go func() {
		s.pumps.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(drainGrace):
	}
	rec := supervisor.ExitRecord{ExitCode: code, Signal: sig, FinishedAtUnixNano: time.Now().UnixNano()}
	werr := supervisor.WriteExitRecordTo(s.exitFile, rec)
	_ = s.exitFile.Close()
	s.mu.Lock()
	if werr == nil {
		s.exit = &rec
	}
	s.mu.Unlock()
	close(s.exited)
	signal.Stop(sigs)
	close(sigs)

	// Exec sessions still open when the container exited keep the shim
	// serving, Status included, until they end or stopGrace passes; with none
	// open it stops at once. (GracefulStop would refuse every new RPC while it
	// waited.) The exit can still be reported up to drainGrace late: a forked
	// descendant that keeps the container's output pipes open holds the record
	// back until the drain bound above passes.
	for deadline := time.Now().Add(stopGrace); s.execs.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	s.grpc.Stop()
	_ = s.logw.Close()
	if werr != nil {
		return supervisor.ShimExitSetup
	}
	return 0
}

// pump moves one of the container's pipes into its ring until EOF, and drains
// the ring into the log; neither ever blocks the container's write(2).
func (s *shimServer) pump(f *os.File, r *ring, stream crilog.Stream) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.writeLog(r, stream)
	}()
	buf := make([]byte, 32<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = r.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	_ = f.Close()
	r.Close()
	wg.Wait()
	s.pumps.Done()
}
