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

package supervisor

import (
	"context"
)

// SpawnSpec is everything needed to posix_spawn one pod process: the executable
// path, full argv (argv[0] is conventionally the path), the environment, the
// working directory, and the two fds the child's stdout and stderr are wired to.
type SpawnSpec struct {
	// Path is the executable to spawn (the exec-shim helper).
	Path string
	// Argv is the full argument vector (Argv[0] is conventionally Path).
	Argv []string
	// Env is the child environment. It must already contain any
	// DYLD_INSERT_LIBRARIES the pod needs; the spawner passes it through verbatim.
	Env []string
	// Dir is the child working directory: an absolute path the child chdirs
	// into before exec (a posix_spawn chdir file action, never a chdir of this
	// shared daemon process). "" means "inherit the caller's cwd".
	//
	// A Dir that is set but unusable — relative, missing, or not a directory —
	// FAILS the spawn with ErrWorkingDir. It never silently falls back to the
	// inherited cwd; see that sentinel for why. Callers that own a pod-safe
	// default (pkg/runtime defaults it to the pod data volume) must apply it
	// before they build the spec: this package cannot.
	Dir string
	// StdoutFD is the write end of the pipe the child's fd 1 is dup2'd onto.
	// If 0, the child inherits the parent's stdout.
	//
	// It is a SEPARATE pipe from StderrFD, and that separation is the CRI log
	// contract rather than a preference: every line written to disk carries a
	// stdout/stderr label, and a merge cannot be undone downstream. The two fds
	// are closed in the child after the dups, so a pod never holds a raw
	// descriptor onto either pipe.
	StdoutFD uintptr
	// StderrFD is the write end of the pipe the child's fd 2 is dup2'd onto.
	// If 0, the child inherits the parent's stderr.
	StderrFD uintptr
	// StdinFD is the read end the child's fd 0 is dup2'd onto (0 = inherit).
	// The resident shim reads its launch spec from it (ShimSpec): the pod
	// environment crosses to the shim over this descriptor, read once before
	// the shim confines itself, and never through the shim's own environ or a
	// file on disk.
	StdinFD uintptr
	// KeepGroup spawns the child into the CALLER's session and process group
	// instead of a fresh one (no POSIX_SPAWN_SETSID). The resident shim uses it
	// for the container it launches, so the shim is the pod group's leader and
	// the container is a member: one group kill still stops both, and the
	// recorded (pgid, leader start) identity is the shim's. Every other spawn
	// leaves it false and gets its own session, as before.
	KeepGroup bool
	// ExecSyncFD is the write end of the exec-sync pipe, dup2'd onto the
	// child's fd ExecSyncChildFD (0 = none). The exec-shim marks that
	// descriptor close-on-exec (ExecSyncFDEnv), so the parent's read end sees
	// EOF at the moment the shim execs the pod binary, or when it exits. It is
	// set by Process.ObserveExec, never by a caller.
	ExecSyncFD uintptr
}

// ExecSyncChildFD is the descriptor number the exec-sync pipe occupies in the
// spawned exec-shim (see SpawnSpec.ExecSyncFD).
const ExecSyncChildFD = 3

// ExecSyncFDEnv names the environment variable telling the exec-shim which
// inherited descriptor is the exec-sync pipe. The shim marks it close-on-exec
// and removes the variable before it execs the pod, so neither reaches the pod.
const ExecSyncFDEnv = "K3SM_EXEC_SYNC_FD"

// ExecArgv0Env names the environment variable carrying the argv[0] the pod
// binary must see when it differs from the path the shim execs (a re-signed
// shell copy exec'd as "sh" so bash enters POSIX mode). The shim substitutes it
// and removes the variable before exec. A shim that predates it ignores it and
// runs the copy under its own path, which is a working shell minus POSIX mode.
const ExecArgv0Env = "K3SM_EXEC_ARGV0"

// Spawner posix_spawns a pod process in its own session/process group and
// returns the child pid. It is the supervisor's spawn seam; the production
// implementation uses raw posix_spawn (spawn_darwin.go), tests inject a fake.
type Spawner interface {
	// Spawn starts spec's process group-leading child and returns its pid.
	Spawn(ctx context.Context, spec SpawnSpec) (pid int, err error)
}

// PodNetwork sets up and tears down pod networking. NodeNetwork is a
// node-IP/no-op implementation; the k3sm-injected adapter over darwin-net's
// podnet IPAM supplies the real per-pod /32 lo0 aliases. Defined here at
// the consumer per the standards (small, 2 methods).
type PodNetwork interface {
	// Setup provisions networking for podID and returns the pod's IP.
	Setup(ctx context.Context, podID string) (ip string, err error)
	// Teardown releases podID's networking (with real IPAM behind the seam, the
	// pod's /32 lo0 alias — without it every pod churn leaks one address of the
	// 253/node pool). It must be idempotent and tolerate an unknown podID (a pod
	// whose Setup never ran, e.g. the vm route): best-effort, callers
	// log-and-continue and never block pod deletion on its error.
	Teardown(podID string) error
}

// ExitWaiter blocks until the process pid exits and returns its wait status,
// reaping it exactly once. The production implementation uses kqueue
// (reaper_darwin.go); it is the sole reaper (never combined with Cmd.Wait).
type ExitWaiter interface {
	// WaitExit blocks until pid exits (or ctx is done) and returns the exit
	// code and terminating signal (signal 0 if none). It reaps pid once.
	WaitExit(ctx context.Context, pid int) (exitCode int, signal int, err error)
}
