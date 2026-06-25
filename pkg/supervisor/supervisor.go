package supervisor

import (
	"context"
)

// SpawnSpec is everything needed to posix_spawn one pod process: the executable
// path, full argv (argv[0] is conventionally the path), the environment, the
// working directory, and the fd the child's combined stdout+stderr is wired to.
type SpawnSpec struct {
	// Path is the executable to spawn (the exec-shim helper).
	Path string
	// Argv is the full argument vector (Argv[0] is conventionally Path).
	Argv []string
	// Env is the child environment. It MUST already contain any
	// DYLD_INSERT_LIBRARIES the pod needs; the spawner passes it through verbatim.
	Env []string
	// Dir is the child working directory ("" = inherit).
	Dir string
	// LogFD is the write end of the combined stdout+stderr pipe; the child's
	// fd 1 and fd 2 are dup2'd onto it. If 0, the child inherits the parent's.
	LogFD uintptr
}

// Spawner posix_spawns a pod process in its own session/process group and
// returns the child pid. It is the supervisor's spawn seam; the production
// implementation uses raw posix_spawn (spawn_darwin.go), tests inject a fake.
type Spawner interface {
	// Spawn starts spec's process group-leading child and returns its pid.
	Spawn(ctx context.Context, spec SpawnSpec) (pid int, err error)
}

// PodNetwork sets up pod networking and returns the pod IP to bind/advertise.
// M1 wires a node-IP/no-op implementation (single node); darwin-net supplies the
// real lo0 IPAM + Service proxy later. Defined here at the consumer per the
// standards (small, 1 method).
type PodNetwork interface {
	// Setup provisions networking for podID and returns the pod's IP.
	Setup(ctx context.Context, podID string) (ip string, err error)
}

// ExitWaiter blocks until the process pid exits and returns its wait status,
// reaping it exactly once. The production implementation uses kqueue
// (reaper_darwin.go); it is the SOLE reaper (never combined with Cmd.Wait).
type ExitWaiter interface {
	// WaitExit blocks until pid exits (or ctx is done) and returns the exit
	// code and terminating signal (signal 0 if none). It reaps pid once.
	WaitExit(ctx context.Context, pid int) (exitCode int, signal int, err error)
}
