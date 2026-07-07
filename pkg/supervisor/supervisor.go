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

// PodNetwork sets up and tears down pod networking. M1 wires a node-IP/no-op
// implementation (NodeNetwork); the k3sm-injected adapter over darwin-net's
// podnet IPAM supplies the real per-pod /32 lo0 aliases (M10.1). Defined here at
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
// (reaper_darwin.go); it is the SOLE reaper (never combined with Cmd.Wait).
type ExitWaiter interface {
	// WaitExit blocks until pid exits (or ctx is done) and returns the exit
	// code and terminating signal (signal 0 if none). It reaps pid once.
	WaitExit(ctx context.Context, pid int) (exitCode int, signal int, err error)
}
