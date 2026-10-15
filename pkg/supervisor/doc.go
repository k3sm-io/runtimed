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

// Package supervisor spawns and reaps native pod processes.
//
// A pod is a process group: the supervisor posix_spawns each container (through
// the sandbox exec-shim, which applies the Seatbelt profile then becomes the pod
// binary) into its own session/process group, wires a SEPARATE pipe for each of
// its stdout and stderr (the CRI log format labels every line with the stream it
// came from, and a merge cannot be undone downstream), and reaps exits via
// kqueue(EVFILT_PROC) — the sole reaper.
//
// A container's output must outlive this daemon, and a pipe whose read end is
// here cannot: when the daemon dies the child's next write takes EPIPE. So a
// pod container runs beside a RESIDENT SHIM (NewShimProcess, shim.go): the
// exec-shim helper stays alive as the pod group's leader and the container's
// parent, holds the pipes, writes the CRI log, reaps the container and persists
// its exit status, and serves shimv1.ContainerShim on a socket. A restarted
// daemon reconnects (ConnectShim, AdoptShim), so output, the real exit status
// and exec all survive it. Exec sessions and the vm helper keep the pipe path.
//
// The process TREE, not the group, is the macOS analog of the pid namespace.
// macOS has none, so nothing ends a container's processes when its init dies:
// a container's SIGTERM goes to its init alone (the runc shape), and a child
// the init did not reap is reparented to launchd and lives on with the pod's
// authority, or leaves the group altogether through setsid(2). So each
// container's tree is tracked (TrackTree, tree.go): every process descended
// from the leader by parent pid, plus the members of the pod's process group
// and session, each known by its exact instance (pid and kernel start time),
// re-enumerated on a tick and once more before every termination signal,
// because a child's ancestry is readable only while its parent lives. When the
// leader's exit is observed, and again at DeletePod, every member still the
// recorded instance is SIGKILLed by pid and each group a verified member is in
// is SIGKILLed too; there is no SIGTERM for stragglers (runc's KILL to all
// after init). Members still alive after the bounded wait are reported, and
// the runtime keeps them in the container's reap record for the next sweep.
//
// The tree is read on a tick (DefaultTreeTick), from one process-table snapshot
// the whole daemon shares (ProcTableCache), and fresh before every termination
// signal; a sweep re-reads it every 50 ms.
//
// Ceilings, each a process the tree never knew and so cannot kill:
//
//   - The tick-sized residual: a child that forks, calls setsid(2) and loses
//     its parent, all inside one tick and before any refresh has seen it, has
//     no remaining link to the pod (no ancestry, not in the pod's group or
//     session) and is not found. It was never a member, so no reap record
//     names it, and the stop and uninstall sweeps of recorded survivors do not
//     see it either.
//   - More generally, a process that re-executes into a new session before the
//     snapshot taken just before the termination signal, and is not reachable
//     by ancestry from a known member at that moment, can survive the pod.
//   - The launchd-mediated case: a job a pod submits through launchctl or XPC
//     is started by launchd, not forked by the pod, so it is no pod
//     descendant and is not killed. Whether that path is open at all is
//     decided by the Seatbelt profile's mach-lookup posture, not here.
//
// The uninstall sweep over the reap records is the backstop for what the
// records name, and only for that.
//
// kqueue is used deliberately INSTEAD OF os/exec.Cmd.Wait so there is exactly one
// place that calls wait4; mixing the two double-reaps and races the exit status.
//
// The spawn carries DYLD_INSERT_LIBRARIES from the PodBox into envp (the
// cross-repo DNS-shim enabler) — posix_spawn passes the env through and the
// exec-shim's execve preserves it.
//
// Seams (consumer-side interfaces, fakeable in unit tests):
//
//   - Spawner   — posix_spawn a SpawnSpec, return the child pid. The production
//     impl (spawn_darwin.go) uses raw posix_spawn + posix_spawn_file_actions +
//     POSIX_SPAWN_SETSID via cgo; tests inject a fake.
//   - ShimDialer — dial a resident shim's socket and name its peer pid; the
//     production UnixShimDialer reads LOCAL_PEERPID, tests inject a fake.
//   - PodNetwork — Setup(ctx, podID) -> pod IP; Teardown(podID) releases it on
//     pod delete (and on a failed create after a successful Setup). NodeNetwork
//     is a node-IP/no-op impl (single node); the k3sm-injected adapter over
//     darwin-net's podnet IPAM supplies the real per-pod /32 lo0 aliases.
//
// All cgo (posix_spawn, kqueue) is isolated in *_darwin.go behind these seams.
package supervisor
