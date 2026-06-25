// Package supervisor spawns and reaps native pod processes.
//
// A pod is a process group: the supervisor posix_spawns each container (through
// the sandbox exec-shim, which applies the Seatbelt profile then becomes the pod
// binary) into its OWN session/process group, wires a combined stdout+stderr
// pipe for logs, and reaps exits via kqueue(EVFILT_PROC) — the SOLE reaper.
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
//     POSIX_SPAWN_SETSID|SETPGROUP via cgo; tests inject a fake.
//   - PodNetwork — Setup(ctx, podID) -> pod IP. M1 wires a node-IP/no-op impl
//     (single node); darwin-net supplies the real lo0 IPAM later.
//
// All cgo (posix_spawn, kqueue) is isolated in *_darwin.go behind these seams.
package supervisor
