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
