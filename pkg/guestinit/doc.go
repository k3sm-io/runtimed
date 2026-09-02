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

// Package guestinit turns a k3sm.io/apis guest/v1 GuestSpec into the PLANS a
// micro-VM guest's PID 1 executes, and owns the one piece of that PID 1 whose
// correctness is concurrency-shaped: the reaper and the Stop state machine.
//
// # Plans are data
//
// Every function in this package is pure. It performs no syscall, opens no
// file, and starts no process: it returns a plan — an ordered slice of steps,
// a rendered file's content, a resolved identity — that the linux-only
// executor in cmd/k3sm-guest-init applies. That split is deliberate and is the
// package's reason to exist. The guest runs linux/arm64 inside a VM that this
// repo cannot boot in a unit test, so any logic living in the executor is
// reachable only by a cross-compile check, which proves it compiles and
// nothing else. Logic living here is exercised by `go test` on darwin, where
// the repo's CI actually runs.
//
// The Linux mount-flag values are therefore restated here as portable
// constants (LinuxMountFlags), not imported from golang.org/x/sys/unix: the
// symbolic-option -> MS_* mapping is a real piece of behaviour, and importing
// the linux-only constants would make it exactly the kind of untestable
// executor logic this package exists to avoid. They are stable Linux ABI
// numbers.
//
// # The one exception: pty allocation
//
// pty_linux.go (OpenPTY, SetWinsize, ChownTTY) does perform syscalls, and is
// the only linux-tagged non-test file here. It earns the exception by carrying
// no decision: WHERE an exec's pty comes from is decided by the pure
// ExecPTYOrigin, HOW its descriptors are wired, closed and pumped by the pure
// PlanExecIO, and what is left is a fixed ioctl sequence with no branch a table
// could cover. Keeping it beside those two is what lets the decisions be tested
// on darwin at all; the !linux stub fails closed so the package still builds
// and tests there.
//
// # The PID 1 state machine
//
// Reaper is GOOS-portable behind a three-method Proc seam (Wait4 / Kill /
// Poweroff) plus a SIGCHLD notification channel and an injectable timer, so
// the reap loop, the exit-before-Track race, and the
// term -> grace -> KILL -> sync -> poweroff sequence are all tested under
// -race on darwin. This is the most concurrency-sensitive code in the vm path
// (it races container starts against the reap loop against the grace timer),
// and it must not live untested inside a linux-only main.
//
// # Cross-boundary constants
//
// guest/v1 does not name the virtiofs tag carrying the spec file, nor the one
// carrying the Rosetta interpreter: both are host/guest conventions rather
// than spec fields. They are exported here (SpecShareTag, RosettaShareTag and
// friends) so the host-side VM builder imports them instead of respelling the
// literals — a disagreement then fails to compile rather than failing to boot.
//
// # Known ceilings (stated, not worked around)
//
//   - guest/v1 carries no sidecar marker: GuestContainer has `init` and
//     nothing else, so a native sidecar (an init container with
//     restartPolicy: Always) cannot be distinguished from a run-to-completion
//     init container here. StartOrder therefore plans every init container as
//     a blocking step, and a producer that emits a never-exiting sidecar as an
//     init container would hang the boot. Until guest/v1 grows the marker, the
//     host-side producer must emit such a container as a main container.
//     StartStep.WaitForExit is the single place that changes when it does.
//   - guest/v1 carries no image USER string: a non-numeric USER must be
//     resolved host-side and stamped into uid/gid. ResolveUser implements the
//     in-guest resolution against a rootfs /etc/passwd and is wired for the
//     numeric case the spec can express today.
//   - A container's /dev is the OCI default device set and nothing else
//     (DefaultDevices) plus a private devpts and a bounded /dev/shm. The
//     allowlist is a security boundary, not a convenience: see ContainerDev for
//     why /dev/vsock in particular must never appear in it.
//   - An idmapped mount (GuestMount.idmap) is planned but not applied by the
//     executor: mount_setattr(MOUNT_ATTR_IDMAP) is contingent on the M11.2-d5
//     lab question. The executor refuses such a spec rather than mounting it
//     without the idmap, because a silently non-idmapped PVC writes files
//     under the wrong owner into storage that outlives the pod.
package guestinit
