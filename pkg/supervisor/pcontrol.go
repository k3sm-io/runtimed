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
	"errors"
	"log/slog"
	"sync/atomic"
	"syscall"
)

// pcontrolPolicy is the resource-starvation policy a spawn asks the kernel to
// record on the child: none, or kill. It is the platform-independent half of
// the decision; the darwin spawner turns pcontrolKill into the
// POSIX_SPAWN_PCONTROL_KILL spawn attribute.
type pcontrolPolicy uint8

const (
	// pcontrolNone leaves the child unmarked (the kernel default).
	pcontrolNone pcontrolPolicy = iota
	// pcontrolKill marks the child to be SIGKILLed when the system runs out of
	// paging space and the kernel picks a marked process to free memory.
	pcontrolKill
)

// ErrPressureKillUnsupported reports that the pressure-kill mark cannot be set
// or read back on this build (anything but darwin with cgo).
var ErrPressureKillUnsupported = errors.New("supervisor: pressure-kill mark requires darwin+cgo")

// ErrPressureKillNotMarked reports that a process spawned with the
// pressure-kill mark requested did not carry it when read back.
var ErrPressureKillNotMarked = errors.New("supervisor: spawned process does not carry the pressure-kill mark")

// unmarkedSpawns counts spawns that asked for the pressure-kill mark and ran
// without it (the fail-soft arms of PosixSpawner.Spawn).
var unmarkedSpawns atomic.Uint64

// UnmarkedSpawns reports how many spawns since process start requested the
// pressure-kill mark but started the child without it. A non-zero value means
// some pod processes are not preferred over the control plane as the
// memory-exhaustion victim.
func UnmarkedSpawns() uint64 { return unmarkedSpawns.Load() }

// noteUnmarkedSpawn records one marked-requested spawn that ran unmarked: one
// Warn line and one counter increment. reason names which fail-soft arm fired;
// code is the setpcontrol return code or the posix_spawn errno behind it.
func noteUnmarkedSpawn(path, reason string, code int) {
	unmarkedSpawns.Add(1)
	slog.Warn("pod process spawned without pressure-kill mark",
		"path", path, "reason", reason, "code", code)
}

// pcontrolRetry decides whether a failed spawn is retried without the
// pressure-kill mark. setRC is what posix_spawnattr_setpcontrol_np returned
// (0 when it was not called), spawnErr is the posix_spawn error.
//
// The mark is a preference, never a reason to refuse a pod, so the one error a
// kernel that rejects the attribute would raise (EINVAL) is retried once with
// every other attribute unchanged. Nothing else is retried: EPERM, ENOENT and
// the rest are about the binary or the caller and would fail the same way
// unmarked. When setpcontrol itself failed the attribute was never set, the
// spawn already ran unmarked, and a retry would repeat it exactly.
//
// It returns the plan to retry with and whether to retry at all.
func pcontrolRetry(plan spawnPlan, setRC int, spawnErr error) (spawnPlan, bool) {
	if plan.PControl != pcontrolKill || setRC != 0 {
		return plan, false
	}
	if !errors.Is(spawnErr, syscall.EINVAL) {
		return plan, false
	}
	plan.PControl = pcontrolNone
	return plan, true
}
