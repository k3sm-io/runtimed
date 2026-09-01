//go:build darwin

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

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The build tag here is `darwin`, not `darwin && cgo`: this probe is deliberately
// pure GO. Rosetta 2 presence is answerable from the filesystem plus one exec, so
// there is no reason to drag it behind cgo — and keeping it cgo-free means the
// CGO_ENABLED=0 lane gets the real probe rather than a stub that would lie about a
// capable host.

// rosettaRuntimePath is the one on-disk artifact whose presence means Rosetta 2 is
// INSTALLED. Verified on macOS 26.5.2 (build (redacted)): mode 0755 root:wheel, flagged
// SIP-`restricted`.
//
// Three properties make it the right (and the only acceptable) path:
//
//   - Its parent directory /Library/Apple/usr/libexec/oah/ is created AT ROSETTA
//     INSTALL TIME, so its existence is evidence of an install rather than of the
//     OS shipping a file.
//   - It is SIP-`restricted`, so no non-SIP-exempt process — including anything
//     running as the unprivileged _k3sm daemon user — can forge it.
//   - The platform's own system.sb grants `file-test-existence` on exactly this
//     path: this IS Apple's presence check, not a heuristic of ours.
//
// DO not substitute /usr/libexec/rosetta/* — those ship with macOS on the SEALED
// SYSTEM VOLUME (dated with the OS build seal, present on hosts with no Rosetta
// installed), so a stat of them is permanently true and the probe would be
// fail-OPEN: every Mac would advertise host-Rosetta.
const rosettaRuntimePath = "/Library/Apple/usr/libexec/oah/libRosettaRuntime"

// archTool / trueTool are the translated-exec leg's two binaries, named as LITERAL
// absolute paths. Both are SIP-`restricted` (verified on macOS 26.5.2 / (redacted)), so
// neither can be replaced by a non-SIP-exempt process.
//
// exec.LookPath is BANNED here and the reason is a privilege boundary, not style:
// /usr/local/bin is human-uid-owned and /opt/homebrew/bin is admin-group-writable,
// while runtimed runs as _k3sm — the uid k3sm-netd's LOCAL_PEERCRED check trusts.
// A planted `arch` on PATH would therefore execute as the one identity that can
// drive the root network helper, escalating across the single root boundary in the
// design. Absolute SIP-restricted paths remove the vector entirely.
const (
	archTool = "/usr/bin/arch"
	trueTool = "/usr/bin/true"
)

// hostRosettaSpawnTimeout bounds the translated exec. It is the probe's own
// INTERNAL ceiling, applied on top of whatever the caller's ctx allows, because the
// caller is Runtime construction: io.k3sm.server is a launchd KeepAlive job and
// KeepAlive respawns on EXIT, not on a WEDGE. A hung probe would therefore leave
// apiserver+kine serving while the node never registers — taint eviction then
// deletes every pod while `launchctl print` still shows the job healthy. A
// capability probe must not be able to cause that, so it is time-boxed.
const hostRosettaSpawnTimeout = 2 * time.Second

// hostRosettaWaitDelay bounds Wait after cancellation, so even an unkillable child
// cannot hold the constructor. Belt to hostRosettaSpawnTimeout's braces.
const hostRosettaWaitDelay = 500 * time.Millisecond

// hostRosettaProbe reports whether this host can translate darwin/amd64 Mach-O
// payloads, composing two legs with and:
//
//  1. presence — stat rosettaRuntimePath (see its doc for why that exact path).
//  2. TRANSLATION — run `/usr/bin/arch -x86_64 /usr/bin/true` and take the verdict
//     from the exit status alone.
//
// Leg 2 is GATED BEHIND leg 1: a host without Rosetta forks nothing, so the probe
// costs one stat on the overwhelmingly common Apple-Silicon-without-Rosetta node.
// Leg 1 alone would not do — the payload can be present while translation is
// unusable — and leg 2 alone would not do either, because `arch(1)` collapses
// EBADARCH and every other failure into a generic non-zero exit, so a bare spawn
// failure could not be distinguished from "no Rosetta installed".
//
// It never returns an error. Every failure mode — stat error, spawn error, non-zero
// exit, timeout — maps to a not-available state, because a missing host capability
// must not be able to fail daemon startup.
func hostRosettaProbe(ctx context.Context) HostRosettaState {
	if _, err := os.Stat(rosettaRuntimePath); err != nil {
		return HostRosettaAbsent
	}
	if err := runTranslatedProbe(ctx); err != nil {
		return HostRosettaTranslationFailed
	}
	return HostRosettaAvailable
}

// runTranslatedProbe runs the translated no-op exec, hardened so it can neither be
// hijacked nor leave anything behind:
//
//   - literal absolute SIP-restricted argv[0] and payload (never exec.LookPath);
//   - an empty environment, so no inherited DYLD_*/PATH/locale can steer it;
//   - no shell — the argv is passed directly to posix_spawn by os/exec;
//   - stdout/stderr left nil, which os/exec wires to /dev/null: output is
//     discarded without any copier goroutine that could outlive the probe;
//   - Setpgid, plus a Cancel that SIGKILLs the whole GROUP (-pgid) rather than the
//     direct child, so a timeout cannot strand a grandchild — gated on a race-free
//     "is the child still ours?" check so a Cancel that fires after the reap cannot
//     signal a recycled pgid;
//   - WaitDelay, so Wait itself is bounded even if the group survives the kill.
//
// The verdict is the exit status only; nothing the child writes is parsed.
func runTranslatedProbe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, hostRosettaSpawnTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, archTool, "-x86_64", trueTool)
	cmd.Env = []string{}
	cmd.WaitDelay = hostRosettaWaitDelay
	// Setpgid makes the child a process-group leader (pgid == pid), which is what
	// lets Cancel address the whole group below.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// Kill the DIRECT child through os.Process first. That is not redundant with
		// the group kill below: os/exec runs Cancel on its watchCtx goroutine, which
		// can lose the race with Wait and fire after the child was reaped — at which
		// point -pid may name a RECYCLED process group, and since the daemon runs as
		// _k3sm alongside every pod process the blast radius is not empty. os.Process
		// tracks the reap under its own lock and answers ErrProcessDone once it has
		// happened, so this is the only race-free way to ask (reading cmd.ProcessState
		// instead would be a real data race: exec.go writes it on the Wait goroutine
		// before it ever synchronises with this one). os/exec makes the same
		// Process.Kill() move in its own WaitDelay path.
		if err := cmd.Process.Kill(); err != nil {
			return err
		}
		// Negative pid = the process GROUP. os/exec's default Cancel kills only the
		// direct child, which would leak any grandchild arch(1) left running.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return cmd.Run()
}
