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

// Shim-load detection: did the pod's DYLD_INSERT_LIBRARIES shim load?
//
// The pod shim (DNS precedence, and the bind/connect source discipline no node
// resolver can restore) reaches a pod process only through dyld honouring
// DYLD_INSERT_LIBRARIES. dyld drops that variable for a platform binary, a
// CS_RESTRICT process, and a hardened-runtime process without the
// allow-dyld-environment-variables entitlement; and library validation
// (CS_REQUIRE_LV / CS_FORCED_LV) rejects the ad-hoc-signed, Team-ID-less shim
// dylib even when the variable survives. Either way the pod runs without the
// shim and nothing fails: the losses are silent. This file turns them into a
// verdict a caller can make loud.
//
// Authority and hint. The only AUTHORITY for "the shim loaded" is a handshake
// artifact the shim itself produces (HandshakeArrived). Spawn-time code-signing
// inspection is a HINT: it can say the shim certainly could not load (the
// flags above), but clean flags prove nothing, because the entitlement blob is
// not read and a static binary has no dyld at all. So ShimLoaded is returned
// ONLY on an arrived handshake, and a hint against loading is never needed once
// it has arrived.
//
// Unknown is as loud as unloaded. When the question cannot be answered (the
// exec was not observed, csops failed, a wired producer stayed silent past its
// window) the verdict is ShimUnknown and it is logged at Warn exactly like
// ShimUnloaded: a detector that goes quiet whenever it is unsure fails open
// silently, which is the defect this exists to close.
//
// Why ShimUnverified is quiet. No handshake producer exists yet (the shim emits
// nothing), so today every pod with clean flags has no authority either way.
// Warning on every such pod would warn on every healthy pod, and a detector
// that always warns gets muted. ShimUnverified (clean hint, no producer wired)
// is therefore logged at Debug; it is the production value until a producer
// ships.
//
// The owed producer, for whoever builds it:
//   - it must fire at LOAD time (a dylib constructor), not on first bind/connect:
//     a pod that never binds would otherwise read as a missing shim;
//   - it is delivered over a descriptor or socket runtimed creates and the pod
//     inherits, never a file the Seatbelt profile lets the pod write;
//   - it carries the pid and a per-spawn nonce;
//   - it is ADVISORY, not attested: a pod can forge it to silence its own
//     warning, so it must never gate anything (admission, networking, policy);
//   - the window (HandshakePending vs HandshakeArrived) is evaluated by the
//     caller once a producer exists; this file only classifies the outcome.
//
// Non-goals for now: static binaries (no LC_LOAD_DYLINKER, so no dyld and no
// shim) are not detected, and no Mach-O parsing is done. This is detection
// only: nothing here changes the sandbox, the environment, or bind behaviour.

import (
	"fmt"
	"log/slog"
	"strings"
)

// The csflags bits (<sys/codesign.h>, not in the public SDK) under which the
// shim cannot load: dyld scrubs DYLD_* for a platform binary, a restricted
// process, and a hardened-runtime process (unless it carries the
// allow-dyld-environment-variables entitlement, which is not read); library
// validation rejects the ad-hoc-signed shim dylib, which has no Team ID.
const (
	CSPlatformBinary uint32 = 0x04000000
	CSRestrict       uint32 = 0x00000800
	CSRuntime        uint32 = 0x00010000
	CSRequireLV      uint32 = 0x00002000
	CSForcedLV       uint32 = 0x00000010
)

// shimBlockingBits lists the bits that block the shim, in the order their
// names appear in a cause.
var shimBlockingBits = []struct {
	bit  uint32
	name string
}{
	{CSPlatformBinary, "CS_PLATFORM_BINARY"},
	{CSRestrict, "CS_RESTRICT"},
	{CSRuntime, "CS_RUNTIME"},
	{CSRequireLV, "CS_REQUIRE_LV"},
	{CSForcedLV, "CS_FORCED_LV"},
}

// CSFlagNames names the shim-blocking csflags bits set in flags, joined by
// "|", or "" when none is set. Bits outside the five constants above are
// ignored.
func CSFlagNames(flags uint32) string {
	var names []string
	for _, b := range shimBlockingBits {
		if flags&b.bit != 0 {
			names = append(names, b.name)
		}
	}
	return strings.Join(names, "|")
}

// HandshakeState is what the shim's load-time handshake said, as the caller
// evaluated it against its window.
type HandshakeState int

const (
	// HandshakeUnsupported means no handshake producer is wired, so no
	// authority exists. It is the zero value and today's production value.
	HandshakeUnsupported HandshakeState = iota
	// HandshakePending means a producer is wired and the window expired with
	// no artifact.
	HandshakePending
	// HandshakeArrived means the shim's artifact arrived: the shim loaded.
	HandshakeArrived
)

// ShimVerdict is the classified answer to "did the pod shim load?".
type ShimVerdict int

const (
	// ShimUnverified means no authority is available and no hint says the
	// shim could not load. It is the zero value, and it is quiet.
	ShimUnverified ShimVerdict = iota
	// ShimLoaded means the handshake arrived. It is the only route to it.
	ShimLoaded
	// ShimUnloaded means the code-signing flags say the shim cannot load.
	ShimUnloaded
	// ShimUnknown means the question could not be answered.
	ShimUnknown
)

// String returns the verdict's lower-case reason word.
func (v ShimVerdict) String() string {
	switch v {
	case ShimLoaded:
		return "loaded"
	case ShimUnloaded:
		return "unloaded"
	case ShimUnknown:
		return "unknown"
	default:
		return "unverified"
	}
}

// CodeSignInspector reads a process's kernel code-signing flags.
type CodeSignInspector interface {
	CodeSignStatus(pid int) (uint32, error)
}

// CodeSignFunc adapts a function, such as CodeSignStatus, to
// CodeSignInspector.
type CodeSignFunc func(pid int) (uint32, error)

// CodeSignStatus calls f.
func (f CodeSignFunc) CodeSignStatus(pid int) (uint32, error) { return f(pid) }

// ShimLoad is one container's classified shim-load outcome.
type ShimLoad struct {
	// Verdict is the classification.
	Verdict ShimVerdict
	// Flags are the csflags read for the process, or 0 when none were read.
	Flags uint32
	// Cause says why: the blocking bit names, the inspection error, or the
	// missing observation or handshake.
	Cause string
}

// Reason is the verdict's reason word ("loaded", "unloaded", "unknown",
// "unverified").
func (l ShimLoad) Reason() string { return l.Verdict.String() }

// Loud reports whether the verdict must be surfaced as a warning: true for
// ShimUnloaded and ShimUnknown.
func (l ShimLoad) Loud() bool {
	return l.Verdict == ShimUnloaded || l.Verdict == ShimUnknown
}

// ClassifyShimLoad classifies whether the shim loaded into pid. observed says
// whether the exec of the pod binary was observed (Process.ObserveExec); h is
// the handshake outcome. The rules, in order: an arrived handshake is Loaded
// without consulting ins; an unobserved exec, a nil ins, or an inspection error
// (ESRCH included) is Unknown; a shim-blocking csflags bit is Unloaded; clean
// flags with a pending handshake are Unknown; clean flags with no producer are
// Unverified.
func ClassifyShimLoad(ins CodeSignInspector, pid int, observed bool, h HandshakeState) ShimLoad {
	if h == HandshakeArrived {
		return ShimLoad{Verdict: ShimLoaded, Cause: "handshake arrived"}
	}
	if !observed {
		return ShimLoad{Verdict: ShimUnknown, Cause: "exec not observed"}
	}
	if ins == nil {
		return ShimLoad{Verdict: ShimUnknown, Cause: "no code-signing inspector"}
	}
	flags, err := ins.CodeSignStatus(pid)
	if err != nil {
		return ShimLoad{Verdict: ShimUnknown, Cause: fmt.Sprintf("code-signing status unavailable: %v", err)}
	}
	if bits := CSFlagNames(flags); bits != "" {
		return ShimLoad{Verdict: ShimUnloaded, Flags: flags, Cause: bits}
	}
	if h == HandshakePending {
		return ShimLoad{Verdict: ShimUnknown, Flags: flags, Cause: "no handshake within the window"}
	}
	return ShimLoad{Verdict: ShimUnverified, Flags: flags, Cause: "no handshake producer; code signing does not block the shim"}
}

// Log emits the verdict for one container on log: a Loud verdict at Warn, any
// other at Debug, each with the attrs pod, container, binary, reason and cause.
func (l ShimLoad) Log(log *slog.Logger, pod, container, binary string) {
	attrs := []any{"pod", pod, "container", container, "binary", binary, "reason", l.Reason(), "cause", l.Cause}
	switch l.Verdict {
	case ShimUnloaded:
		log.Warn("pod shim not loaded: the main process's code signing keeps dyld from inserting it; "+
			"DNS precedence and bind/connect source discipline are unavailable", attrs...)
	case ShimUnknown:
		log.Warn("pod shim load unknown: DNS precedence and bind/connect source discipline may be unavailable", attrs...)
	default:
		log.Debug("pod shim load", attrs...)
	}
}
