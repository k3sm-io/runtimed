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

package runtime

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ShimInactiveConditionType is the pod-condition type runtimed publishes when
// a container's main process was exec'd as a restricted binary, so dyld
// dropped DYLD_INSERT_LIBRARIES and neither the DNS shim nor the path-rebase
// shim is loaded in it. It rides PodStatus.conditions, the same path
// GuestStatsConditionType takes, with status TRUE and a message the node turns
// into a Warning Event; runtimed has no API client and creates no Event.
//
// It is qualified for the reason GuestStatsConditionType is: it is not one of
// the four condition types the kubelet owns.
const ShimInactiveConditionType = "k3sm.io/shim-inactive"

// ShimInactiveReason is the condition's reason: the main process's own
// code-signing flags, read from the kernel, say dyld will scrub DYLD_*
// (a platform binary, or CS_RESTRICT).
const ShimInactiveReason = "RestrictedMainProcess"

// ShimInactiveHardenedReason is the condition's reason when the only cause is
// the hardened runtime (CS_RUNTIME): dyld ignores DYLD_* for such a process
// unless the binary carries the
// com.apple.security.cs.allow-dyld-environment-variables entitlement. The
// entitlement blob is NOT read, so a hardened binary that does carry it is
// reported inactive although the shim may in fact load: a false positive on
// the safe side (a warning about a loss that did not happen, never silence
// about one that did). When a pod has containers of both kinds, the condition
// carries ShimInactiveReason and each container's message names its own cause.
const ShimInactiveHardenedReason = "HardenedRuntimeMainProcess"

// The two csflags bits under which dyld scrubs DYLD_* from a process
// (<sys/codesign.h>, not in the public SDK): a platform binary, and a process
// the kernel marked restricted.
const (
	csPlatformBinary uint32 = 0x04000000
	csRestrict       uint32 = 0x00000800
	csRuntime        uint32 = 0x00010000
)

// execObserveTimeout bounds how long a container start waits for the
// exec-shim to exec the pod binary before it gives up on the detection
// (supervisor.Process.ObserveExec). The shim's launch sequence is
// milliseconds; the bound only matters for a shim that never execs.
const execObserveTimeout = 2 * time.Second

// shimInactive is a container's restricted-main-process verdict, written once
// by the exec observer (observeShim) and read, like it is written, under pod.mu.
type shimInactive struct {
	inactive bool
	reason   string // the condition reason (ShimInactiveReason or ShimInactiveHardenedReason)
	message  string
	at       time.Time
}

// restrictedFlags names the csflags bits in flags that make dyld scrub DYLD_*,
// or "" when there are none.
func restrictedFlags(flags uint32) string {
	var bits []string
	if flags&csPlatformBinary != 0 {
		bits = append(bits, "CS_PLATFORM_BINARY")
	}
	if flags&csRestrict != 0 {
		bits = append(bits, "CS_RESTRICT")
	}
	return strings.Join(bits, "|")
}

// shimInactiveMessage is the condition message for one container: it names
// BOTH losses, because the shim carries the bind/connect source discipline as
// well as DNS, and no node resolver restores the former.
func shimInactiveMessage(container, path, bits string) string {
	return fmt.Sprintf("container %s: pod shim inactive for a restricted main process (%s, %s): "+
		"per-namespace DNS precedence and bind/connect source discipline are unavailable; "+
		"FQDN and name.ns.svc resolve through the node resolver", container, path, bits)
}

// observeShim returns the exec observer for a container whose environment
// asks dyld to insert a shim, or nil when there is nothing to observe (no
// shim requested, or detection disabled). The observer runs on the
// container's reaper goroutine (supervisor.Process.ObserveExec), after the
// exec-shim has exec'd the pod binary and before the reaper can collect it, so
// the pid cannot have been reused. It records its verdict in cp.shim under
// p.mu and, once the pod is registered, publishes a MODIFIED status so the
// condition reaches the node without waiting for the next transition. Any
// csops error, ESRCH for a process that has already exited included, is
// fail-open: a Debug line and no verdict.
func (r *Runtime) observeShim(p *pod, cp *containerProc, path string, env []string) func(pid int) {
	if r.codeSignStatus == nil || !envHasName(env, dyldInsertEnv) {
		return nil
	}
	podID, container := p.box.GetPodId(), cp.name
	return func(pid int) {
		flags, err := r.codeSignStatus(pid)
		if err != nil {
			r.log.Debug("code-signing status unavailable; the shim-inactive detection is skipped",
				"pod", podID, "container", container, "pid", pid, "err", err)
			return
		}
		reason, msg := ShimInactiveReason, ""
		if bits := restrictedFlags(flags); bits != "" {
			msg = shimInactiveMessage(container, path, bits)
		} else if flags&csRuntime != 0 {
			reason = ShimInactiveHardenedReason
			msg = shimInactiveMessage(container, path, "CS_RUNTIME: hardened runtime; the shim loads only if "+
				"the binary carries com.apple.security.cs.allow-dyld-environment-variables")
		} else {
			return
		}
		r.log.Warn("pod shim inactive: the main process is restricted, so dyld dropped DYLD_INSERT_LIBRARIES",
			"pod", podID, "container", container, "path", path, "csflags", fmt.Sprintf("%#x", flags))
		p.mu.Lock()
		cp.shim = shimInactive{inactive: true, reason: reason, message: msg, at: time.Now()}
		p.mu.Unlock()
		// A pod still being created is published (ADDED) by createPod after it
		// registers, and that snapshot is taken after the write above.
		if cur, ok := r.lookupPod(podID); ok && cur == p {
			r.publish(runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED, r.podStatus(p))
		}
	}
}

// shimInactiveConditionLocked renders the pod's shim-inactive verdicts as one
// condition, or nil when no container has one. The caller holds p.mu.
func shimInactiveConditionLocked(p *pod) *runtimev1.PodCondition {
	var msgs []string
	var first time.Time
	reason := ShimInactiveHardenedReason
	for _, cp := range p.containers {
		if !cp.shim.inactive {
			continue
		}
		msgs = append(msgs, cp.shim.message)
		if cp.shim.reason == ShimInactiveReason {
			reason = ShimInactiveReason
		}
		if first.IsZero() || cp.shim.at.Before(first) {
			first = cp.shim.at
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return &runtimev1.PodCondition{
		Type:               ShimInactiveConditionType,
		Status:             runtimev1.ConditionStatus_CONDITION_STATUS_TRUE,
		LastProbeTime:      timestamppb.New(first),
		LastTransitionTime: timestamppb.New(first),
		Reason:             reason,
		Message:            strings.Join(msgs, "; "),
	}
}
