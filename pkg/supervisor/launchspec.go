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
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// LaunchSpec bundles the RESOLVED, proto-free inputs of one confined pod-process
// launch: the POSIX identity to drop to, the explicit setrlimit(2) plan, and the
// darwin QoS decision. It is the single struct the runtime threads through the
// sandbox.Backend.WrapCommand choke-point so BOTH spawn callers (container start
// and exec sessions) carry the same launch posture, and the shape
// RunLaunchSequence consumes in the exec-shim.
//
// Like Credential and PlannedRlimit, it is deliberately decoupled from apis: the
// daemon's runtime layer resolves the proto fields (PodBox.rlimits[] via
// resolveRlimitPlan, PodBox.qos_class via resolveBgQoS) into this local form, so
// the supervisor never imports proto types.
type LaunchSpec struct {
	// Cred is the securityContext identity the exec-shim drops to (or the no-drop
	// sentinel posture). See Credential.
	Cred Credential
	// Rlimits is the resolved numeric setrlimit(2) plan applied FIRST in the
	// launch sequence, before the privilege drop. Empty means no explicit limits.
	Rlimits []PlannedRlimit
	// BgQoS requests the darwin BACKGROUND band for the pod process
	// (setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) in the launch
	// sequence, before the sandbox is applied). The runtime layer maps the kube
	// QoS class: BestEffort/unspecified -> true; Guaranteed/Burstable -> false
	// (false means NO setpriority call at all — downward-only, never an explicit
	// reset). See docs/resources.md for the contention-policy rationale and the
	// cooperative (non-enforcing) nature of the band.
	BgQoS bool
}

// Shim argv token vocabulary. The rlimit and qos tokens are SINGLE fixed-position
// argv tokens inserted BEFORE the profile path in the k3sm-execshim invocation:
//
//	<uid> <gid> <groups-csv> <rlimits> <qos> <profile.sb> <pod-binary> [args...]
//
// The position is load-bearing for binary skew: an OLD (pre-B7) shim handed the
// NEW argv reads the rlimit token where it expects its profile path, fails the
// profile ReadFile, and exits — fail-closed; a NEW shim handed the OLD argv sees
// a profile path where it expects the rlimit token, fails the decode, and exits —
// also fail-closed. Neither skew direction can exec a pod without the limits it
// was handed.
const (
	// emptyLaunchToken is the sentinel for "no rlimits" / "no qos request",
	// mirroring the groups-csv "-" pattern.
	emptyLaunchToken = "-"
	// rlimitTokenPrefix introduces the encoded rlimit plan token.
	rlimitTokenPrefix = "r="
	// qosBackgroundToken is the qos token requesting the darwin background band.
	qosBackgroundToken = "q=bg"
)

// EncodeRlimits encodes a resolved rlimit plan as the single shim argv token
// "r=RESOURCE:cur:max[,RESOURCE:cur:max...]" (or "-" for an empty plan). The
// RESOURCE selector is the NUMERIC darwin RLIMIT_* value — the RLIMIT_* name
// table stays daemon-side only (runtime.resolveRlimitPlan); the shim never maps
// names. ParseRlimits is the inverse.
func EncodeRlimits(plan []PlannedRlimit) string {
	if len(plan) == 0 {
		return emptyLaunchToken
	}
	parts := make([]string, len(plan))
	for i, pr := range plan {
		parts[i] = strconv.Itoa(pr.Resource) + ":" +
			strconv.FormatUint(pr.Lim.Cur, 10) + ":" +
			strconv.FormatUint(pr.Lim.Max, 10)
	}
	return rlimitTokenPrefix + strings.Join(parts, ",")
}

// ParseRlimits decodes the shim argv rlimit token produced by EncodeRlimits.
// "-" decodes to a nil plan. ANY malformed or truncated token is an error the
// shim treats as FATAL (fail-closed): the shim must never skip-with-warning or
// exec the pod without the limits it was handed — a decode failure here is the
// binary-skew / corruption signal, not a degradable condition.
func ParseRlimits(tok string) ([]PlannedRlimit, error) {
	if tok == emptyLaunchToken {
		return nil, nil
	}
	payload, ok := strings.CutPrefix(tok, rlimitTokenPrefix)
	if !ok || payload == "" {
		return nil, fmt.Errorf("malformed rlimit token %q: want %q or %q-prefixed RESOURCE:cur:max list",
			tok, emptyLaunchToken, rlimitTokenPrefix)
	}
	entries := strings.Split(payload, ",")
	plan := make([]PlannedRlimit, 0, len(entries))
	for _, e := range entries {
		fields := strings.Split(e, ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed rlimit entry %q in token %q: want RESOURCE:cur:max", e, tok)
		}
		resource, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("parse rlimit resource %q: %w", fields[0], err)
		}
		if resource < 0 {
			return nil, fmt.Errorf("negative rlimit resource selector %d in token %q", resource, tok)
		}
		cur, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse rlimit cur %q: %w", fields[1], err)
		}
		max, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse rlimit max %q: %w", fields[2], err)
		}
		plan = append(plan, PlannedRlimit{Resource: resource, Lim: unix.Rlimit{Cur: cur, Max: max}})
	}
	return plan, nil
}

// EncodeQoS encodes the background-QoS decision as the single shim argv token
// "q=bg" (background requested) or "-" (no call — Guaranteed/Burstable).
// ParseQoS is the inverse.
func EncodeQoS(bg bool) string {
	if bg {
		return qosBackgroundToken
	}
	return emptyLaunchToken
}

// ParseQoS decodes the shim argv qos token produced by EncodeQoS. Anything other
// than the two exact tokens is an error the shim treats as FATAL (fail-closed),
// same contract as ParseRlimits.
func ParseQoS(tok string) (bool, error) {
	switch tok {
	case emptyLaunchToken:
		return false, nil
	case qosBackgroundToken:
		return true, nil
	}
	return false, fmt.Errorf("malformed qos token %q: want %q or %q", tok, emptyLaunchToken, qosBackgroundToken)
}
