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
	"log/slog"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// resolveCredential computes the POSIX identity a container drops to (M2.3),
// with the kube precedence container.securityContext > pod_security_context >
// PodBox.uid/gid. The proto's int64 run_as_* fields cannot distinguish "unset"
// from 0 (documented on apis SecurityContext), so this treats 0 as "inherit from
// the next source" — 0 is root, which is also the daemon identity and the no-op.
// fs_group (pod-level) joins the supplemental group set so a dropped pod retains
// group access to its fsGroup-owned volumes.
//
// A drop is requested iff the resolved uid OR gid is non-zero. A fully-zero
// identity means the pod runs as the daemon (root-in-Seatbelt) — the documented
// M2.3 fallback until untrusted tenancy routes to the M5 vm backend.
func resolveCredential(box *runtimev1.PodBox, c *runtimev1.Container) supervisor.Credential {
	psc := box.GetPodSecurityContext()
	sc := c.GetSecurityContext()

	uid := firstNonZero(int(sc.GetRunAsUser()), int(psc.GetRunAsUser()), int(box.GetUid()))
	gid := firstNonZero(int(sc.GetRunAsGroup()), int(psc.GetRunAsGroup()), int(box.GetGid()))
	fsGroup := int(psc.GetFsGroup())

	var groups []int
	if gid != 0 {
		groups = append(groups, gid)
	}
	if fsGroup != 0 && fsGroup != gid {
		groups = append(groups, fsGroup)
	}

	return supervisor.Credential{
		UID:    uid,
		GID:    gid,
		Groups: groups,
		Drop:   uid != 0 || gid != 0,
	}
}

// firstNonZero returns the first non-zero value, or 0 if all are zero.
func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

// resolveBgQoS maps the pod's declared kube QoS class (the apis QOSClass enum,
// PodBox.qos_class) to the supervisor-local background flag — the B7 mapping
// decision lives HERE, in the runtime layer, so the supervisor stays decoupled
// from apis (mirroring resolveRlimitPlan/PlannedRlimit):
//
//   - BEST_EFFORT and UNSPECIFIED → true: the launch sequence issues one
//     setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) — the deliberate
//     contention policy (a BestEffort pod yields CPU/IO/network to the rest of
//     the node; darwin's background band couples all three);
//   - GUARANTEED and BURSTABLE → false: NO setpriority call AT ALL. The policy
//     is downward-only — the default band is the absence of the call, never an
//     explicit reset-to-0.
//
// See docs/resources.md for the honesty notes (the band is cooperative, not
// enforcement) and resolveLaunchSpec for where this joins the spawn path.
func resolveBgQoS(box *runtimev1.PodBox) bool {
	switch box.GetQosClass() {
	case runtimev1.QOSClass_QOS_CLASS_GUARANTEED, runtimev1.QOSClass_QOS_CLASS_BURSTABLE:
		return false
	default:
		return true
	}
}

// resolveLaunchSpec bundles the pod-scoped launch inputs — the explicit rlimit
// plan and the qos decision — with the container-scoped credential into the one
// supervisor.LaunchSpec the sandbox backend threads to the exec-shim. It is used
// by BOTH spawn callers (startContainer and exec sessions): an exec session
// deliberately re-enters the pod's rlimits and qos band, one code path.
func resolveLaunchSpec(box *runtimev1.PodBox, cred supervisor.Credential) supervisor.LaunchSpec {
	return supervisor.LaunchSpec{
		Cred:    cred,
		Rlimits: resolveRlimitPlan(box),
		BgQoS:   resolveBgQoS(box),
	}
}

// rlimitResource maps a ResourceLimit.type name to its darwin RLIMIT_* selector.
// The lookup is comma-ok ON PURPOSE: an unknown name returns ok=false so
// resolveRlimitPlan SKIPS it (with a warning) rather than defaulting to the
// zero-value resource — on darwin RLIMIT_CPU is 0x0, so a zero-value miss would
// silently install a cumulative-CPU-seconds killer. RLIMIT_CPU is therefore only
// ever selected when a type explicitly names it.
var rlimitResource = map[string]int{
	"RLIMIT_NOFILE": unix.RLIMIT_NOFILE,
	"RLIMIT_NPROC":  unix.RLIMIT_NPROC,
	"RLIMIT_AS":     unix.RLIMIT_AS,
	"RLIMIT_CORE":   unix.RLIMIT_CORE,
	"RLIMIT_STACK":  unix.RLIMIT_STACK,
	"RLIMIT_DATA":   unix.RLIMIT_DATA,
	"RLIMIT_FSIZE":  unix.RLIMIT_FSIZE,
	"RLIMIT_CPU":    unix.RLIMIT_CPU,
}

// resolveRlimitPlan computes the setrlimit(2) plan from a pod's EXPLICIT
// PodBox.rlimits[] — and ONLY those. It deliberately synthesizes NO rlimit from
// memory_limit_bytes or a cpu quota:
//   - memory is enforced out-of-band by the proc_pid_rusage→OOMKilled sampler;
//     RLIMIT_AS caps virtual address space (≠ phys_footprint) and would crash Go
//     pods at startup while erasing the OOMKilled reason;
//   - RLIMIT_CPU is cumulative CPU-SECONDS, not a rate, so it cannot express a cpu
//     quota.
//
// Each explicit entry maps type→RLIMIT_* via the comma-ok rlimitResource table;
// an UNKNOWN type is skipped with a warning (never silently applied as the
// zero-value RLIMIT_CPU). "Unlimited" (^uint64(0) or RLIM_INFINITY's bit pattern)
// maps to unix.RLIM_INFINITY; soft and hard are otherwise carried verbatim. The
// supervisor applies the returned plan via RunLaunchSequence, before the uid drop.
func resolveRlimitPlan(box *runtimev1.PodBox) []supervisor.PlannedRlimit {
	rls := box.GetRlimits()
	if len(rls) == 0 {
		return nil
	}
	plan := make([]supervisor.PlannedRlimit, 0, len(rls))
	for _, rl := range rls {
		name := rl.GetType()
		resource, ok := rlimitResource[name]
		if !ok {
			slog.Warn("skipping unknown rlimit type", "type", name)
			continue
		}
		plan = append(plan, supervisor.PlannedRlimit{
			Resource: resource,
			Lim: unix.Rlimit{
				Cur: rlimitValue(rl.GetSoft()),
				Max: rlimitValue(rl.GetHard()),
			},
		})
	}
	if len(plan) == 0 {
		return nil
	}
	return plan
}

// rlimitValue normalizes a proto rlimit magnitude to a kernel rlim_t, mapping the
// "unlimited" sentinels to unix.RLIM_INFINITY. A pod author (or the kube→proto
// mapping) may express unlimited as all-ones (^uint64(0)) or as RLIM_INFINITY's
// own bit pattern; both become unix.RLIM_INFINITY. Any other value is verbatim.
func rlimitValue(v uint64) uint64 {
	if v == ^uint64(0) || v == uint64(unix.RLIM_INFINITY) {
		return uint64(unix.RLIM_INFINITY)
	}
	return v
}

// volumeMountStatuses builds the ContainerStatus.volume_mounts mirror from a
// container's declared mounts (the lossless-mirror pairing for the M2.1 spec
// field VolumeMount).
func volumeMountStatuses(c *runtimev1.Container) []*runtimev1.VolumeMountStatus {
	vms := c.GetVolumeMounts()
	if len(vms) == 0 {
		return nil
	}
	out := make([]*runtimev1.VolumeMountStatus, 0, len(vms))
	for _, vm := range vms {
		out = append(out, &runtimev1.VolumeMountStatus{
			Name:      vm.GetName(),
			MountPath: vm.GetMountPath(),
			ReadOnly:  vm.GetReadOnly(),
		})
	}
	return out
}

// containerUser builds the ContainerStatus.user mirror (the effective uid/gid +
// supplemental groups the privilege drop produced). It is nil when no drop is
// requested (the pod runs as the daemon identity, with no explicit user).
func containerUser(cred supervisor.Credential) *runtimev1.ContainerUser {
	if !cred.Drop {
		return nil
	}
	groups := make([]int64, len(cred.Groups))
	for i, g := range cred.Groups {
		groups[i] = int64(g)
	}
	return &runtimev1.ContainerUser{
		Linux: &runtimev1.LinuxContainerUser{
			Uid:                int64(cred.UID),
			Gid:                int64(cred.GID),
			SupplementalGroups: groups,
		},
	}
}
