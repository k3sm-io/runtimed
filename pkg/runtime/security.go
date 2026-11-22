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
	"log/slog"
	"path/filepath"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
	"k3sm.io/runtimed/pkg/supervisor"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// resolveCredential computes the POSIX identity a container drops to,
// with the kube precedence container.securityContext > pod_security_context >
// PodBox.uid/gid. The proto's int64 run_as_* fields cannot distinguish "unset"
// from 0 (documented on apis SecurityContext), so this treats 0 as "inherit from
// the next source" — 0 is root, which is also the daemon identity and the no-op.
// fs_group (pod-level) joins the supplemental group set so a dropped pod retains
// group access to its fsGroup-owned volumes.
//
// A drop is requested iff the resolved uid OR gid is non-zero. A fully-zero
// identity means the pod runs as the daemon (root-in-Seatbelt) — the documented
// fallback until untrusted tenancy routes to the vm backend. A drop with a
// uid and no gid takes supervisor.NobodyGID as its primary group.
func resolveCredential(box *runtimev1.PodBox, c *runtimev1.Container) supervisor.Credential {
	psc := box.GetPodSecurityContext()
	sc := c.GetSecurityContext()

	uid := firstNonZero(int(sc.GetRunAsUser()), int(psc.GetRunAsUser()), int(box.GetUid()))
	gid := firstNonZero(int(sc.GetRunAsGroup()), int(psc.GetRunAsGroup()), int(box.GetGid()))
	fsGroup := int(psc.GetFsGroup())
	drop := uid != 0 || gid != 0
	// A user with no group drops to nobody, not to gid 0 (wheel): the proto
	// cannot tell an unset run_as_group from 0, and wheel is refused.
	if uid != 0 && gid == 0 {
		gid = supervisor.NobodyGID()
	}

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
		Drop:   drop,
	}
}

// checkPodUID refuses, before anything is spawned, a credential whose drop
// would leave the pod process in the login range, below 0, at uid 0 or at the
// service user's uid, or in a group a pod may not hold, a host-assigned system
// group among them (supervisor.Credential.CheckPodIdentity, asking
// Deps.lookupGroup). The service user is
// the one New resolved (Deps.lookupService); when that lookup failed every
// drop is refused. A credential without a drop runs at the daemon's own uid
// and is allowed.
// serviceInstalledDirs are the installed directories whose owner stands in
// for the service user when the directory lookup finds no account
// (supervisor.ResolveServiceIdentity): the keystore's socket directory under
// the k3sm data root (cfg.DataRoot), and the k3sm role's work dir
// (cfg.StateDir). Each is named only when the node configured it.
func serviceInstalledDirs(cfg Config) []string {
	var dirs []string
	if cfg.DataRoot != "" {
		dirs = append(dirs, filepath.Join(cfg.DataRoot, keystorepaths.SockDir))
	}
	if cfg.StateDir != "" {
		dirs = append(dirs, cfg.StateDir)
	}
	return dirs
}

func (r *Runtime) checkPodUID(cred supervisor.Credential) error {
	if cred.Drop && r.serviceErr != nil {
		return fmt.Errorf("%w: %w", supervisor.ErrPodUIDRefused, r.serviceErr)
	}
	return cred.CheckPodIdentity(r.service, r.cfg.FSGroupAdmitted, r.lookupGroup)
}

// fsGroupOwners says whose entries the fsGroup walk may change in a pod's
// tree (supervisor.ChownForFSGroup): the uid each of the pod's containers
// runs as, and the daemon's own uid (euid), which owns what the daemon puts
// in the tree (volumes, the pod's temp and home dirs, the Xcode cache) and is
// the uid of a container that requests no drop, the same rule
// resolveCredential's callers apply. An entry any other uid owns came from
// outside the pod's content, for instance renamed in from a writable share,
// and the walk leaves it alone.
//
// On a daemon running as root whose pod drops to another uid, root is named
// only in InGroup: a pod can rename into its tree a file or directory root
// owns from any location it may write, and with root among the owners the
// walk would give the pod's group the owner's access to it, which the pod
// could then rename back out with the access it gained. What the daemon puts
// in the tree is told apart by its group instead: createPod gives the rootfs
// the fsGroup before it puts anything there (supervisor.PrepareFSGroupRoot),
// every entry it makes then takes that group, and an entry renamed in keeps
// its own. A daemon running as another uid (the service user, which every pod
// also runs as on the shipped posture) is unchanged: it and the pods are one
// uid, and so one trust domain to the walk.
func fsGroupOwners(box *runtimev1.PodBox, euid int) supervisor.FSGroupOwners {
	var drops []int
	seen := map[int]bool{euid: true}
	for _, list := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers(), box.GetEphemeralContainers()} {
		for _, c := range list {
			cred := resolveCredential(box, c)
			if !cred.Drop || cred.UID == 0 {
				continue // runs at the daemon's uid
			}
			if !seen[cred.UID] {
				seen[cred.UID] = true
				drops = append(drops, cred.UID)
			}
		}
	}
	if euid == 0 && len(drops) > 0 {
		return supervisor.FSGroupOwners{UIDs: drops, InGroup: []int{0}}
	}
	return supervisor.FSGroupOwners{UIDs: append([]int{euid}, drops...)}
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
// PodBox.qos_class) to the supervisor-local background flag — the mapping
// decision lives here, in the runtime layer, so the supervisor stays decoupled
// from apis (mirroring resolveRlimitPlan/PlannedRlimit):
//
//   - BEST_EFFORT and UNSPECIFIED → true: the launch sequence issues one
//     setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG) — the deliberate
//     contention policy (a BestEffort pod yields CPU/IO/network to the rest of
//     the node; darwin's background band couples all three);
//   - GUARANTEED, BURSTABLE, and any unknown/future enum value → false: NO
//     setpriority call AT all. The policy is downward-only — the default band
//     is the absence of the call, never an explicit reset-to-0. Backgrounding
//     is the explicitly-ENUMERATED branch on purpose: a future additive apis
//     QOSClass value must not be silently BG-throttled by a stale runtimed.
//
// See docs/resources.md for the honesty notes (the band is cooperative, not
// enforcement) and resolveLaunchSpec for where this joins the spawn path.
func resolveBgQoS(box *runtimev1.PodBox) bool {
	switch box.GetQosClass() {
	case runtimev1.QOSClass_QOS_CLASS_BEST_EFFORT, runtimev1.QOSClass_QOS_CLASS_UNSPECIFIED:
		return true
	default:
		return false
	}
}

// resolveLaunchSpec bundles the pod-scoped launch inputs — the explicit rlimit
// plan and the qos decision — with the container-scoped credential into the one
// supervisor.LaunchSpec the sandbox backend threads to the exec-shim. It is used
// by both spawn callers (startContainer and exec sessions): an exec session
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
// resolveRlimitPlan skips it (with a warning) rather than defaulting to the
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

// resolveRlimitPlan computes the setrlimit(2) plan from a pod's explicit
// PodBox.rlimits[] — and only those. It deliberately synthesizes NO rlimit from
// memory_limit_bytes or a cpu quota:
//   - memory is enforced out-of-band by the proc_pid_rusage→OOMKilled sampler;
//     RLIMIT_AS caps virtual address space (≠ phys_footprint) and would crash Go
//     pods at startup while erasing the OOMKilled reason;
//   - RLIMIT_CPU is cumulative CPU-SECONDS, not a rate, so it cannot express a cpu
//     quota.
//
// Each explicit entry maps type→RLIMIT_* via the comma-ok rlimitResource table;
// an unknown type is skipped with a warning (never silently applied as the
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
// container's declared mounts (the lossless-mirror pairing for the
// VolumeMount spec field).
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
