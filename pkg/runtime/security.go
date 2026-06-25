package runtime

import (
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
