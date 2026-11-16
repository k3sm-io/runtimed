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
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
	"k3sm.io/runtimed/pkg/sandbox"
)

// hostShares decides box's hostPath volumes against the node's allowlist
// (Config.HostSharesFile) and returns the sandbox grants for them. It is the
// runtime's own decision, made from the root-owned file and never from the
// request: a pod shares this daemon's uid and can reach its gRPC socket, so a
// CreatePod that arrives without the provider's check must meet the same one.
//
// A pod with no mounted hostPath volume gets nil without the file being read.
// Every grant is logged at Info with the pod, the path and the mode, and the
// uid whose delegated file holds the entry when one does: the node-side audit
// record of what each pod was given. A delegated entry the node drops (it no
// longer passes its delegation's checks) is logged at Warn on each create
// that reads it.
func (r *Runtime) hostShares(box *runtimev1.PodBox) ([]sandbox.HostShare, error) {
	if !mountsHostPath(box) {
		return nil, nil
	}
	var eff hostshare.Effective
	if r.cfg.HostSharesFile != "" {
		var err error
		if eff, err = hostshare.LoadEffective(r.cfg.HostSharesFile); err != nil {
			return nil, err
		}
	}
	// Log only the drops this pod could have used (or a whole user file),
	// so a user's list cannot flood the node log on every create.
	for _, d := range eff.Dropped {
		if d.Entry.Path == "" || coversVolume(box, d.Entry.Path) {
			r.log.Warn("delegated host share not admitted", "uid", d.UID, "entry", d.Entry.String(), "reason", d.Reason)
		}
	}
	grants, err := hostshare.Authorize(eff.Entries, box)
	if err != nil {
		return nil, err
	}
	out := make([]sandbox.HostShare, 0, len(grants))
	for _, g := range grants {
		mode := "rw"
		switch {
		case g.Socket:
			mode = "socket"
		case g.ReadOnly:
			mode = "ro"
		}
		// The pod fields come from the request; the path, mode, entry and
		// delegating uid are the node's own decision.
		attrs := []any{"pod", box.GetPodId(), "namespace", box.GetNamespace(),
			"name", box.GetName(), "volume", g.Volume, "path", g.Path, "mode", mode, "entry", g.Entry.String()}
		if uid, ok := eff.Owners[g.Entry]; ok {
			attrs = append(attrs, "delegated_uid", uid)
		}
		r.log.Info("host share granted", attrs...)
		out = append(out, sandbox.HostShare{Path: g.Path, ReadOnly: g.ReadOnly, Socket: g.Socket})
	}
	return out, nil
}

// coversVolume reports whether p is at, under or above a hostPath volume of
// box.
func coversVolume(box *runtimev1.PodBox, p string) bool {
	for _, v := range box.GetVolumes() {
		if hp := v.GetHostPath(); hp != nil && (hostshare.AtOrUnder(hp.GetPath(), p) || hostshare.AtOrUnder(p, hp.GetPath())) {
			return true
		}
	}
	return false
}

// mountsHostPath reports whether any container of box mounts a hostPath volume.
func mountsHostPath(box *runtimev1.PodBox) bool {
	hp := map[string]bool{}
	for _, v := range box.GetVolumes() {
		if v.GetHostPath() != nil {
			hp[v.GetName()] = true
		}
	}
	if len(hp) == 0 {
		return false
	}
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				if hp[m.GetName()] {
					return true
				}
			}
		}
	}
	return false
}
