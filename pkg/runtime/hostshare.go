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
// Every grant is logged at Info with the pod, the path and the mode, which is
// the node-side audit record of what each pod was given.
func (r *Runtime) hostShares(box *runtimev1.PodBox) ([]sandbox.HostShare, error) {
	if !mountsHostPath(box) {
		return nil, nil
	}
	var entries []hostshare.Entry
	if r.cfg.HostSharesFile != "" {
		var err error
		if entries, err = hostshare.Load(r.cfg.HostSharesFile); err != nil {
			return nil, err
		}
	}
	grants, err := hostshare.Authorize(entries, box)
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
		r.log.Info("host share granted", "pod", box.GetPodId(), "namespace", box.GetNamespace(),
			"name", box.GetName(), "volume", g.Volume, "path", g.Path, "mode", mode, "entry", g.Entry.String())
		out = append(out, sandbox.HostShare{Path: g.Path, ReadOnly: g.ReadOnly, Socket: g.Socket})
	}
	return out, nil
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
