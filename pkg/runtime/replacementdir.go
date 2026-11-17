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

import "k3sm.io/runtimed/pkg/sandbox"

// shimRebasePrefixes returns the prefixes the path-rebase shim rebases under a
// container's data volume: its volume mounts, then the shared replacement
// directory of the volume the pods live on, when there is one.
//
// On a node /var/lib/k3sm is its own APFS volume. For a file on a volume other
// than the user temp dir's, Foundation (Data.write(.atomic),
// FileManager.url(for: .itemReplacementDirectory), and so swift build's
// manifest writes) puts its replacement directory at that volume's root, in
// .TemporaryItems/folders.<uid>: one per uid, so every pod of the node running
// as _k3sm would share it. The profile denies it (sandbox.Posture.WorkVolume),
// which fails those writes with EPERM. Rebased, the path lands in the pod's own
// tree, where it does not exist: Foundation then stages beside the file, in the
// pod's data volume, on the same volume, so the rename stays atomic. The shim
// is cooperative; the profile's deny is the enforcement.
//
// The prefix is spelled as statfs reports the mount point (f_mntonname,
// /private/var/lib/k3sm on a node), which is the spelling Foundation uses; the
// deny covers both firmlink forms.
func (r *Runtime) shimRebasePrefixes(mounts []string) []string {
	prefixes := append([]string{}, mounts...)
	if p, ok := sandbox.SharedVolumeTempDir(r.workVolume); ok {
		prefixes = append(prefixes, p)
	}
	return prefixes
}
