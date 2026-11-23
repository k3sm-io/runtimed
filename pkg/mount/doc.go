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

// Package mount materializes a PodBox's volume sources into the pod's on-disk
// directory: configMap, secret, emptyDir, downwardAPI, and
// projected (including the serviceAccountToken projection).
//
// k3sm has NO mount namespace and NO chroot — a pod is a native process running
// at host paths. There is therefore nothing to "bind-mount"; a volume is
// materialized as real files at a path REBASED under the pod data volume
// (filepath.Join(dataVol, mountPath)), and the provider points the workload at
// that path. Because every materialized volume lives inside the writable data
// volume, none of them need an SBPL extra-path grant — the data volume is already
// in the pod's write-scope. Host paths outside the data volume are the provider's
// SandboxProfile.extra_read_paths/extra_write_paths, which sandbox.Generate
// validates against the protected deny-set. A mount path that would escape the
// data volume via "../" is rejected.
//
// A volume selection (volume name plus subPath) is materialized once, at the
// first mount path that names it (init containers first). Another container
// mounting the same selection at a different mount path gets a relative
// symlink there to that one directory (placeAlias), so an emptyDir an init
// container fills is what the main container sees, as with the kubelet's one
// directory per pod. Two different selections at one mount path are an error.
//
// The runtime proto (k3sm.io/apis runtime/v1) carries only the volume source
// *reference* — a ConfigMap/Secret name, the SA-token audience — not the bytes,
// because runtimed never talks to the apiserver. The data is supplied by a
// Resolver (defined at the consumer per the k3sm Go standards): the k3sm provider
// wires one backed by its apiserver client; unit tests wire a fake.
//
// Secrets and the projected ServiceAccount token are reported as credentials in
// the returned Layout so the caller hands them to sandbox.Generate as the
// read-only sub-scope (file-read* + an explicit file-write* deny): a pod cannot
// write the files at its credential mount paths. That is a rule on paths, not
// on the files: a pod can rename a parent of a credential mount aside (it
// writes its rootfs), after which the live generation's files sit outside the
// sub-scope and the pod can change them, and it can put a directory of its own
// at the mount path. So the live generation's content is not
// integrity-protected against the pod itself; the daemon never reads it back
// unless it is the generation the daemon recorded (see below), and a refresh
// of a replaced mount dir renders it fresh.
//
// # Refresh: the atomic-writer layout
//
// A non-subPath configMap / secret / downwardAPI / projected mount is written in
// the kubelet atomic-writer layout, at create and on every Refresh through the
// same code (writeGeneration): each render goes into a fresh
// <mountdir>/..<timestamp>/ generation, <mountdir>/..data is flipped to it by
// renaming a new symlink over the old one, and each top-level key is a relative
// symlink <key> -> ..data/<key>. A reader sees the whole old set or the whole
// new set. Refresh re-renders these mounts for a running pod; it skips subPath
// mounts (cloned once, never refreshed, as in the kubelet), emptyDirs, volumes
// whose sources were all immutable, and re-mints a ServiceAccount token only
// when under 20% of its lifetime remains. A failed resolve or render leaves the
// live generation in place.
//
// # Writes into the pod tree go through descriptors
//
// The pod owns every directory below its data volume and can rename one away
// and plant a symlink, or a file, in its place at any time, including between
// Materialize and a Refresh (a process of an earlier instance can do it before
// Materialize). So a mount dir is opened from the data volume one component at
// a time with O_NOFOLLOW|O_DIRECTORY (openUnder, pathsafe.OpenDirFrom), and a
// component that is a symlink or not a directory fails the mount (at create)
// or the volume's refresh. Every step of the atomic writer — the generation
// dir, the files rendered into it, the check of what was rendered, the ..data
// flip, the key links, the removal of the old generation and of dropped keys,
// and the re-read of a still-fresh token — then acts relative to that
// descriptor or the generation's own: mkdirat, openat with O_CREAT|O_EXCL and
// O_NOFOLLOW, fchmod, symlinkat, renameat, readlinkat, unlinkat and a
// descriptor-relative tree removal (pathsafe.RemoveTreeAt). A subPath
// selection is cloned into place with clonefileat(2) relative to the pinned
// destination, and an image volume's view link is placed with symlinkat. What
// a name means after it was opened cannot redirect a write.
//
// The pod can also write into the tree while the daemon works in it: plant a
// name in a generation being rendered, or point ..data at a directory of its
// own. So a render writes only names it created (a planted one is refused,
// never truncated), a rendered or re-read file must have one link, the mount
// dir and the live generation must be the ones the previous render recorded
// (RefreshState.Mounts) before anything is read back from the live
// generation, and every read and walk of a generation is bounded
// (maxVolumeBytes, maxTreeEntries, maxTreeDepth; over a bound the volume's
// refresh fails).
//
// The rendered files are owned by the daemon's uid, which is the uid a pod
// runs as unless it drops to another one, so their mode bits protect nothing
// from the pod: the SBPL read-only sub-scope on a credential mount's path is
// the only thing that keeps a pod from writing the files there, and it holds
// only while those files stay at that path (above).
//
// Every tree a refresh removes from a mount dir can be the pod's, so removal
// is bounded too (pathsafe.RemoveTreeAt with removeBounds), and holds a
// constant number of descriptors however deep the tree is: a ..data that is no
// link is renamed aside to a ..trash_ name first and removed from there (over
// a bound the refresh fails and the rest stays aside; the next refresh
// renders), a generation the pod grew while it was rendered is removed within
// the bound, and the previous generation is removed only when it was the
// trusted live one. A mount dir that is not the one recorded is rendered as
// after a restart: fresh, with nothing read from it, and recorded anew. A
// render that would write more than maxVolumeBytes fails, so a volume too
// large to refresh fails its create.
//
// Still by path: the data volume itself and the pod dir above it (the
// daemon's own paths; see openAnchor for what that trusts), the subPath
// staging dir (a daemon-owned sibling of the data volume, created and
// removed by path), and a vm pod's share roots and emptyDir share dirs
// (MaterializeShares creates them under the pod dir after
// pathsafe.RefuseSymlinkedPath, a pre-check; the proj volumes rendered into
// them go through descriptors).
//
// # subPath
//
// A VolumeMount subPath selects a single element within the volume: the container
// mount path exposes only the volume's <subPath> file or subdirectory, never the
// whole volume. subPath does not change the destination level — the destination is
// always the rebased mountPath (filepath.Join(dataVol, mountPath)); the empty-
// subPath path is unchanged (whole volume materialized at the mount path). For a
// non-empty subPath the model is: materialize the whole volume into a STAGING dir
// outside the readable data volume → validate + select <staging>/<subPath> → CoW-
// clone only that element into the rebased mount path → remove the staging dir, so
// no un-selected sibling (e.g. the volume's other keys) is ever left readable under
// the pod tree.
//
// The selection is validated before it is used (subPath is CVE-2021-25741 class):
// a lexical isUnder check rejects a "../"-escaping subPath (beside the mountPath
// "../" rejection above), and a symlink-safe EvalSymlinks + re-check rejects an
// in-volume symlink pointing outside the volume root. The placed element is then
// branched on kind: a FILE element IS the mount path (clone the file only — never
// MkdirAll it, which would give the workload's open(2) an EISDIR), a DIR element is
// the mount path's tree. The staging render is flat, not a generation. A
// subPath naming a non-existent element fails closed,
// except for an emptyDir, whose missing subPath directory is created (kubelet
// parity). subPathExpr (env-var-expanded subPath) is not yet implemented.
//
// # vm-RuntimeClass pods
//
// A pod that runs in a Linux guest has no rebased host tree: its volumes reach
// the guest as virtiofs shares. ComputeSharePlan computes that share plan as
// pure data (no filesystem access), and MaterializeShares is its filesystem
// half — it creates the pod-dir share roots and renders each pooled proj/vols
// volume into <shareRoot>/<volume name>, reusing the same per-volume renderers
// the native spine uses. A bind's subPath is applied guest-side, not here.
package mount
