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
// directory (runtimed M2.2): configMap, secret, emptyDir, downwardAPI, and
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
// The runtime proto (k3sm.io/apis runtime/v1) carries only the volume source
// *reference* — a ConfigMap/Secret name, the SA-token audience — not the bytes,
// because runtimed never talks to the apiserver. The data is supplied by a
// Resolver (defined at the consumer per the k3sm Go standards): the k3sm provider
// wires one backed by its apiserver client; unit tests wire a fake.
//
// Secrets and the projected ServiceAccount token are reported as credentials in
// the returned Layout so the caller hands them to sandbox.Generate as the
// read-only sub-scope (file-read* + an explicit file-write* deny) — a pod can
// read its credentials but never overwrite them.
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
// the mount path's tree. A subPath naming a non-existent element fails closed,
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
