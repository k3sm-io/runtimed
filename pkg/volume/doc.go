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

// Package volume materializes APFS-backed persistent volumes (PVCs) for a pod.
// It is the durable counterpart to pkg/mount: where pkg/mount
// renders pod-ephemeral sources (configMap/secret/emptyDir/downwardAPI/projected)
// INTO the pod data volume — torn down with the pod — a PVC-backed dir lives at a
// STABLE per-claim path on the APFS storage root outside the pod tree and SURVIVES
// pod stop/restart/delete (ReclaimPolicy Retain).
//
// The path two repos agree on is k3sm.io/apis/storage/v1: the provisioner
// controller (k3sm) writes the bound PersistentVolume's local path as
// LocalPathClass.DataDir(namespace, claimName), and the Binder here resolves the
// same dir from the PodBox alone (namespace + the PVC source's claim_name) —
// runtimed never needs the PV object. The storage root is the same APFS volume as
// /var/lib/k3sm (kine's SQLite shares it), so seeding can clonefile-CoW and a
// runaway PVC can fill the datastore volume: capacity is not enforced vs free
// space (over-commit → write-time ENOSPC).
//
// The Binder empty-CREATEs a fresh claim's dir (the hot path — never a clonefile),
// and SEEDs-once from a StorageClass template only when one is configured, via the
// pkg/image Cloner (clonefile-CoW). It then symlinks each container mount of the
// claim into the pod rootfs so the confined pod reaches the persistent dir at its
// mount path; the symlink lives in the pod dir (removed on teardown) while its
// target does not. The Binder never deletes a PV dir — there is no volume-delete
// RPC and root-rmdir would bypass the pod SBPL deny-set (Retain only). The PV dir
// is added to the pod's SBPL write-scope by the caller (pkg/runtime → pkg/sandbox).
package volume
