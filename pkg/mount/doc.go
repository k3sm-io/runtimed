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
// in the pod's write-scope. Host paths OUTSIDE the data volume are the provider's
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
package mount
