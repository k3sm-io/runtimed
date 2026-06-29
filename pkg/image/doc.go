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

// Package image pulls OCI image artifacts into a content-addressed cache and
// materializes them into a pod's rootfs as native files runnable in place at
// host paths (k3sm/docs/DESIGN.md §5a).
//
// Pipeline:
//
//   - Pull: fetch an OCI image by reference into a content-addressed blob cache
//     under /var/lib/k3sm (default; configurable). Blobs are keyed by digest, so
//     a second pull of the same content is a cache hit.
//   - Materialize: copy the cached payload into the per-pod rootfs using APFS
//     copy-on-write via golang.org/x/sys/unix.Clonefile. The cache and pod
//     rootfs MUST be on the same APFS volume for the clone to succeed; on EXDEV
//     (cross-device) or ENOTSUP (non-APFS) the copier falls back to copyfile /
//     byte-copy. Materialization is idempotent and asserts no
//     com.apple.quarantine xattr is left on the result.
//   - Sign: ad-hoc codesign pulled Mach-O binaries (codesign -s - -f) STRIPPING
//     hardened-runtime and library-validation flags, so a later DYLD insert (the
//     darwin-net DNS shim) can load. Hardened runtime would block the insert.
//   - SignaturePolicy gate: enforce runtimev1.SignaturePolicy before exec.
//     UNSPECIFIED is fail-closed (refuse to run).
//
// CoW and codesign touch Darwin specifics; the cgo-free Clonefile binding lives
// behind cowCopy (clonefile_darwin.go) so callers stay platform-agnostic.
package image
